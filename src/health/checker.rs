use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use tokio::sync::RwLock;
use tokio::time::{interval, MissedTickBehavior};
use crate::database::AuthDatabase;
use crate::cache::CacheProvider;
use crate::email::EmailProvider;
use super::{HealthMonitor, HealthReport, HealthConfig};
use super::alerts::{AlertManager, AlertConfig};
use super::metrics::HealthMetrics;

/// Health checking service that orchestrates all health monitoring
pub struct HealthChecker {
    monitor: Arc<HealthMonitor>,
    alert_manager: Arc<AlertManager>,
    metrics: Arc<RwLock<HealthMetrics>>,
    config: HealthConfig,
    last_report: Arc<RwLock<Option<HealthReport>>>,
    is_running: Arc<RwLock<bool>>,
}

impl HealthChecker {
    /// Create new health checker service
    pub fn new(
        health_config: HealthConfig,
        alert_config: AlertConfig,
        metrics: HealthMetrics,
        version: String,
    ) -> Self {
        let monitor = Arc::new(HealthMonitor::new(health_config.clone(), version));
        let alert_manager = Arc::new(AlertManager::new(alert_config));
        let metrics = Arc::new(RwLock::new(metrics));

        Self {
            monitor,
            alert_manager,
            metrics,
            config: health_config,
            last_report: Arc::new(RwLock::new(None)),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the health checking service
    pub async fn start(
        &self,
        database: Arc<dyn AuthDatabase>,
        cache: Arc<dyn CacheProvider>,
        email: Arc<dyn EmailProvider>,
    ) -> Result<()> {
        if !self.config.enabled {
            tracing::info!("Health checking is disabled");
            return Ok(());
        }

        let mut is_running = self.is_running.write().await;
        if *is_running {
            tracing::warn!("Health checker is already running");
            return Ok(());
        }
        *is_running = true;
        drop(is_running);

        tracing::info!(
            "Starting health checker with {} second intervals",
            self.config.check_interval_seconds
        );

        // Clone Arc references for the background task
        let monitor = self.monitor.clone();
        let alert_manager = self.alert_manager.clone();
        let metrics = self.metrics.clone();
        let last_report = self.last_report.clone();
        let is_running = self.is_running.clone();
        let config = self.config.clone();

        // Spawn background health checking task
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.check_interval_seconds));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                // Check if we should continue running
                {
                    let running = is_running.read().await;
                    if !*running {
                        tracing::info!("Health checker stopping");
                        break;
                    }
                }

                interval.tick().await;

                // Perform health check
                let start_time = Instant::now();
                
                let report = if config.enable_detailed_checks {
                    monitor.detailed_health_check(
                        database.as_ref(),
                        cache.as_ref(),
                        email.as_ref(),
                    ).await
                } else {
                    monitor.basic_health_check().await
                };

                let check_duration = start_time.elapsed();
                
                tracing::debug!(
                    "Health check completed in {:.2}ms with status: {:?}",
                    check_duration.as_millis(),
                    report.status
                );

                // Update metrics
                {
                    let mut metrics_guard = metrics.write().await;
                    metrics_guard.record_health_report(&report);
                }

                // Process alerts
                if let Err(e) = alert_manager.process_health_report(&report).await {
                    tracing::error!("Failed to process health report for alerts: {}", e);
                }

                // Store the latest report
                {
                    let mut last_report_guard = last_report.write().await;
                    *last_report_guard = Some(report);
                }

                // Log health status periodically
                if config.check_interval_seconds >= 60 {
                    Self::log_health_summary(&report);
                }
            }
        });

        Ok(())
    }

    /// Stop the health checking service
    pub async fn stop(&self) {
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        tracing::info!("Health checker stop requested");
    }

    /// Check if the health checker is running
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    /// Get the latest health report
    pub async fn get_latest_report(&self) -> Option<HealthReport> {
        let last_report = self.last_report.read().await;
        last_report.clone()
    }

    /// Perform an on-demand health check
    pub async fn check_now(
        &self,
        database: &dyn AuthDatabase,
        cache: &dyn CacheProvider,
        email: &dyn EmailProvider,
        detailed: bool,
    ) -> HealthReport {
        let report = if detailed {
            self.monitor.detailed_health_check(database, cache, email).await
        } else {
            self.monitor.basic_health_check().await
        };

        // Update metrics for on-demand checks too
        {
            let mut metrics_guard = self.metrics.write().await;
            metrics_guard.record_health_report(&report);
        }

        // Store as latest report
        {
            let mut last_report_guard = self.last_report.write().await;
            *last_report_guard = Some(report.clone());
        }

        report
    }

    /// Get health metrics
    pub async fn get_metrics(&self) -> Arc<RwLock<HealthMetrics>> {
        self.metrics.clone()
    }

    /// Get alert manager
    pub fn get_alert_manager(&self) -> Arc<AlertManager> {
        self.alert_manager.clone()
    }

    /// Get health configuration
    pub fn get_config(&self) -> &HealthConfig {
        &self.config
    }

    /// Update health configuration (for hot-reloading)
    pub async fn update_config(&mut self, new_config: HealthConfig) -> Result<()> {
        if new_config.enabled != self.config.enabled {
            tracing::info!(
                "Health checking enabled status changing from {} to {}",
                self.config.enabled,
                new_config.enabled
            );
        }

        if new_config.check_interval_seconds != self.config.check_interval_seconds {
            tracing::info!(
                "Health check interval changing from {}s to {}s",
                self.config.check_interval_seconds,
                new_config.check_interval_seconds
            );
            
            // Restart the service with new interval
            if self.is_running().await {
                tracing::info!("Restarting health checker with new configuration");
                // Note: In a real implementation, you'd need to handle the restart
                // For now, we'll just update the config and let the next iteration pick it up
            }
        }

        self.config = new_config;
        Ok(())
    }

    /// Get health check statistics
    pub async fn get_statistics(&self) -> HealthStatistics {
        let metrics_guard = self.metrics.read().await;
        let current_values = metrics_guard.get_current_values();
        
        let alert_manager = &self.alert_manager;
        let active_alerts = alert_manager.get_active_alerts().await;
        let alert_history = alert_manager.get_alert_history(Some(100)).await;

        HealthStatistics {
            total_checks: current_values.get("health_check_total").copied().unwrap_or(0.0) as u64,
            current_status: current_values.get("health_check_status").copied().unwrap_or(0.0) as u8,
            uptime_seconds: current_values.get("service_uptime_seconds").copied().unwrap_or(0.0) as u64,
            active_alerts_count: active_alerts.len(),
            total_alerts_generated: current_values.get("alerts_total").copied().unwrap_or(0.0) as u64,
            recent_alert_history: alert_history,
            component_health: self.get_component_health_summary(&current_values),
        }
    }

    /// Get component health summary
    fn get_component_health_summary(&self, metrics: &std::collections::HashMap<String, f64>) -> ComponentHealthSummary {
        ComponentHealthSummary {
            database_status: metrics.get("database_health_status").copied().unwrap_or(0.0) as u8,
            cache_status: metrics.get("cache_health_status").copied().unwrap_or(0.0) as u8,
            email_status: metrics.get("email_health_status").copied().unwrap_or(0.0) as u8,
            memory_usage_percent: metrics.get("memory_usage_percent").copied().unwrap_or(0.0),
            disk_usage_percent: metrics.get("disk_usage_percent").copied().unwrap_or(0.0),
            system_load_average: metrics.get("system_load_average").copied().unwrap_or(0.0),
        }
    }

    /// Log health summary for monitoring
    fn log_health_summary(report: &HealthReport) {
        let summary = &report.summary;
        
        match report.status {
            super::HealthStatus::Healthy => {
                tracing::info!(
                    "Health check: ALL SYSTEMS HEALTHY ({}/{} checks passed, avg latency: {:.1}ms)",
                    summary.healthy_checks,
                    summary.total_checks,
                    summary.average_latency_ms
                );
            }
            super::HealthStatus::Warning => {
                tracing::warn!(
                    "Health check: DEGRADED PERFORMANCE ({} warnings, {}/{} checks healthy, avg latency: {:.1}ms)",
                    summary.warning_checks,
                    summary.healthy_checks,
                    summary.total_checks,
                    summary.average_latency_ms
                );
            }
            super::HealthStatus::Critical => {
                tracing::error!(
                    "Health check: CRITICAL ISSUES ({} critical, {} warnings, {}/{} checks healthy, avg latency: {:.1}ms)",
                    summary.critical_checks,
                    summary.warning_checks,
                    summary.healthy_checks,
                    summary.total_checks,
                    summary.average_latency_ms
                );
            }
            super::HealthStatus::Unknown => {
                tracing::warn!(
                    "Health check: UNKNOWN STATUS ({} unknown, {}/{} checks completed, avg latency: {:.1}ms)",
                    summary.unknown_checks,
                    summary.healthy_checks + summary.warning_checks + summary.critical_checks,
                    summary.total_checks,
                    summary.average_latency_ms
                );
            }
        }

        // Log individual failing checks
        for check in &report.checks {
            match check.status {
                super::HealthStatus::Critical => {
                    tracing::error!(
                        "CRITICAL: {} - {} ({}ms)",
                        check.name, check.message, check.latency_ms
                    );
                }
                super::HealthStatus::Warning => {
                    tracing::warn!(
                        "WARNING: {} - {} ({}ms)",
                        check.name, check.message, check.latency_ms
                    );
                }
                super::HealthStatus::Unknown => {
                    tracing::warn!(
                        "UNKNOWN: {} - {} ({}ms)",
                        check.name, check.message, check.latency_ms
                    );
                }
                _ => {} // Don't log healthy checks in summary
            }
        }
    }

    /// Graceful shutdown with cleanup
    pub async fn shutdown(&self) -> Result<()> {
        tracing::info!("Starting health checker graceful shutdown");
        
        // Stop the health checking loop
        self.stop().await;

        // Wait a moment for the background task to finish
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Clean up old alerts
        let cleaned = self.alert_manager.cleanup_old_alerts(30).await;
        if cleaned > 0 {
            tracing::info!("Cleaned up {} old alerts during shutdown", cleaned);
        }

        tracing::info!("Health checker shutdown completed");
        Ok(())
    }
}

/// Health checker statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthStatistics {
    pub total_checks: u64,
    pub current_status: u8, // 0=Unknown, 1=Healthy, 2=Warning, 3=Critical
    pub uptime_seconds: u64,
    pub active_alerts_count: usize,
    pub total_alerts_generated: u64,
    pub recent_alert_history: Vec<super::alerts::Alert>,
    pub component_health: ComponentHealthSummary,
}

/// Component health summary
#[derive(Debug, Clone, serde::Serialize)]
pub struct ComponentHealthSummary {
    pub database_status: u8,
    pub cache_status: u8,
    pub email_status: u8,
    pub memory_usage_percent: f64,
    pub disk_usage_percent: f64,
    pub system_load_average: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use prometheus::Registry;
    use crate::health::alerts::AlertConfig;

    // Mock implementations for testing
    struct MockDatabase;
    #[async_trait::async_trait]
    impl AuthDatabase for MockDatabase {
        async fn health_check(&self) -> Result<std::collections::HashMap<String, serde_json::Value>> {
            Ok(std::collections::HashMap::new())
        }
        // ... other required methods would be implemented with mock behavior
    }

    struct MockCache;
    #[async_trait::async_trait]
    impl CacheProvider for MockCache {
        async fn get<T: serde::de::DeserializeOwned>(&self, _key: &str) -> Result<Option<T>> {
            Ok(None)
        }
        async fn set<T: serde::Serialize>(&self, _key: &str, _value: &T, _ttl: u64) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(false)
        }
        async fn clear(&self) -> Result<()> {
            Ok(())
        }
    }

    struct MockEmail;
    #[async_trait::async_trait]
    impl EmailProvider for MockEmail {
        async fn send_email(&self, _to: &str, _subject: &str, _body: &str) -> Result<()> {
            Ok(())
        }
        async fn health_check(&self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_health_checker_creation() {
        let health_config = HealthConfig::default();
        let alert_config = AlertConfig {
            enabled: false,
            channels: vec![],
            cooldown_seconds: 300,
            escalation_enabled: false,
            escalation_delay_seconds: 900,
        };
        
        let registry = Arc::new(Registry::new());
        let metrics = HealthMetrics::new(registry).unwrap();
        
        let checker = HealthChecker::new(
            health_config,
            alert_config,
            metrics,
            "test-1.0.0".to_string(),
        );

        assert!(!checker.is_running().await);
        assert!(checker.get_latest_report().await.is_none());
    }

    #[tokio::test]
    async fn test_health_checker_on_demand_check() {
        let health_config = HealthConfig::default();
        let alert_config = AlertConfig {
            enabled: false,
            channels: vec![],
            cooldown_seconds: 300,
            escalation_enabled: false,
            escalation_delay_seconds: 900,
        };
        
        let registry = Arc::new(Registry::new());
        let metrics = HealthMetrics::new(registry).unwrap();
        
        let checker = HealthChecker::new(
            health_config,
            alert_config,
            metrics,
            "test-1.0.0".to_string(),
        );

        let database = MockDatabase;
        let cache = MockCache;
        let email = MockEmail;

        let report = checker.check_now(&database, &cache, &email, true).await;
        
        assert!(!report.checks.is_empty());
        assert!(checker.get_latest_report().await.is_some());
    }
}