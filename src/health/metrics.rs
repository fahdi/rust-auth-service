use std::sync::Arc;
use std::collections::HashMap;
use prometheus::{Counter, Gauge, Histogram, IntCounter, IntGauge, Registry, Opts, HistogramOpts};
use anyhow::Result;
use super::{HealthReport, HealthStatus, HealthCheck};

/// Health monitoring metrics collector
pub struct HealthMetrics {
    registry: Arc<Registry>,
    
    // Health check metrics
    health_check_total: IntCounter,
    health_check_duration_seconds: Histogram,
    health_check_status: IntGauge,
    
    // Component health metrics
    database_health_status: IntGauge,
    cache_health_status: IntGauge,
    email_health_status: IntGauge,
    
    // System metrics
    memory_usage_bytes: Gauge,
    memory_usage_percent: Gauge,
    disk_usage_bytes: Gauge,
    disk_usage_percent: Gauge,
    system_load_average: Gauge,
    
    // Service metrics
    service_uptime_seconds: Gauge,
    service_version_info: IntGauge,
    
    // Alert metrics
    alerts_total: IntCounter,
    active_alerts: IntGauge,
    alert_resolution_time_seconds: Histogram,
    
    // Component-specific metrics
    component_metrics: HashMap<String, ComponentMetrics>,
}

/// Metrics for individual components
#[derive(Clone)]
pub struct ComponentMetrics {
    pub health_status: IntGauge,
    pub check_duration_seconds: Histogram,
    pub check_total: IntCounter,
    pub last_check_timestamp: Gauge,
    pub consecutive_failures: IntGauge,
}

impl HealthMetrics {
    /// Create new health metrics collector
    pub fn new(registry: Arc<Registry>) -> Result<Self> {
        let health_check_total = IntCounter::with_opts(
            Opts::new("health_check_total", "Total number of health checks performed")
        )?;
        registry.register(Box::new(health_check_total.clone()))?;

        let health_check_duration_seconds = Histogram::with_opts(
            HistogramOpts::new("health_check_duration_seconds", "Duration of health checks in seconds")
                .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0])
        )?;
        registry.register(Box::new(health_check_duration_seconds.clone()))?;

        let health_check_status = IntGauge::with_opts(
            Opts::new("health_check_status", "Current health check status (0=Unknown, 1=Healthy, 2=Warning, 3=Critical)")
        )?;
        registry.register(Box::new(health_check_status.clone()))?;

        // Component health metrics
        let database_health_status = IntGauge::with_opts(
            Opts::new("database_health_status", "Database health status")
        )?;
        registry.register(Box::new(database_health_status.clone()))?;

        let cache_health_status = IntGauge::with_opts(
            Opts::new("cache_health_status", "Cache health status")
        )?;
        registry.register(Box::new(cache_health_status.clone()))?;

        let email_health_status = IntGauge::with_opts(
            Opts::new("email_health_status", "Email service health status")
        )?;
        registry.register(Box::new(email_health_status.clone()))?;

        // System metrics
        let memory_usage_bytes = Gauge::with_opts(
            Opts::new("memory_usage_bytes", "Current memory usage in bytes")
        )?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;

        let memory_usage_percent = Gauge::with_opts(
            Opts::new("memory_usage_percent", "Current memory usage percentage")
        )?;
        registry.register(Box::new(memory_usage_percent.clone()))?;

        let disk_usage_bytes = Gauge::with_opts(
            Opts::new("disk_usage_bytes", "Current disk usage in bytes")
        )?;
        registry.register(Box::new(disk_usage_bytes.clone()))?;

        let disk_usage_percent = Gauge::with_opts(
            Opts::new("disk_usage_percent", "Current disk usage percentage")
        )?;
        registry.register(Box::new(disk_usage_percent.clone()))?;

        let system_load_average = Gauge::with_opts(
            Opts::new("system_load_average", "System load average")
        )?;
        registry.register(Box::new(system_load_average.clone()))?;

        // Service metrics
        let service_uptime_seconds = Gauge::with_opts(
            Opts::new("service_uptime_seconds", "Service uptime in seconds")
        )?;
        registry.register(Box::new(service_uptime_seconds.clone()))?;

        let service_version_info = IntGauge::with_opts(
            Opts::new("service_version_info", "Service version information")
        )?;
        registry.register(Box::new(service_version_info.clone()))?;

        // Alert metrics
        let alerts_total = IntCounter::with_opts(
            Opts::new("alerts_total", "Total number of alerts generated")
        )?;
        registry.register(Box::new(alerts_total.clone()))?;

        let active_alerts = IntGauge::with_opts(
            Opts::new("active_alerts", "Number of currently active alerts")
        )?;
        registry.register(Box::new(active_alerts.clone()))?;

        let alert_resolution_time_seconds = Histogram::with_opts(
            HistogramOpts::new("alert_resolution_time_seconds", "Time taken to resolve alerts in seconds")
                .buckets(vec![1.0, 10.0, 60.0, 300.0, 600.0, 1800.0, 3600.0, 7200.0])
        )?;
        registry.register(Box::new(alert_resolution_time_seconds.clone()))?;

        Ok(Self {
            registry,
            health_check_total,
            health_check_duration_seconds,
            health_check_status,
            database_health_status,
            cache_health_status,
            email_health_status,
            memory_usage_bytes,
            memory_usage_percent,
            disk_usage_bytes,
            disk_usage_percent,
            system_load_average,
            service_uptime_seconds,
            service_version_info,
            alerts_total,
            active_alerts,
            alert_resolution_time_seconds,
            component_metrics: HashMap::new(),
        })
    }

    /// Record health check metrics from a health report
    pub fn record_health_report(&mut self, report: &HealthReport) {
        // Update overall health status
        self.health_check_status.set(self.status_to_number(&report.status));
        
        // Update service uptime
        self.service_uptime_seconds.set(report.uptime_seconds as f64);
        
        // Update service version (set to 1 to indicate presence)
        self.service_version_info.set(1);

        // Record individual check metrics
        for check in &report.checks {
            self.record_health_check(check);
        }

        // Record summary metrics
        self.record_summary_metrics(report);
    }

    /// Record metrics for an individual health check
    pub fn record_health_check(&mut self, check: &HealthCheck) {
        // Increment total health checks
        self.health_check_total.inc();
        
        // Record check duration
        let duration_seconds = check.latency_ms as f64 / 1000.0;
        self.health_check_duration_seconds.observe(duration_seconds);

        // Get or create component metrics
        let component_metrics = self.get_or_create_component_metrics(&check.name);
        
        // Update component-specific metrics
        component_metrics.check_total.inc();
        component_metrics.check_duration_seconds.observe(duration_seconds);
        component_metrics.health_status.set(self.status_to_number(&check.status));
        component_metrics.last_check_timestamp.set(check.timestamp.timestamp() as f64);

        // Update consecutive failures
        match check.status {
            HealthStatus::Healthy => {
                component_metrics.consecutive_failures.set(0);
            }
            _ => {
                component_metrics.consecutive_failures.inc();
            }
        }

        // Update specific component metrics
        match check.name.as_str() {
            "database" => self.database_health_status.set(self.status_to_number(&check.status)),
            "cache" => self.cache_health_status.set(self.status_to_number(&check.status)),
            "email" => self.email_health_status.set(self.status_to_number(&check.status)),
            _ => {}
        }

        // Extract and record system metrics from check details
        if let Some(details) = &check.details {
            match check.name.as_str() {
                "memory" => {
                    if let Some(used_mb) = details.get("used_mb").and_then(|v| v.as_u64()) {
                        self.memory_usage_bytes.set((used_mb * 1024 * 1024) as f64);
                    }
                    if let Some(usage_percent) = details.get("usage_percent").and_then(|v| v.as_f64()) {
                        self.memory_usage_percent.set(usage_percent);
                    }
                }
                "disk_space" => {
                    if let Some(total_gb) = details.get("total_gb").and_then(|v| v.as_u64()) {
                        if let Some(free_gb) = details.get("free_gb").and_then(|v| v.as_u64()) {
                            let used_bytes = ((total_gb - free_gb) * 1024 * 1024 * 1024) as f64;
                            self.disk_usage_bytes.set(used_bytes);
                        }
                    }
                    if let Some(usage_percent) = details.get("usage_percent").and_then(|v| v.as_f64()) {
                        self.disk_usage_percent.set(usage_percent);
                    }
                }
                "system_load" => {
                    if let Some(load1) = details.get("load_1min").and_then(|v| v.as_f64()) {
                        self.system_load_average.set(load1);
                    }
                }
                _ => {}
            }
        }
    }

    /// Record summary metrics from health report
    fn record_summary_metrics(&self, report: &HealthReport) {
        // These could be recorded as additional metrics if needed
        // For now, they're captured in the individual check metrics
    }

    /// Record alert metrics
    pub fn record_alert_generated(&self) {
        self.alerts_total.inc();
        self.active_alerts.inc();
    }

    /// Record alert resolution
    pub fn record_alert_resolved(&self, resolution_time_seconds: f64) {
        self.active_alerts.dec();
        self.alert_resolution_time_seconds.observe(resolution_time_seconds);
    }

    /// Update active alerts count
    pub fn set_active_alerts_count(&self, count: i64) {
        self.active_alerts.set(count);
    }

    /// Get or create component metrics
    fn get_or_create_component_metrics(&mut self, component_name: &str) -> &mut ComponentMetrics {
        if !self.component_metrics.contains_key(component_name) {
            let component_metrics = self.create_component_metrics(component_name)
                .expect("Failed to create component metrics");
            self.component_metrics.insert(component_name.to_string(), component_metrics);
        }
        
        self.component_metrics.get_mut(component_name).unwrap()
    }

    /// Create metrics for a new component
    fn create_component_metrics(&self, component_name: &str) -> Result<ComponentMetrics> {
        let health_status = IntGauge::with_opts(
            Opts::new(
                format!("component_health_status_{}", component_name),
                format!("Health status for component {}", component_name)
            )
        )?;
        self.registry.register(Box::new(health_status.clone()))?;

        let check_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                format!("component_check_duration_seconds_{}", component_name),
                format!("Health check duration for component {} in seconds", component_name)
            ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0])
        )?;
        self.registry.register(Box::new(check_duration_seconds.clone()))?;

        let check_total = IntCounter::with_opts(
            Opts::new(
                format!("component_check_total_{}", component_name),
                format!("Total health checks for component {}", component_name)
            )
        )?;
        self.registry.register(Box::new(check_total.clone()))?;

        let last_check_timestamp = Gauge::with_opts(
            Opts::new(
                format!("component_last_check_timestamp_{}", component_name),
                format!("Timestamp of last health check for component {}", component_name)
            )
        )?;
        self.registry.register(Box::new(last_check_timestamp.clone()))?;

        let consecutive_failures = IntGauge::with_opts(
            Opts::new(
                format!("component_consecutive_failures_{}", component_name),
                format!("Number of consecutive failures for component {}", component_name)
            )
        )?;
        self.registry.register(Box::new(consecutive_failures.clone()))?;

        Ok(ComponentMetrics {
            health_status,
            check_duration_seconds,
            check_total,
            last_check_timestamp,
            consecutive_failures,
        })
    }

    /// Convert health status to numeric value for Prometheus
    fn status_to_number(&self, status: &HealthStatus) -> i64 {
        match status {
            HealthStatus::Unknown => 0,
            HealthStatus::Healthy => 1,
            HealthStatus::Warning => 2,
            HealthStatus::Critical => 3,
        }
    }

    /// Get registry for Prometheus metrics
    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }

    /// Reset all metrics (useful for testing)
    pub fn reset(&mut self) {
        self.health_check_total.reset();
        self.health_check_status.set(0);
        self.database_health_status.set(0);
        self.cache_health_status.set(0);
        self.email_health_status.set(0);
        self.memory_usage_bytes.set(0.0);
        self.memory_usage_percent.set(0.0);
        self.disk_usage_bytes.set(0.0);
        self.disk_usage_percent.set(0.0);
        self.system_load_average.set(0.0);
        self.service_uptime_seconds.set(0.0);
        self.service_version_info.set(0);
        self.alerts_total.reset();
        self.active_alerts.set(0);

        for component_metrics in self.component_metrics.values_mut() {
            component_metrics.check_total.reset();
            component_metrics.health_status.set(0);
            component_metrics.last_check_timestamp.set(0.0);
            component_metrics.consecutive_failures.set(0);
        }
    }

    /// Get current metrics values (useful for debugging)
    pub fn get_current_values(&self) -> HashMap<String, f64> {
        let mut values = HashMap::new();
        
        values.insert("health_check_total".to_string(), self.health_check_total.get() as f64);
        values.insert("health_check_status".to_string(), self.health_check_status.get() as f64);
        values.insert("database_health_status".to_string(), self.database_health_status.get() as f64);
        values.insert("cache_health_status".to_string(), self.cache_health_status.get() as f64);
        values.insert("email_health_status".to_string(), self.email_health_status.get() as f64);
        values.insert("memory_usage_bytes".to_string(), self.memory_usage_bytes.get());
        values.insert("memory_usage_percent".to_string(), self.memory_usage_percent.get());
        values.insert("disk_usage_bytes".to_string(), self.disk_usage_bytes.get());
        values.insert("disk_usage_percent".to_string(), self.disk_usage_percent.get());
        values.insert("system_load_average".to_string(), self.system_load_average.get());
        values.insert("service_uptime_seconds".to_string(), self.service_uptime_seconds.get());
        values.insert("active_alerts".to_string(), self.active_alerts.get() as f64);
        
        values
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Registry;
    use std::collections::HashMap;

    #[test]
    fn test_health_metrics_creation() {
        let registry = Arc::new(Registry::new());
        let metrics = HealthMetrics::new(registry).expect("Failed to create health metrics");
        
        // Test that metrics were created successfully
        assert_eq!(metrics.health_check_total.get(), 0);
        assert_eq!(metrics.health_check_status.get(), 0);
    }

    #[test]
    fn test_status_to_number_conversion() {
        let registry = Arc::new(Registry::new());
        let metrics = HealthMetrics::new(registry).unwrap();
        
        assert_eq!(metrics.status_to_number(&HealthStatus::Unknown), 0);
        assert_eq!(metrics.status_to_number(&HealthStatus::Healthy), 1);
        assert_eq!(metrics.status_to_number(&HealthStatus::Warning), 2);
        assert_eq!(metrics.status_to_number(&HealthStatus::Critical), 3);
    }

    #[test]
    fn test_health_check_recording() {
        let registry = Arc::new(Registry::new());
        let mut metrics = HealthMetrics::new(registry).unwrap();
        
        let check = HealthCheck {
            name: "test_component".to_string(),
            status: HealthStatus::Healthy,
            message: "Test check".to_string(),
            latency_ms: 100,
            timestamp: chrono::Utc::now(),
            details: None,
        };
        
        metrics.record_health_check(&check);
        
        assert_eq!(metrics.health_check_total.get(), 1);
        assert!(metrics.component_metrics.contains_key("test_component"));
    }

    #[test]
    fn test_alert_metrics() {
        let registry = Arc::new(Registry::new());
        let metrics = HealthMetrics::new(registry).unwrap();
        
        metrics.record_alert_generated();
        assert_eq!(metrics.alerts_total.get(), 1);
        assert_eq!(metrics.active_alerts.get(), 1);
        
        metrics.record_alert_resolved(300.0);
        assert_eq!(metrics.active_alerts.get(), 0);
    }

    #[test]
    fn test_metrics_reset() {
        let registry = Arc::new(Registry::new());
        let mut metrics = HealthMetrics::new(registry).unwrap();
        
        // Record some metrics
        metrics.record_alert_generated();
        metrics.health_check_total.inc();
        
        // Reset and verify
        metrics.reset();
        assert_eq!(metrics.health_check_total.get(), 0);
        assert_eq!(metrics.active_alerts.get(), 0);
    }
}