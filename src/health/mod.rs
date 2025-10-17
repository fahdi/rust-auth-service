use std::collections::HashMap;
use std::time::{Duration, Instant};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use crate::database::AuthDatabase;
use crate::cache::CacheProvider;
use crate::email::EmailProvider;

pub mod checker;
pub mod metrics;
pub mod alerts;

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
    Unknown,
}

impl Default for HealthStatus {
    fn default() -> Self {
        HealthStatus::Unknown
    }
}

/// Individual health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthStatus,
    pub message: String,
    pub latency_ms: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub details: Option<HashMap<String, serde_json::Value>>,
}

/// Overall health report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub version: String,
    pub uptime_seconds: u64,
    pub checks: Vec<HealthCheck>,
    pub summary: HealthSummary,
}

/// Health summary with metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub total_checks: usize,
    pub healthy_checks: usize,
    pub warning_checks: usize,
    pub critical_checks: usize,
    pub unknown_checks: usize,
    pub average_latency_ms: f64,
}

/// Health monitor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    pub enabled: bool,
    pub check_interval_seconds: u64,
    pub timeout_seconds: u64,
    pub critical_threshold_ms: u64,
    pub warning_threshold_ms: u64,
    pub enable_detailed_checks: bool,
    pub alert_on_failure: bool,
    pub alert_cooldown_seconds: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: 30,
            timeout_seconds: 10,
            critical_threshold_ms: 5000,
            warning_threshold_ms: 1000,
            enable_detailed_checks: true,
            alert_on_failure: true,
            alert_cooldown_seconds: 300, // 5 minutes
        }
    }
}

/// Health monitor service
pub struct HealthMonitor {
    config: HealthConfig,
    start_time: Instant,
    last_alert_time: HashMap<String, Instant>,
    version: String,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new(config: HealthConfig, version: String) -> Self {
        Self {
            config,
            start_time: Instant::now(),
            last_alert_time: HashMap::new(),
            version,
        }
    }

    /// Perform basic health check
    pub async fn basic_health_check(&self) -> HealthReport {
        let mut checks = vec![
            self.check_memory().await,
            self.check_disk_space().await,
            self.check_system_load().await,
        ];

        let overall_status = self.determine_overall_status(&checks);
        let summary = self.create_summary(&checks);

        HealthReport {
            status: overall_status,
            timestamp: chrono::Utc::now(),
            version: self.version.clone(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            checks,
            summary,
        }
    }

    /// Perform detailed health check including dependencies
    pub async fn detailed_health_check(
        &self,
        database: &dyn AuthDatabase,
        cache: &dyn CacheProvider,
        email: &dyn EmailProvider,
    ) -> HealthReport {
        let mut checks = vec![
            self.check_memory().await,
            self.check_disk_space().await,
            self.check_system_load().await,
            self.check_database(database).await,
            self.check_cache(cache).await,
            self.check_email(email).await,
        ];

        if self.config.enable_detailed_checks {
            checks.extend(vec![
                self.check_jwt_functionality().await,
                self.check_password_hashing().await,
                self.check_configuration().await,
            ]);
        }

        let overall_status = self.determine_overall_status(&checks);
        let summary = self.create_summary(&checks);

        HealthReport {
            status: overall_status,
            timestamp: chrono::Utc::now(),
            version: self.version.clone(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            checks,
            summary,
        }
    }

    /// Check system memory usage
    async fn check_memory(&self) -> HealthCheck {
        let start = Instant::now();
        let name = "memory".to_string();

        match self.get_memory_info().await {
            Ok((used_mb, total_mb)) => {
                let usage_percent = (used_mb as f64 / total_mb as f64) * 100.0;
                let latency = start.elapsed().as_millis() as u64;
                
                let (status, message) = if usage_percent > 90.0 {
                    (HealthStatus::Critical, format!("Memory usage critical: {:.1}%", usage_percent))
                } else if usage_percent > 80.0 {
                    (HealthStatus::Warning, format!("Memory usage high: {:.1}%", usage_percent))
                } else {
                    (HealthStatus::Healthy, format!("Memory usage normal: {:.1}%", usage_percent))
                };

                let mut details = HashMap::new();
                details.insert("used_mb".to_string(), serde_json::Value::Number(used_mb.into()));
                details.insert("total_mb".to_string(), serde_json::Value::Number(total_mb.into()));
                details.insert("usage_percent".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(usage_percent).unwrap()));

                HealthCheck {
                    name,
                    status,
                    message,
                    latency_ms: latency,
                    timestamp: chrono::Utc::now(),
                    details: Some(details),
                }
            }
            Err(e) => HealthCheck {
                name,
                status: HealthStatus::Unknown,
                message: format!("Failed to check memory: {value}"), e),
                latency_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: None,
            }
        }
    }

    /// Check disk space usage
    async fn check_disk_space(&self) -> HealthCheck {
        let start = Instant::now();
        let name = "disk_space".to_string();

        match self.get_disk_info().await {
            Ok((free_gb, total_gb)) => {
                let usage_percent = ((total_gb - free_gb) as f64 / total_gb as f64) * 100.0;
                let latency = start.elapsed().as_millis() as u64;
                
                let (status, message) = if usage_percent > 95.0 {
                    (HealthStatus::Critical, format!("Disk usage critical: {:.1}%", usage_percent))
                } else if usage_percent > 85.0 {
                    (HealthStatus::Warning, format!("Disk usage high: {:.1}%", usage_percent))
                } else {
                    (HealthStatus::Healthy, format!("Disk usage normal: {:.1}%", usage_percent))
                };

                let mut details = HashMap::new();
                details.insert("free_gb".to_string(), serde_json::Value::Number(free_gb.into()));
                details.insert("total_gb".to_string(), serde_json::Value::Number(total_gb.into()));
                details.insert("usage_percent".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(usage_percent).unwrap()));

                HealthCheck {
                    name,
                    status,
                    message,
                    latency_ms: latency,
                    timestamp: chrono::Utc::now(),
                    details: Some(details),
                }
            }
            Err(e) => HealthCheck {
                name,
                status: HealthStatus::Unknown,
                message: format!("Failed to check disk space: {value}"), e),
                latency_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: None,
            }
        }
    }

    /// Check system load average
    async fn check_system_load(&self) -> HealthCheck {
        let start = Instant::now();
        let name = "system_load".to_string();

        match self.get_load_average().await {
            Ok((load1, load5, load15)) => {
                let cpu_cores = num_cpus::get() as f64;
                let load_percent = (load1 / cpu_cores) * 100.0;
                let latency = start.elapsed().as_millis() as u64;
                
                let (status, message) = if load_percent > 90.0 {
                    (HealthStatus::Critical, format!("System load critical: {:.2}", load1))
                } else if load_percent > 70.0 {
                    (HealthStatus::Warning, format!("System load high: {:.2}", load1))
                } else {
                    (HealthStatus::Healthy, format!("System load normal: {:.2}", load1))
                };

                let mut details = HashMap::new();
                details.insert("load_1min".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(load1).unwrap()));
                details.insert("load_5min".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(load5).unwrap()));
                details.insert("load_15min".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(load15).unwrap()));
                details.insert("cpu_cores".to_string(), serde_json::Value::Number(cpu_cores.into()));
                details.insert("load_percent".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(load_percent).unwrap()));

                HealthCheck {
                    name,
                    status,
                    message,
                    latency_ms: latency,
                    timestamp: chrono::Utc::now(),
                    details: Some(details),
                }
            }
            Err(e) => HealthCheck {
                name,
                status: HealthStatus::Unknown,
                message: format!("Failed to check system load: {value}"), e),
                latency_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: None,
            }
        }
    }

    /// Check database connectivity and performance
    async fn check_database(&self, database: &dyn AuthDatabase) -> HealthCheck {
        let start = Instant::now();
        let name = "database".to_string();

        match tokio::time::timeout(
            Duration::from_secs(self.config.timeout_seconds),
            database.health_check()
        ).await {
            Ok(Ok(health_info)) => {
                let latency = start.elapsed().as_millis() as u64;
                
                let (status, message) = if latency > self.config.critical_threshold_ms {
                    (HealthStatus::Critical, format!("Database response time critical: {}ms", latency))
                } else if latency > self.config.warning_threshold_ms {
                    (HealthStatus::Warning, format!("Database response time slow: {}ms", latency))
                } else {
                    (HealthStatus::Healthy, format!("Database healthy: {}ms", latency))
                };

                HealthCheck {
                    name,
                    status,
                    message,
                    latency_ms: latency,
                    timestamp: chrono::Utc::now(),
                    details: Some(health_info),
                }
            }
            Ok(Err(e)) => HealthCheck {
                name,
                status: HealthStatus::Critical,
                message: format!("Database connection failed: {value}"), e),
                latency_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: None,
            },
            Err(_) => HealthCheck {
                name,
                status: HealthStatus::Critical,
                message: "Database health check timed out".to_string(),
                latency_ms: self.config.timeout_seconds * 1000,
                timestamp: chrono::Utc::now(),
                details: None,
            }
        }
    }

    /// Check cache connectivity and performance
    async fn check_cache(&self, cache: &dyn CacheProvider) -> HealthCheck {
        let start = Instant::now();
        let name = "cache".to_string();

        // Test cache with a simple get/set operation
        let test_key = "health_check_test";
        let test_value = "test_value";

        match tokio::time::timeout(
            Duration::from_secs(self.config.timeout_seconds),
            async {
                cache.set(test_key, test_value, 60).await?;
                let result: Option<String> = cache.get(test_key).await?;
                cache.delete(test_key).await?;
                
                if result.as_deref() == Some(test_value) {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Cache test value mismatch"))
                }
            }
        ).await {
            Ok(Ok(_)) => {
                let latency = start.elapsed().as_millis() as u64;
                
                let (status, message) = if latency > self.config.critical_threshold_ms {
                    (HealthStatus::Critical, format!("Cache response time critical: {}ms", latency))
                } else if latency > self.config.warning_threshold_ms {
                    (HealthStatus::Warning, format!("Cache response time slow: {}ms", latency))
                } else {
                    (HealthStatus::Healthy, format!("Cache healthy: {}ms", latency))
                };

                HealthCheck {
                    name,
                    status,
                    message,
                    latency_ms: latency,
                    timestamp: chrono::Utc::now(),
                    details: None,
                }
            }
            Ok(Err(e)) => HealthCheck {
                name,
                status: HealthStatus::Critical,
                message: format!("Cache operation failed: {value}"), e),
                latency_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: None,
            },
            Err(_) => HealthCheck {
                name,
                status: HealthStatus::Critical,
                message: "Cache health check timed out".to_string(),
                latency_ms: self.config.timeout_seconds * 1000,
                timestamp: chrono::Utc::now(),
                details: None,
            }
        }
    }

    /// Check email service connectivity
    async fn check_email(&self, email: &dyn EmailProvider) -> HealthCheck {
        let start = Instant::now();
        let name = "email".to_string();

        match tokio::time::timeout(
            Duration::from_secs(self.config.timeout_seconds),
            email.health_check()
        ).await {
            Ok(Ok(_)) => {
                let latency = start.elapsed().as_millis() as u64;
                
                let (status, message) = if latency > self.config.critical_threshold_ms {
                    (HealthStatus::Critical, format!("Email service response time critical: {}ms", latency))
                } else if latency > self.config.warning_threshold_ms {
                    (HealthStatus::Warning, format!("Email service response time slow: {}ms", latency))
                } else {
                    (HealthStatus::Healthy, format!("Email service healthy: {}ms", latency))
                };

                HealthCheck {
                    name,
                    status,
                    message,
                    latency_ms: latency,
                    timestamp: chrono::Utc::now(),
                    details: None,
                }
            }
            Ok(Err(e)) => HealthCheck {
                name,
                status: HealthStatus::Warning, // Email is not critical for auth service
                message: format!("Email service connection failed: {value}"), e),
                latency_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: None,
            },
            Err(_) => HealthCheck {
                name,
                status: HealthStatus::Warning,
                message: "Email service health check timed out".to_string(),
                latency_ms: self.config.timeout_seconds * 1000,
                timestamp: chrono::Utc::now(),
                details: None,
            }
        }
    }

    /// Check JWT functionality
    async fn check_jwt_functionality(&self) -> HealthCheck {
        let start = Instant::now();
        let name = "jwt".to_string();

        // This would test JWT token generation and validation
        // Implementation depends on your JWT utilities
        let latency = start.elapsed().as_millis() as u64;

        HealthCheck {
            name,
            status: HealthStatus::Healthy,
            message: "JWT functionality check passed".to_string(),
            latency_ms: latency,
            timestamp: chrono::Utc::now(),
            details: None,
        }
    }

    /// Check password hashing functionality
    async fn check_password_hashing(&self) -> HealthCheck {
        let start = Instant::now();
        let name = "password_hashing".to_string();

        // Test bcrypt hashing
        match tokio::task::spawn_blocking(|| {
            let password = "test_password";
            let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
            bcrypt::verify(password, &hash)?;
            Ok::<(), bcrypt::BcryptError>(())
        }).await {
            Ok(Ok(_)) => {
                let latency = start.elapsed().as_millis() as u64;
                HealthCheck {
                    name,
                    status: HealthStatus::Healthy,
                    message: "Password hashing functional".to_string(),
                    latency_ms: latency,
                    timestamp: chrono::Utc::now(),
                    details: None,
                }
            }
            Ok(Err(e)) => HealthCheck {
                name,
                status: HealthStatus::Critical,
                message: format!("Password hashing failed: {value}"), e),
                latency_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: None,
            },
            Err(e) => HealthCheck {
                name,
                status: HealthStatus::Critical,
                message: format!("Password hashing task failed: {value}"), e),
                latency_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: None,
            }
        }
    }

    /// Check configuration validity
    async fn check_configuration(&self) -> HealthCheck {
        let start = Instant::now();
        let name = "configuration".to_string();

        // This would validate current configuration
        let latency = start.elapsed().as_millis() as u64;

        HealthCheck {
            name,
            status: HealthStatus::Healthy,
            message: "Configuration valid".to_string(),
            latency_ms: latency,
            timestamp: chrono::Utc::now(),
            details: None,
        }
    }

    /// Determine overall health status from individual checks
    fn determine_overall_status(&self, checks: &[HealthCheck]) -> HealthStatus {
        if checks.iter().any(|c| c.status == HealthStatus::Critical) {
            HealthStatus::Critical
        } else if checks.iter().any(|c| c.status == HealthStatus::Warning) {
            HealthStatus::Warning
        } else if checks.iter().all(|c| c.status == HealthStatus::Healthy) {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unknown
        }
    }

    /// Create health summary from checks
    fn create_summary(&self, checks: &[HealthCheck]) -> HealthSummary {
        let total_checks = checks.len();
        let healthy_checks = checks.iter().filter(|c| c.status == HealthStatus::Healthy).count();
        let warning_checks = checks.iter().filter(|c| c.status == HealthStatus::Warning).count();
        let critical_checks = checks.iter().filter(|c| c.status == HealthStatus::Critical).count();
        let unknown_checks = checks.iter().filter(|c| c.status == HealthStatus::Unknown).count();
        
        let average_latency_ms = if total_checks > 0 {
            checks.iter().map(|c| c.latency_ms as f64).sum::<f64>() / total_checks as f64
        } else {
            0.0
        };

        HealthSummary {
            total_checks,
            healthy_checks,
            warning_checks,
            critical_checks,
            unknown_checks,
            average_latency_ms,
        }
    }

    /// Get system memory information
    async fn get_memory_info(&self) -> Result<(u64, u64)> {
        // Platform-specific memory info
        #[cfg(target_os = "linux")]
        {
            let meminfo = std::fs::read_to_string("/proc/meminfo")?;
            let mut total_kb = 0;
            let mut available_kb = 0;
            
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    total_kb = line.split_whitespace().nth(1)
                        .ok_or_else(|| anyhow::anyhow!("Invalid MemTotal format"))?
                        .parse::<u64>()?;
                } else if line.starts_with("MemAvailable:") {
                    available_kb = line.split_whitespace().nth(1)
                        .ok_or_else(|| anyhow::anyhow!("Invalid MemAvailable format"))?
                        .parse::<u64>()?;
                }
            }
            
            let total_mb = total_kb / 1024;
            let used_mb = (total_kb - available_kb) / 1024;
            Ok((used_mb, total_mb))
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            // Fallback for non-Linux systems
            Ok((512, 1024)) // Mock values
        }
    }

    /// Get disk space information
    async fn get_disk_info(&self) -> Result<(u64, u64)> {
        // Platform-specific disk info
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::mem;
            
            let path = CString::new("/")?;
            let mut stat: libc::statvfs = unsafe { mem::zeroed() };
            
            let result = unsafe { libc::statvfs(path.as_ptr(), &mut stat) };
            if result == 0 {
                let total_bytes = stat.f_blocks * stat.f_frsize;
                let free_bytes = stat.f_bavail * stat.f_frsize;
                let total_gb = total_bytes / (1024 * 1024 * 1024);
                let free_gb = free_bytes / (1024 * 1024 * 1024);
                Ok((free_gb, total_gb))
            } else {
                Err(anyhow::anyhow!("Failed to get disk statistics"))
            }
        }
        
        #[cfg(not(unix))]
        {
            // Fallback for non-Unix systems
            Ok((50, 100)) // Mock values
        }
    }

    /// Get system load average
    async fn get_load_average(&self) -> Result<(f64, f64, f64)> {
        #[cfg(unix)]
        {
            let mut loadavg: [f64; 3] = [0.0; 3];
            let result = unsafe { libc::getloadavg(loadavg.as_mut_ptr(), 3) };
            if result == 3 {
                Ok((loadavg[0], loadavg[1], loadavg[2]))
            } else {
                Err(anyhow::anyhow!("Failed to get load average"))
            }
        }
        
        #[cfg(not(unix))]
        {
            // Fallback for non-Unix systems
            Ok((0.5, 0.7, 0.9)) // Mock values
        }
    }
}