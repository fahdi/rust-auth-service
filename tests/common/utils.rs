use anyhow::Result;
use std::time::{Duration, Instant};
use tokio::time;
use tracing::{info, debug, warn};

/// Performance measurement utilities for database operations
pub struct PerformanceMetrics {
    pub operation: String,
    pub duration: Duration,
    pub success: bool,
    pub database_type: String,
}

impl PerformanceMetrics {
    pub fn new(operation: &str, database_type: &str) -> Self {
        Self {
            operation: operation.to_string(),
            duration: Duration::default(),
            success: false,
            database_type: database_type.to_string(),
        }
    }

    pub fn record_duration(&mut self, duration: Duration) {
        self.duration = duration;
    }

    pub fn mark_success(&mut self) {
        self.success = true;
    }

    pub fn log_performance(&self) {
        let status = if self.success { "SUCCESS" } else { "FAILED" };
        info!(
            "PERF: {} {} on {} took {:.2}ms - {}",
            self.database_type,
            self.operation,
            self.database_type,
            self.duration.as_secs_f64() * 1000.0,
            status
        );
    }
}

/// Measure execution time of async operations
pub async fn measure_async<F, T, E>(operation: &str, database_type: &str, f: F) -> Result<(T, PerformanceMetrics)>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut metrics = PerformanceMetrics::new(operation, database_type);
    let start = Instant::now();
    
    match f.await {
        Ok(result) => {
            metrics.record_duration(start.elapsed());
            metrics.mark_success();
            metrics.log_performance();
            Ok((result, metrics))
        }
        Err(e) => {
            metrics.record_duration(start.elapsed());
            metrics.log_performance();
            Err(anyhow::anyhow!("{}: {}", operation, e))
        }
    }
}

/// Wait for condition with timeout
pub async fn wait_for_condition<F, Fut>(
    description: &str,
    condition: F,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<()>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    
    loop {
        if condition().await {
            debug!("Condition '{}' met after {:.2}s", description, start.elapsed().as_secs_f64());
            return Ok(());
        }
        
        if start.elapsed() >= timeout {
            return Err(anyhow::anyhow!(
                "Timeout waiting for condition '{}' after {:.2}s",
                description,
                timeout.as_secs_f64()
            ));
        }
        
        time::sleep(poll_interval).await;
    }
}

/// Database consistency checker
pub struct ConsistencyChecker;

impl ConsistencyChecker {
    /// Check if user data is consistent across databases
    pub async fn check_user_consistency(
        databases: &[(&str, &rust_auth_service::database::AuthDatabase)],
        user_email: &str,
    ) -> Result<()> {
        debug!("Checking user consistency for: {}", user_email);
        
        let mut users = Vec::new();
        
        // Fetch user from all databases
        for (db_type, db) in databases {
            match db.find_user_by_email(user_email).await {
                Ok(Some(user)) => users.push((*db_type, user)),
                Ok(None) => return Err(anyhow::anyhow!("User not found in {}", db_type)),
                Err(e) => return Err(anyhow::anyhow!("Error fetching from {}: {:?}", db_type, e)),
            }
        }
        
        if users.is_empty() {
            return Err(anyhow::anyhow!("No users found in any database"));
        }
        
        // Compare all users
        let reference = &users[0].1;
        for (db_type, user) in &users[1..] {
            if !users_are_equivalent(reference, user) {
                return Err(anyhow::anyhow!(
                    "User data inconsistent between {} and {}",
                    users[0].0, db_type
                ));
            }
        }
        
        info!("User consistency check passed for: {}", user_email);
        Ok(())
    }
}

/// Compare two users for functional equivalence (ignoring database-specific differences)
fn users_are_equivalent(user1: &rust_auth_service::models::user::User, user2: &rust_auth_service::models::user::User) -> bool {
    // Compare core fields that should be identical
    user1.email == user2.email
        && user1.password_hash == user2.password_hash
        && user1.full_name == user2.full_name
        && user1.role == user2.role
        && user1.is_active == user2.is_active
        && user1.email_verified == user2.email_verified
        && user1.failed_login_attempts == user2.failed_login_attempts
        && timestamps_are_close(&user1.created_at, &user2.created_at, Duration::from_secs(5))
        && timestamps_are_close(&user1.updated_at, &user2.updated_at, Duration::from_secs(5))
}

/// Check if two timestamps are within tolerance (accounts for database precision differences)
fn timestamps_are_close(
    time1: &chrono::DateTime<chrono::Utc>,
    time2: &chrono::DateTime<chrono::Utc>,
    tolerance: Duration,
) -> bool {
    let diff = (*time1 - *time2).abs();
    diff <= chrono::Duration::from_std(tolerance).unwrap_or(chrono::Duration::seconds(1))
}

/// Stress testing utilities
pub struct StressTestRunner {
    pub concurrent_operations: usize,
    pub operation_count: usize,
    pub success_count: std::sync::atomic::AtomicUsize,
    pub error_count: std::sync::atomic::AtomicUsize,
}

impl StressTestRunner {
    pub fn new(concurrent_operations: usize, operation_count: usize) -> Self {
        Self {
            concurrent_operations,
            operation_count,
            success_count: std::sync::atomic::AtomicUsize::new(0),
            error_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Run concurrent database operations
    pub async fn run_concurrent_test<F, Fut>(&self, operation_factory: F) -> Result<Duration>
    where
        F: Fn(usize) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;
        
        let start = Instant::now();
        let operation_factory = Arc::new(operation_factory);
        let mut handles = Vec::new();
        
        for batch in 0..self.concurrent_operations {
            let factory = operation_factory.clone();
            let success_count = Arc::new(&self.success_count);
            let error_count = Arc::new(&self.error_count);
            
            let handle = tokio::spawn(async move {
                for i in 0..self.operation_count / self.concurrent_operations {
                    let operation_id = batch * (self.operation_count / self.concurrent_operations) + i;
                    
                    match factory(operation_id).await {
                        Ok(()) => success_count.fetch_add(1, Ordering::Relaxed),
                        Err(e) => {
                            warn!("Operation {} failed: {}", operation_id, e);
                            error_count.fetch_add(1, Ordering::Relaxed)
                        }
                    };
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for all operations to complete
        for handle in handles {
            handle.await.map_err(|e| anyhow::anyhow!("Task join error: {}", e))?;
        }
        
        let duration = start.elapsed();
        let total_ops = self.success_count.load(Ordering::Relaxed) + self.error_count.load(Ordering::Relaxed);
        
        info!(
            "Stress test completed: {} operations in {:.2}s ({:.1} ops/s), {} successes, {} errors",
            total_ops,
            duration.as_secs_f64(),
            total_ops as f64 / duration.as_secs_f64(),
            self.success_count.load(Ordering::Relaxed),
            self.error_count.load(Ordering::Relaxed)
        );
        
        Ok(duration)
    }

    pub fn success_rate(&self) -> f64 {
        use std::sync::atomic::Ordering;
        let successes = self.success_count.load(Ordering::Relaxed) as f64;
        let total = successes + self.error_count.load(Ordering::Relaxed) as f64;
        if total == 0.0 { 0.0 } else { successes / total }
    }
}

/// Test environment utilities
pub struct TestEnvironment;

impl TestEnvironment {
    /// Check if required databases are available for testing
    pub async fn check_database_availability(database_types: &[&str]) -> Result<Vec<String>> {
        let mut available = Vec::new();
        
        for &db_type in database_types {
            if Self::is_database_available(db_type).await {
                available.push(db_type.to_string());
                info!("Database {} is available for testing", db_type);
            } else {
                warn!("Database {} is not available for testing", db_type);
            }
        }
        
        if available.is_empty() {
            return Err(anyhow::anyhow!("No databases available for testing"));
        }
        
        Ok(available)
    }

    /// Check if specific database type is available
    async fn is_database_available(database_type: &str) -> bool {
        // Try to create a test configuration and connect
        match crate::common::database::create_test_database_config(database_type, "availability_check").await {
            Ok(config) => {
                match rust_auth_service::database::create_database(&config).await {
                    Ok(db) => {
                        // Try a simple health check
                        match db.health_check().await {
                            Ok(health) => health.connected,
                            Err(_) => false,
                        }
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }

    /// Generate test report
    pub fn generate_test_report(
        database_types: &[String],
        performance_metrics: &[PerformanceMetrics],
    ) -> String {
        let mut report = String::new();
        report.push_str("=== Database Integration Test Report ===\n\n");
        
        // Summary
        report.push_str(&format!("Tested Databases: {}\n", database_types.join(", ")));
        report.push_str(&format!("Total Operations: {}\n", performance_metrics.len()));
        
        let successful = performance_metrics.iter().filter(|m| m.success).count();
        let failed = performance_metrics.len() - successful;
        
        report.push_str(&format!("Successful: {}\n", successful));
        report.push_str(&format!("Failed: {}\n", failed));
        
        if !performance_metrics.is_empty() {
            let avg_duration: f64 = performance_metrics
                .iter()
                .map(|m| m.duration.as_secs_f64())
                .sum::<f64>() / performance_metrics.len() as f64;
            
            report.push_str(&format!("Average Duration: {:.2}ms\n\n", avg_duration * 1000.0));
        }
        
        // Per-database breakdown
        for db_type in database_types {
            let db_metrics: Vec<_> = performance_metrics
                .iter()
                .filter(|m| m.database_type == *db_type)
                .collect();
            
            if !db_metrics.is_empty() {
                let db_successful = db_metrics.iter().filter(|m| m.success).count();
                let db_avg: f64 = db_metrics
                    .iter()
                    .map(|m| m.duration.as_secs_f64())
                    .sum::<f64>() / db_metrics.len() as f64;
                
                report.push_str(&format!(
                    "{}: {} operations, {} successful, {:.2}ms avg\n",
                    db_type,
                    db_metrics.len(),
                    db_successful,
                    db_avg * 1000.0
                ));
            }
        }
        
        report
    }
}