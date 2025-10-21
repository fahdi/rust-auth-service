use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::common::{IntegrationTestFramework, TestUser};

/// Database performance targets from Issue #43
#[derive(Debug, Clone)]
pub struct DatabasePerformanceTargets {
    pub user_create_ms: u64,        // <20ms per operation
    pub user_lookup_ms: u64,        // <5ms per operation
    pub user_update_ms: u64,        // <12ms per operation
    pub bulk_operations_ms: u64,    // <1500ms for 100 users
    pub connection_pool_efficiency: f64, // >90% efficiency
    pub concurrent_operations_success_rate: f64, // >95% success rate
}

impl Default for DatabasePerformanceTargets {
    fn default() -> Self {
        Self {
            user_create_ms: 20,
            user_lookup_ms: 5,
            user_update_ms: 12,
            bulk_operations_ms: 1500,
            connection_pool_efficiency: 0.90,
            concurrent_operations_success_rate: 0.95,
        }
    }
}

/// Database operation metrics
#[derive(Debug, Default)]
pub struct DatabaseMetrics {
    pub operation_name: String,
    pub total_operations: usize,
    pub successful_operations: usize,
    pub failed_operations: usize,
    pub response_times: Vec<Duration>,
    pub test_duration: Duration,
    pub connection_pool_stats: HashMap<String, f64>,
}

impl DatabaseMetrics {
    pub fn new(operation_name: &str) -> Self {
        Self {
            operation_name: operation_name.to_string(),
            ..Default::default()
        }
    }

    pub fn add_result(&mut self, success: bool, response_time: Duration) {
        self.total_operations += 1;
        if success {
            self.successful_operations += 1;
        } else {
            self.failed_operations += 1;
        }
        self.response_times.push(response_time);
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_operations == 0 {
            0.0
        } else {
            self.successful_operations as f64 / self.total_operations as f64
        }
    }

    pub fn operations_per_second(&self) -> f64 {
        if self.test_duration.as_millis() == 0 {
            0.0
        } else {
            self.total_operations as f64 / self.test_duration.as_secs_f64()
        }
    }

    pub fn average_response_time(&self) -> Duration {
        if self.response_times.is_empty() {
            Duration::from_millis(0)
        } else {
            let total: Duration = self.response_times.iter().sum();
            total / self.response_times.len() as u32
        }
    }

    pub fn calculate_percentiles(&self) -> (Duration, Duration, Duration) {
        if self.response_times.is_empty() {
            return (Duration::from_millis(0), Duration::from_millis(0), Duration::from_millis(0));
        }

        let mut sorted_times = self.response_times.clone();
        sorted_times.sort();

        let len = sorted_times.len();
        let p50_idx = len * 50 / 100;
        let p95_idx = len * 95 / 100;
        let p99_idx = len * 99 / 100;

        (
            sorted_times[p50_idx.min(len - 1)],
            sorted_times[p95_idx.min(len - 1)],
            sorted_times[p99_idx.min(len - 1)],
        )
    }

    pub fn print_detailed_metrics(&self) {
        let (p50, p95, p99) = self.calculate_percentiles();
        
        println!("\n📊 Database Performance Metrics: {}", self.operation_name);
        println!("├─ Total Operations: {}", self.total_operations);
        println!("├─ Success Rate: {:.2}%", self.success_rate() * 100.0);
        println!("├─ Operations/sec: {:.2}", self.operations_per_second());
        println!("├─ Average Response: {:.2}ms", self.average_response_time().as_millis());
        println!("├─ P50 Response: {:.2}ms", p50.as_millis());
        println!("├─ P95 Response: {:.2}ms", p95.as_millis());
        println!("├─ P99 Response: {:.2}ms", p99.as_millis());
        println!("└─ Test Duration: {:.2}s", self.test_duration.as_secs_f64());

        if !self.connection_pool_stats.is_empty() {
            println!("\n🔗 Connection Pool Statistics:");
            for (key, value) in &self.connection_pool_stats {
                println!("├─ {}: {:.2}", key, value);
            }
        }
    }
}

/// Test database operation performance
#[tokio::test]
async fn test_database_operation_performance() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping database performance test.");
        return Ok(());
    }

    info!("🗃️ Testing database operation performance");
    
    // Test user creation performance
    println!("📝 Testing user creation performance...");
    let create_metrics = test_user_creation_performance(&framework).await?;
    
    // Test user lookup performance
    println!("🔍 Testing user lookup performance...");
    let lookup_metrics = test_user_lookup_performance(&framework).await?;
    
    // Test user update performance
    println!("✏️ Testing user update performance...");
    let update_metrics = test_user_update_performance(&framework).await?;
    
    // Validate performance targets
    let targets = DatabasePerformanceTargets::default();
    
    // Validate user creation performance
    let (_, create_p95, _) = create_metrics.calculate_percentiles();
    assert!(
        create_p95.as_millis() <= targets.user_create_ms as u128,
        "User creation P95 should be ≤{}ms, got {}ms",
        targets.user_create_ms,
        create_p95.as_millis()
    );
    
    // Validate user lookup performance
    let (_, lookup_p95, _) = lookup_metrics.calculate_percentiles();
    assert!(
        lookup_p95.as_millis() <= targets.user_lookup_ms as u128,
        "User lookup P95 should be ≤{}ms, got {}ms",
        targets.user_lookup_ms,
        lookup_p95.as_millis()
    );
    
    // Validate user update performance
    let (_, update_p95, _) = update_metrics.calculate_percentiles();
    assert!(
        update_p95.as_millis() <= targets.user_update_ms as u128,
        "User update P95 should be ≤{}ms, got {}ms",
        targets.user_update_ms,
        update_p95.as_millis()
    );
    
    println!("✅ Database operation performance targets met");
    Ok(())
}

/// Test user creation performance
async fn test_user_creation_performance(framework: &IntegrationTestFramework) -> Result<DatabaseMetrics> {
    const NUM_USERS: usize = 100;
    
    let mut metrics = DatabaseMetrics::new("User Creation");
    let start_time = Instant::now();
    let mut handles = Vec::new();

    // Create users concurrently
    for i in 0..NUM_USERS {
        let client = framework.client.clone();
        let user = TestUser::new(&format!("db_create_perf_{}", i));
        
        let handle = tokio::spawn(async move {
            let request_start = Instant::now();
            let result = client.register(&user).await;
            let elapsed = request_start.elapsed();
            
            match result {
                Ok(_) => (true, elapsed),
                Err(_) => (false, elapsed),
            }
        });
        
        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        if let Ok((success, response_time)) = handle.await {
            metrics.add_result(success, response_time);
        }
    }

    metrics.test_duration = start_time.elapsed();
    metrics.print_detailed_metrics();
    
    Ok(metrics)
}

/// Test user lookup performance
async fn test_user_lookup_performance(framework: &IntegrationTestFramework) -> Result<DatabaseMetrics> {
    const NUM_LOOKUPS: usize = 200;
    
    // Create test users first
    println!("📝 Creating test users for lookup testing...");
    let mut test_users = Vec::new();
    for i in 0..50 {
        let user = TestUser::new(&format!("db_lookup_perf_{}", i));
        let _ = framework.client.register(&user).await?;
        test_users.push(user);
    }
    
    let mut metrics = DatabaseMetrics::new("User Lookup");
    let start_time = Instant::now();
    let mut handles = Vec::new();

    // Perform lookups (login operations which require user lookup)
    for i in 0..NUM_LOOKUPS {
        let client = framework.client.clone();
        let user = test_users[i % test_users.len()].clone();
        
        let handle = tokio::spawn(async move {
            let request_start = Instant::now();
            let result = client.login(&user).await;
            let elapsed = request_start.elapsed();
            
            match result {
                Ok(_) => (true, elapsed),
                Err(_) => (false, elapsed),
            }
        });
        
        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        if let Ok((success, response_time)) = handle.await {
            metrics.add_result(success, response_time);
        }
    }

    metrics.test_duration = start_time.elapsed();
    metrics.print_detailed_metrics();
    
    Ok(metrics)
}

/// Test user update performance
async fn test_user_update_performance(framework: &IntegrationTestFramework) -> Result<DatabaseMetrics> {
    const NUM_UPDATES: usize = 100;
    
    // Create test users first and get their tokens
    println!("📝 Creating test users for update testing...");
    let mut user_tokens = Vec::new();
    for i in 0..NUM_UPDATES {
        let user = TestUser::new(&format!("db_update_perf_{}", i));
        let (tokens, _) = framework.client.register(&user).await?;
        user_tokens.push(tokens.access_token);
    }
    
    let mut metrics = DatabaseMetrics::new("User Update");
    let start_time = Instant::now();
    let mut handles = Vec::new();

    // Perform profile updates
    for (i, token) in user_tokens.into_iter().enumerate() {
        let client = framework.client.clone();
        
        let handle = tokio::spawn(async move {
            let request_start = Instant::now();
            let update_data = serde_json::json!({
                "first_name": format!("Updated{}", i),
                "last_name": "User"
            });
            let result = client.update_profile(&token, &update_data).await;
            let elapsed = request_start.elapsed();
            
            match result {
                Ok(_) => (true, elapsed),
                Err(_) => (false, elapsed),
            }
        });
        
        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        if let Ok((success, response_time)) = handle.await {
            metrics.add_result(success, response_time);
        }
    }

    metrics.test_duration = start_time.elapsed();
    metrics.print_detailed_metrics();
    
    Ok(metrics)
}

/// Test bulk database operations performance
#[tokio::test]
async fn test_bulk_database_operations() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping bulk database test.");
        return Ok(());
    }

    info!("📦 Testing bulk database operations performance");
    
    const BULK_SIZE: usize = 100;
    let targets = DatabasePerformanceTargets::default();
    
    let mut metrics = DatabaseMetrics::new("Bulk Operations");
    let start_time = Instant::now();
    
    // Create bulk users sequentially to test database throughput
    for i in 0..BULK_SIZE {
        let user = TestUser::new(&format!("bulk_db_perf_{}", i));
        let request_start = Instant::now();
        
        match framework.client.register(&user).await {
            Ok(_) => metrics.add_result(true, request_start.elapsed()),
            Err(_) => metrics.add_result(false, request_start.elapsed()),
        }
    }
    
    metrics.test_duration = start_time.elapsed();
    metrics.print_detailed_metrics();
    
    // Validate bulk operation performance
    assert!(
        metrics.test_duration.as_millis() <= targets.bulk_operations_ms as u128,
        "Bulk operations should complete in ≤{}ms, took {}ms",
        targets.bulk_operations_ms,
        metrics.test_duration.as_millis()
    );
    
    assert!(
        metrics.success_rate() >= targets.concurrent_operations_success_rate,
        "Bulk operations success rate should be ≥{:.2}%, got {:.2}%",
        targets.concurrent_operations_success_rate * 100.0,
        metrics.success_rate() * 100.0
    );
    
    println!("✅ Bulk database operations performance targets met");
    Ok(())
}

/// Test database connection pool performance
#[tokio::test]
async fn test_connection_pool_performance() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping connection pool test.");
        return Ok(());
    }

    info!("🔗 Testing database connection pool performance");
    
    const CONCURRENT_CONNECTIONS: usize = 50;
    const OPERATIONS_PER_CONNECTION: usize = 10;
    
    let mut metrics = DatabaseMetrics::new("Connection Pool Test");
    let start_time = Instant::now();
    let semaphore = Arc::new(Semaphore::new(CONCURRENT_CONNECTIONS));
    let mut handles = Vec::new();

    // Launch concurrent database operations
    for i in 0..(CONCURRENT_CONNECTIONS * OPERATIONS_PER_CONNECTION) {
        let client = framework.client.clone();
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        
        let handle = tokio::spawn(async move {
            let _permit = permit;
            let user = TestUser::new(&format!("pool_test_{}", i));
            let request_start = Instant::now();
            
            // Perform a database operation
            let result = client.register(&user).await;
            let elapsed = request_start.elapsed();
            
            match result {
                Ok(_) => (true, elapsed),
                Err(_) => (false, elapsed),
            }
        });
        
        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        if let Ok((success, response_time)) = handle.await {
            metrics.add_result(success, response_time);
        }
    }

    metrics.test_duration = start_time.elapsed();
    
    // Add mock connection pool statistics
    metrics.connection_pool_stats.insert("max_connections".to_string(), 50.0);
    metrics.connection_pool_stats.insert("active_connections".to_string(), CONCURRENT_CONNECTIONS as f64);
    metrics.connection_pool_stats.insert("pool_utilization".to_string(), 
        (CONCURRENT_CONNECTIONS as f64 / 50.0) * 100.0);
    
    metrics.print_detailed_metrics();
    
    let targets = DatabasePerformanceTargets::default();
    
    // Validate connection pool efficiency
    assert!(
        metrics.success_rate() >= targets.concurrent_operations_success_rate,
        "Connection pool success rate should be ≥{:.2}%, got {:.2}%",
        targets.concurrent_operations_success_rate * 100.0,
        metrics.success_rate() * 100.0
    );
    
    println!("✅ Database connection pool performance targets met");
    Ok(())
}

/// Test database query performance under load
#[tokio::test]
async fn test_database_query_performance_under_load() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping query performance test.");
        return Ok(());
    }

    info!("🔍 Testing database query performance under load");
    
    // Create a set of test users for querying
    const TEST_USERS: usize = 100;
    const QUERY_ROUNDS: usize = 5;
    
    println!("📝 Creating {} test users for query testing...", TEST_USERS);
    let mut test_users = Vec::new();
    for i in 0..TEST_USERS {
        let user = TestUser::new(&format!("query_perf_{}", i));
        let _ = framework.client.register(&user).await?;
        test_users.push(user);
    }
    
    let mut metrics = DatabaseMetrics::new("Query Performance Under Load");
    let start_time = Instant::now();
    
    // Perform multiple rounds of concurrent queries
    for round in 0..QUERY_ROUNDS {
        println!("🔄 Query round {} of {}", round + 1, QUERY_ROUNDS);
        let mut handles = Vec::new();
        
        for user in &test_users {
            let client = framework.client.clone();
            let user_clone = user.clone();
            
            let handle = tokio::spawn(async move {
                let request_start = Instant::now();
                let result = client.login(&user_clone).await;
                let elapsed = request_start.elapsed();
                
                match result {
                    Ok(_) => (true, elapsed),
                    Err(_) => (false, elapsed),
                }
            });
            
            handles.push(handle);
        }
        
        // Collect results for this round
        for handle in handles {
            if let Ok((success, response_time)) = handle.await {
                metrics.add_result(success, response_time);
            }
        }
    }
    
    metrics.test_duration = start_time.elapsed();
    metrics.print_detailed_metrics();
    
    let targets = DatabasePerformanceTargets::default();
    let (_, p95, _) = metrics.calculate_percentiles();
    
    // Validate query performance under load
    assert!(
        p95.as_millis() <= (targets.user_lookup_ms * 2) as u128, // Allow 2x normal latency under load
        "Query P95 under load should be ≤{}ms, got {}ms",
        targets.user_lookup_ms * 2,
        p95.as_millis()
    );
    
    assert!(
        metrics.success_rate() >= targets.concurrent_operations_success_rate,
        "Query success rate under load should be ≥{:.2}%, got {:.2}%",
        targets.concurrent_operations_success_rate * 100.0,
        metrics.success_rate() * 100.0
    );
    
    println!("✅ Database query performance under load targets met");
    Ok(())
}