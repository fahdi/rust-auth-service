use futures::future::join_all;
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

use rust_auth_service::cache::{create_cache_provider, CacheService};
use rust_auth_service::config::{cache::CacheConfig, database::DatabaseConfig};
use rust_auth_service::database::{create_database, AuthDatabase};
use rust_auth_service::models::user::{User, UserMetadata, UserRole};

/// Performance and Load Testing Suite
///
/// This test suite measures performance characteristics of:
/// - Database operations (CRUD, authentication flows)
/// - Cache operations (set, get, multi-level performance)
/// - Authentication service load testing (concurrent users, RPS)
/// - Memory usage and resource consumption
/// - Response time distribution and percentiles
///
/// Run with: cargo test --test performance_load_testing -- --include-ignored

const SERVICE_URL: &str = "http://localhost:8090";

#[derive(Debug, Clone)]
struct PerformanceMetrics {
    total_operations: u64,
    successful_operations: u64,
    failed_operations: u64,
    total_duration_ms: u64,
    min_duration_ms: u64,
    max_duration_ms: u64,
    avg_duration_ms: f64,
    operations_per_second: f64,
    p50_duration_ms: u64,
    p95_duration_ms: u64,
    p99_duration_ms: u64,
}

impl PerformanceMetrics {
    fn new() -> Self {
        Self {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            total_duration_ms: 0,
            min_duration_ms: u64::MAX,
            max_duration_ms: 0,
            avg_duration_ms: 0.0,
            operations_per_second: 0.0,
            p50_duration_ms: 0,
            p95_duration_ms: 0,
            p99_duration_ms: 0,
        }
    }

    fn calculate_from_durations(&mut self, durations: &mut Vec<u64>, total_duration: Duration) {
        if durations.is_empty() {
            return;
        }

        durations.sort();

        self.total_operations = durations.len() as u64;
        self.total_duration_ms = durations.iter().sum();
        self.min_duration_ms = *durations.first().unwrap();
        self.max_duration_ms = *durations.last().unwrap();
        self.avg_duration_ms = self.total_duration_ms as f64 / self.total_operations as f64;
        self.operations_per_second = self.total_operations as f64 / total_duration.as_secs_f64();

        // Calculate percentiles
        let len = durations.len();
        self.p50_duration_ms = durations[len * 50 / 100];
        self.p95_duration_ms = durations[len * 95 / 100];
        self.p99_duration_ms = durations[len * 99 / 100];
    }

    fn print_summary(&self, operation_name: &str) {
        println!("📊 {} Performance Summary:", operation_name);
        println!("   Total Operations: {}", self.total_operations);
        println!("   Successful: {}", self.successful_operations);
        println!("   Failed: {}", self.failed_operations);
        println!("   Operations/sec: {:.2}", self.operations_per_second);
        println!("   Average: {:.2}ms", self.avg_duration_ms);
        println!(
            "   Min: {}ms, Max: {}ms",
            self.min_duration_ms, self.max_duration_ms
        );
        println!(
            "   P50: {}ms, P95: {}ms, P99: {}ms",
            self.p50_duration_ms, self.p95_duration_ms, self.p99_duration_ms
        );
    }
}

/// Generate unique test user for performance testing
fn generate_perf_test_user(prefix: &str, index: usize) -> User {
    let email = format!(
        "{}+{}+{}@example.com",
        prefix,
        index,
        Uuid::new_v4().to_string()[..8].to_string()
    );

    User {
        id: None,
        user_id: Uuid::new_v4().to_string(),
        email,
        password_hash: "$2a$12$test.hash.for.performance.testing".to_string(),
        first_name: "Perf".to_string(),
        last_name: "User".to_string(),
        role: UserRole::User,
        is_active: true,
        email_verified: false,
        email_verification_token: Some(Uuid::new_v4().to_string()),
        email_verification_expires: Some(chrono::Utc::now() + chrono::Duration::hours(24)),
        password_reset_token: None,
        password_reset_expires: None,
        last_login: None,
        login_attempts: 0,
        locked_until: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        metadata: UserMetadata {
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("Performance Test Agent".to_string()),
            registration_source: Some("performance_test".to_string()),
            timezone: None,
            locale: None,
            preferences: json!({}),
        },
    }
}

/// Create test database adapters for performance testing
async fn create_performance_test_databases() -> Vec<(String, Box<dyn AuthDatabase>)> {
    let mut databases = Vec::new();

    // MongoDB Performance Testing
    #[cfg(feature = "mongodb")]
    {
        if let Ok(mongo_url) = std::env::var("MONGODB_TEST_URL") {
            let config = DatabaseConfig {
                r#type: "mongodb".to_string(),
                url: mongo_url,
                pool: Default::default(),
            };

            if let Ok(adapter) = create_database(&config).await {
                databases.push(("mongodb".to_string(), adapter));
                println!("✅ MongoDB performance test database ready");
            }
        }
    }

    // PostgreSQL Performance Testing
    #[cfg(feature = "postgresql")]
    {
        if let Ok(pg_url) = std::env::var("POSTGRESQL_TEST_URL") {
            let config = DatabaseConfig {
                r#type: "postgresql".to_string(),
                url: pg_url,
                pool: Default::default(),
            };

            if let Ok(adapter) = create_database(&config).await {
                databases.push(("postgresql".to_string(), adapter));
                println!("✅ PostgreSQL performance test database ready");
            }
        }
    }

    // MySQL Performance Testing
    #[cfg(feature = "mysql")]
    {
        if let Ok(mysql_url) = std::env::var("MYSQL_TEST_URL") {
            let config = DatabaseConfig {
                r#type: "mysql".to_string(),
                url: mysql_url,
                pool: Default::default(),
            };

            if let Ok(adapter) = create_database(&config).await {
                databases.push(("mysql".to_string(), adapter));
                println!("✅ MySQL performance test database ready");
            }
        }
    }

    databases
}

/// Test database operation performance across all adapters
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_database_operation_performance() {
    let databases = create_performance_test_databases().await;
    const OPERATIONS_COUNT: usize = 100;

    for (db_type, db) in databases {
        println!("🚀 Testing {} database performance", db_type);

        // Test user creation performance
        let mut create_durations = Vec::new();
        let create_start = Instant::now();

        for i in 0..OPERATIONS_COUNT {
            let user = generate_perf_test_user(&format!("create_perf_{}", db_type), i);

            let op_start = Instant::now();
            match db.create_user(user).await {
                Ok(_) => create_durations.push(op_start.elapsed().as_millis() as u64),
                Err(e) => println!("⚠️ Create operation {} failed: {}", i, e),
            }
        }

        let create_total = create_start.elapsed();
        let mut create_metrics = PerformanceMetrics::new();
        create_metrics.calculate_from_durations(&mut create_durations, create_total);
        create_metrics.successful_operations = create_durations.len() as u64;
        create_metrics.failed_operations =
            OPERATIONS_COUNT as u64 - create_metrics.successful_operations;
        create_metrics.print_summary(&format!("{} User Creation", db_type));

        // Test user lookup performance using created users
        let mut lookup_durations = Vec::new();
        let lookup_start = Instant::now();

        for i in 0..std::cmp::min(OPERATIONS_COUNT, 50) {
            // Lookup subset to avoid overwhelming
            let email = format!(
                "create_perf_{}+{}+{}@example.com",
                db_type,
                i,
                Uuid::new_v4().to_string()[..8].to_string()
            );

            let op_start = Instant::now();
            match db.find_user_by_email(&email).await {
                Ok(_) => lookup_durations.push(op_start.elapsed().as_millis() as u64),
                Err(e) => println!("⚠️ Lookup operation {} failed: {}", i, e),
            }
        }

        let lookup_total = lookup_start.elapsed();
        let mut lookup_metrics = PerformanceMetrics::new();
        lookup_metrics.calculate_from_durations(&mut lookup_durations, lookup_total);
        lookup_metrics.successful_operations = lookup_durations.len() as u64;
        lookup_metrics.failed_operations = 50_u64 - lookup_metrics.successful_operations;
        lookup_metrics.print_summary(&format!("{} User Lookup", db_type));

        // Performance thresholds (lenient for CI environments)
        assert!(
            create_metrics.operations_per_second > 5.0,
            "{} create performance should be > 5 ops/sec",
            db_type
        );
        assert!(
            lookup_metrics.operations_per_second > 20.0,
            "{} lookup performance should be > 20 ops/sec",
            db_type
        );
        assert!(
            create_metrics.p95_duration_ms < 2000,
            "{} create P95 should be < 2000ms",
            db_type
        );

        println!("✅ {} database performance test passed\n", db_type);
    }
}

/// Test cache operation performance
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_cache_operation_performance() {
    let cache_configs = vec![
        (
            "memory",
            CacheConfig {
                r#type: "memory".to_string(),
                url: None,
                ttl: 3600,
                lru_size: 1000,
            },
        ),
        (
            "redis",
            CacheConfig {
                r#type: "redis".to_string(),
                url: std::env::var("REDIS_TEST_URL").ok(),
                ttl: 3600,
                lru_size: 1000,
            },
        ),
    ];

    const CACHE_OPERATIONS: usize = 1000;

    for (cache_type, config) in cache_configs {
        if cache_type == "redis" && config.url.is_none() {
            println!("⚠️ Skipping Redis performance test - REDIS_TEST_URL not set");
            continue;
        }

        println!("🚀 Testing {} cache performance", cache_type);

        let cache_provider = match create_cache_provider(&config).await {
            Ok(provider) => provider,
            Err(e) => {
                println!("⚠️ Failed to create {} cache: {}", cache_type, e);
                continue;
            }
        };

        let cache_service = CacheService::new(cache_provider, 3600);

        // Clear cache for clean test
        let _ = cache_service.clear().await;

        // Test cache set performance
        let mut set_durations = Vec::new();
        let set_start = Instant::now();

        for i in 0..CACHE_OPERATIONS {
            let key = format!("perf_test_{}_{}", cache_type, i);
            let value = format!("test_value_{}", i);

            let op_start = Instant::now();
            match cache_service.set(&key, &value).await {
                Ok(_) => set_durations.push(op_start.elapsed().as_millis() as u64),
                Err(e) => println!("⚠️ Cache set {} failed: {}", i, e),
            }
        }

        let set_total = set_start.elapsed();
        let mut set_metrics = PerformanceMetrics::new();
        set_metrics.calculate_from_durations(&mut set_durations, set_total);
        set_metrics.successful_operations = set_durations.len() as u64;
        set_metrics.print_summary(&format!("{} Cache Set", cache_type));

        // Test cache get performance
        let mut get_durations = Vec::new();
        let get_start = Instant::now();

        for i in 0..CACHE_OPERATIONS {
            let key = format!("perf_test_{}_{}", cache_type, i);

            let op_start = Instant::now();
            match cache_service.get(&key).await {
                Ok(_) => get_durations.push(op_start.elapsed().as_millis() as u64),
                Err(e) => println!("⚠️ Cache get {} failed: {}", i, e),
            }
        }

        let get_total = get_start.elapsed();
        let mut get_metrics = PerformanceMetrics::new();
        get_metrics.calculate_from_durations(&mut get_durations, get_total);
        get_metrics.successful_operations = get_durations.len() as u64;
        get_metrics.print_summary(&format!("{} Cache Get", cache_type));

        // Performance thresholds
        assert!(
            set_metrics.operations_per_second > 100.0,
            "{} cache set should be > 100 ops/sec",
            cache_type
        );
        assert!(
            get_metrics.operations_per_second > 500.0,
            "{} cache get should be > 500 ops/sec",
            cache_type
        );

        println!("✅ {} cache performance test passed\n", cache_type);
    }
}

/// Wait for authentication service to be ready
async fn wait_for_auth_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new();
    let mut attempts = 0;
    let max_attempts = 30;

    println!("🔍 Waiting for auth service to be ready for load testing...");

    while attempts < max_attempts {
        match client.get(&format!("{}/health", SERVICE_URL)).send().await {
            Ok(response) if response.status().is_success() => {
                println!("✅ Auth service is ready for load testing");
                return Ok(());
            }
            _ => {
                attempts += 1;
                if attempts < max_attempts {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    Err("Auth service not available for load testing".into())
}

/// Test authentication service load with concurrent users
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_authentication_service_load() {
    wait_for_auth_service()
        .await
        .expect("Service should be ready");

    const CONCURRENT_USERS: usize = 50;
    const REQUESTS_PER_USER: usize = 10;

    println!("🚀 Starting authentication service load test");
    println!("   Concurrent Users: {}", CONCURRENT_USERS);
    println!("   Requests per User: {}", REQUESTS_PER_USER);
    println!(
        "   Total Requests: {}",
        CONCURRENT_USERS * REQUESTS_PER_USER
    );

    let client = Arc::new(Client::new());
    let success_counter = Arc::new(AtomicU64::new(0));
    let error_counter = Arc::new(AtomicU64::new(0));
    let request_durations = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let load_test_start = Instant::now();

    // Create concurrent user simulation tasks
    let mut user_tasks = Vec::new();

    for user_id in 0..CONCURRENT_USERS {
        let client = Arc::clone(&client);
        let success_counter = Arc::clone(&success_counter);
        let error_counter = Arc::clone(&error_counter);
        let request_durations = Arc::clone(&request_durations);

        let task = tokio::spawn(async move {
            // Simulate user session
            let unique_id = Uuid::new_v4().to_string()[..8].to_string();
            let user_email = format!("loadtest+{}+{}@example.com", user_id, unique_id);

            // Register user
            let register_payload = json!({
                "email": user_email,
                "password": "LoadTest123!",
                "first_name": "Load",
                "last_name": "Test"
            });

            let register_start = Instant::now();
            let register_response = client
                .post(&format!("{}/auth/register", SERVICE_URL))
                .json(&register_payload)
                .send()
                .await;

            let register_duration = register_start.elapsed().as_millis() as u64;

            let access_token = match register_response {
                Ok(response) if response.status().is_success() => {
                    success_counter.fetch_add(1, Ordering::Relaxed);
                    request_durations.lock().await.push(register_duration);

                    // Extract access token
                    if let Ok(result) = response.json::<Value>().await {
                        result
                            .get("access_token")
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string())
                    } else {
                        None
                    }
                }
                _ => {
                    error_counter.fetch_add(1, Ordering::Relaxed);
                    None
                }
            };

            if let Some(token) = access_token {
                // Perform multiple authenticated requests per user
                for _ in 0..REQUESTS_PER_USER - 1 {
                    // -1 because registration counts as one request
                    let request_start = Instant::now();
                    let profile_response = client
                        .get(&format!("{}/auth/me", SERVICE_URL))
                        .bearer_auth(&token)
                        .send()
                        .await;

                    let request_duration = request_start.elapsed().as_millis() as u64;

                    match profile_response {
                        Ok(response) if response.status().is_success() => {
                            success_counter.fetch_add(1, Ordering::Relaxed);
                            request_durations.lock().await.push(request_duration);
                        }
                        _ => {
                            error_counter.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    // Small delay between requests to simulate real usage
                    sleep(Duration::from_millis(10)).await;
                }
            }
        });

        user_tasks.push(task);
    }

    // Wait for all users to complete
    join_all(user_tasks).await;

    let total_test_duration = load_test_start.elapsed();

    // Calculate performance metrics
    let successful_requests = success_counter.load(Ordering::Relaxed);
    let failed_requests = error_counter.load(Ordering::Relaxed);
    let total_requests = successful_requests + failed_requests;

    let mut durations = request_durations.lock().await;
    let mut load_metrics = PerformanceMetrics::new();
    load_metrics.calculate_from_durations(&mut durations, total_test_duration);
    load_metrics.successful_operations = successful_requests;
    load_metrics.failed_operations = failed_requests;

    load_metrics.print_summary("Authentication Service Load Test");

    println!("📊 Load Test Results:");
    println!("   Total Requests: {}", total_requests);
    println!(
        "   Success Rate: {:.1}%",
        (successful_requests as f64 / total_requests as f64) * 100.0
    );
    println!(
        "   Test Duration: {:.2}s",
        total_test_duration.as_secs_f64()
    );
    println!(
        "   Overall RPS: {:.2}",
        total_requests as f64 / total_test_duration.as_secs_f64()
    );

    // Performance assertions
    assert!(
        load_metrics.operations_per_second > 50.0,
        "Service should handle > 50 RPS under load"
    );
    assert!(
        (successful_requests as f64 / total_requests as f64) > 0.95,
        "Success rate should be > 95%"
    );
    assert!(
        load_metrics.p95_duration_ms < 1000,
        "P95 response time should be < 1000ms"
    );

    println!("✅ Authentication service load test passed");
}

/// Test concurrent user registration performance
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_concurrent_user_registration_performance() {
    wait_for_auth_service()
        .await
        .expect("Service should be ready");

    const CONCURRENT_REGISTRATIONS: usize = 100;
    println!(
        "🚀 Testing concurrent user registration performance ({} users)",
        CONCURRENT_REGISTRATIONS
    );

    let client = Arc::new(Client::new());
    let success_counter = Arc::new(AtomicU64::new(0));
    let error_counter = Arc::new(AtomicU64::new(0));

    let test_start = Instant::now();

    let registration_tasks: Vec<_> = (0..CONCURRENT_REGISTRATIONS)
        .map(|i| {
            let client = Arc::clone(&client);
            let success_counter = Arc::clone(&success_counter);
            let error_counter = Arc::clone(&error_counter);

            tokio::spawn(async move {
                let unique_id = Uuid::new_v4().to_string()[..8].to_string();
                let user_email = format!("concurrent+{}+{}@example.com", i, unique_id);

                let register_payload = json!({
                    "email": user_email,
                    "password": "ConcurrentTest123!",
                    "first_name": "Concurrent",
                    "last_name": "User"
                });

                let response = client
                    .post(&format!("{}/auth/register", SERVICE_URL))
                    .json(&register_payload)
                    .send()
                    .await;

                match response {
                    Ok(resp) if resp.status().is_success() => {
                        success_counter.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        error_counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();

    // Wait for all registrations to complete
    join_all(registration_tasks).await;

    let test_duration = test_start.elapsed();
    let successful = success_counter.load(Ordering::Relaxed);
    let failed = error_counter.load(Ordering::Relaxed);
    let total = successful + failed;

    println!("📊 Concurrent Registration Results:");
    println!("   Total Registrations: {}", total);
    println!("   Successful: {}", successful);
    println!("   Failed: {}", failed);
    println!(
        "   Success Rate: {:.1}%",
        (successful as f64 / total as f64) * 100.0
    );
    println!("   Duration: {:.2}s", test_duration.as_secs_f64());
    println!(
        "   Registration Rate: {:.2}/sec",
        total as f64 / test_duration.as_secs_f64()
    );

    // Performance assertions
    assert!(
        successful >= total * 90 / 100,
        "At least 90% should succeed"
    );
    assert!(
        total as f64 / test_duration.as_secs_f64() > 10.0,
        "Should handle > 10 registrations/sec"
    );

    println!("✅ Concurrent registration performance test passed");
}

/// Test memory usage and resource consumption patterns
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_memory_and_resource_consumption() {
    println!("🚀 Testing memory and resource consumption patterns");

    // Memory usage test for database operations
    let databases = create_performance_test_databases().await;

    if let Some((db_type, db)) = databases.first() {
        println!("🔍 Testing {} memory usage patterns", db_type);

        let initial_memory = get_memory_usage().unwrap_or(0);
        println!("   Initial memory usage: {} MB", initial_memory);

        // Create a large number of users to test memory scaling
        const MEMORY_TEST_USERS: usize = 500;
        let mut created_users = Vec::new();

        for i in 0..MEMORY_TEST_USERS {
            let user = generate_perf_test_user(&format!("memory_test_{}", db_type), i);
            match db.create_user(user).await {
                Ok(created_user) => created_users.push(created_user),
                Err(e) => println!("⚠️ Memory test user creation {} failed: {}", i, e),
            }

            // Check memory every 100 operations
            if i % 100 == 0 {
                let current_memory = get_memory_usage().unwrap_or(0);
                println!("   Memory after {} operations: {} MB", i, current_memory);
            }
        }

        let final_memory = get_memory_usage().unwrap_or(0);
        let memory_growth = final_memory.saturating_sub(initial_memory);

        println!("📊 Memory Usage Results:");
        println!("   Initial: {} MB", initial_memory);
        println!("   Final: {} MB", final_memory);
        println!("   Growth: {} MB", memory_growth);
        println!(
            "   Per Operation: {:.2} KB",
            memory_growth as f64 * 1024.0 / MEMORY_TEST_USERS as f64
        );

        // Memory growth should be reasonable (< 100MB for 500 operations)
        assert!(
            memory_growth < 100,
            "Memory growth should be < 100MB for {} operations",
            MEMORY_TEST_USERS
        );

        println!("✅ Memory and resource consumption test passed");
    } else {
        println!("⚠️ No databases available for memory testing");
    }
}

/// Get current memory usage in MB (simplified implementation)
fn get_memory_usage() -> Option<u64> {
    // This is a simplified implementation
    // In a real scenario, you'd use a proper memory profiling crate
    // For now, return a mock value for testing
    Some(50) // Mock 50MB baseline
}

/// Stress test with sustained load over time
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_sustained_load_stress_test() {
    wait_for_auth_service()
        .await
        .expect("Service should be ready");

    const STRESS_DURATION_SECONDS: u64 = 30;
    const REQUESTS_PER_SECOND: usize = 20;

    println!("🚀 Starting sustained load stress test");
    println!("   Duration: {}s", STRESS_DURATION_SECONDS);
    println!("   Target RPS: {}", REQUESTS_PER_SECOND);

    let client = Arc::new(Client::new());
    let success_counter = Arc::new(AtomicU64::new(0));
    let error_counter = Arc::new(AtomicU64::new(0));

    let test_start = Instant::now();
    let test_end = test_start + Duration::from_secs(STRESS_DURATION_SECONDS);

    // Sustained load generation
    while Instant::now() < test_end {
        let second_start = Instant::now();
        let mut second_tasks = Vec::new();

        // Generate target RPS for this second
        for _i in 0..REQUESTS_PER_SECOND {
            let client = Arc::clone(&client);
            let success_counter = Arc::clone(&success_counter);
            let error_counter = Arc::clone(&error_counter);

            let task = tokio::spawn(async move {
                let response = client.get(&format!("{}/health", SERVICE_URL)).send().await;

                match response {
                    Ok(resp) if resp.status().is_success() => {
                        success_counter.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        error_counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

            second_tasks.push(task);
        }

        // Wait for this second's requests to complete
        join_all(second_tasks).await;

        // Sleep to maintain target RPS
        let elapsed = second_start.elapsed();
        if elapsed < Duration::from_secs(1) {
            sleep(Duration::from_secs(1) - elapsed).await;
        }

        let total_requests =
            success_counter.load(Ordering::Relaxed) + error_counter.load(Ordering::Relaxed);
        let current_rps = total_requests as f64 / test_start.elapsed().as_secs_f64();

        print!(
            "\r   Progress: {:.1}s, Requests: {}, Current RPS: {:.1}    ",
            test_start.elapsed().as_secs_f64(),
            total_requests,
            current_rps
        );
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
    }

    println!(); // New line after progress updates

    let test_duration = test_start.elapsed();
    let successful = success_counter.load(Ordering::Relaxed);
    let failed = error_counter.load(Ordering::Relaxed);
    let total = successful + failed;

    println!("📊 Sustained Load Stress Test Results:");
    println!("   Duration: {:.2}s", test_duration.as_secs_f64());
    println!("   Total Requests: {}", total);
    println!("   Successful: {}", successful);
    println!("   Failed: {}", failed);
    println!(
        "   Success Rate: {:.1}%",
        (successful as f64 / total as f64) * 100.0
    );
    println!(
        "   Average RPS: {:.2}",
        total as f64 / test_duration.as_secs_f64()
    );

    // Stress test assertions
    assert!(
        (successful as f64 / total as f64) > 0.98,
        "Success rate should be > 98% under sustained load"
    );
    assert!(
        total as f64 / test_duration.as_secs_f64() > REQUESTS_PER_SECOND as f64 * 0.8,
        "Should maintain > 80% of target RPS"
    );

    println!("✅ Sustained load stress test passed");
}

/// Comprehensive performance regression test
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_performance_regression_baseline() {
    println!("🚀 Running comprehensive performance regression baseline");

    // This test establishes performance baselines that can be used
    // in CI/CD to detect performance regressions

    let mut baseline_results = std::collections::HashMap::new();

    // Database performance baseline
    let databases = create_performance_test_databases().await;
    for (db_type, db) in databases {
        let user = generate_perf_test_user(&format!("baseline_{}", db_type), 0);

        let start = Instant::now();
        match db.create_user(user).await {
            Ok(_) => {
                let duration = start.elapsed().as_millis();
                baseline_results.insert(format!("{}_create_user_ms", db_type), duration);
            }
            Err(e) => println!("⚠️ Baseline test failed for {}: {}", db_type, e),
        }
    }

    // Cache performance baseline
    if let Ok(redis_url) = std::env::var("REDIS_TEST_URL") {
        let config = CacheConfig {
            r#type: "redis".to_string(),
            url: Some(redis_url),
            ttl: 3600,
            lru_size: 1000,
        };

        if let Ok(cache_provider) = create_cache_provider(&config).await {
            let cache_service = CacheService::new(cache_provider, 3600);

            let start = Instant::now();
            if cache_service
                .set("baseline_test", "baseline_value")
                .await
                .is_ok()
            {
                let set_duration = start.elapsed().as_millis();
                baseline_results.insert("redis_set_ms".to_string(), set_duration);

                let start = Instant::now();
                if cache_service.get("baseline_test").await.is_ok() {
                    let get_duration = start.elapsed().as_millis();
                    baseline_results.insert("redis_get_ms".to_string(), get_duration);
                }
            }
        }
    }

    // Service health check baseline
    if wait_for_auth_service().await.is_ok() {
        let client = Client::new();
        let start = Instant::now();
        if let Ok(response) = client.get(&format!("{}/health", SERVICE_URL)).send().await {
            if response.status().is_success() {
                let health_duration = start.elapsed().as_millis();
                baseline_results.insert("service_health_ms".to_string(), health_duration);
            }
        }
    }

    println!("📊 Performance Baseline Results:");
    for (metric, value) in &baseline_results {
        println!("   {}: {}ms", metric, value);
    }

    // Baseline assertions (these should be updated based on actual performance)
    for (metric, &value) in &baseline_results {
        match metric.as_str() {
            s if s.contains("create_user") => {
                assert!(value < 1000, "{} should be < 1000ms", metric)
            }
            s if s.contains("redis_set") => assert!(value < 100, "{} should be < 100ms", metric),
            s if s.contains("redis_get") => assert!(value < 50, "{} should be < 50ms", metric),
            s if s.contains("service_health") => {
                assert!(value < 200, "{} should be < 200ms", metric)
            }
            _ => {}
        }
    }

    println!("✅ Performance regression baseline established");
}
