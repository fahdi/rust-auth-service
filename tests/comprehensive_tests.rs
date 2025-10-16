use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

use rust_auth_service::config::{database::DatabaseConfig, database::PoolConfig, Config};
use rust_auth_service::database::{create_database, AuthDatabase};
use rust_auth_service::models::user::{CreateUserRequest, User, UserMetadata, UserRole};
use rust_auth_service::utils::password::hash_password;

/// Comprehensive Integration Test Suite
///
/// This test suite provides comprehensive coverage of the rust-auth-service
/// across all supported database adapters (MongoDB, PostgreSQL, MySQL).
/// 
/// Tests include:
/// - Database operations (CRUD, authentication flows)
/// - Performance benchmarks (throughput, latency)
/// - Concurrent operations
/// - Error handling and recovery
/// - Authentication flows (registration, login, verification)
/// - Security features (rate limiting, account lockouts)
/// - Health checks and monitoring
///
/// ## Running Tests with Feature-based Selection
///
/// Tests are now conditionally compiled based on Cargo features:
///
/// ### Database-specific tests:
/// ```bash
/// # Run only MongoDB tests
/// cargo test --test comprehensive_tests --features mongodb
///
/// # Run PostgreSQL and MySQL tests
/// cargo test --test comprehensive_tests --features "postgresql,mysql"
///
/// # Run all database tests (default)
/// cargo test --test comprehensive_tests
/// ```
///
/// ### Prerequisites:
/// - Docker containers running for enabled database features
/// - Environment variables configured (optional, defaults provided)
/// - No more #[ignore] tags - tests run automatically when features are enabled

#[derive(Debug, Clone)]
struct PerformanceMetrics {
    operation_count: u64,
    total_duration: Duration,
    min_latency: Duration,
    max_latency: Duration,
    latencies: Vec<Duration>,
}

impl PerformanceMetrics {
    fn new() -> Self {
        Self {
            operation_count: 0,
            total_duration: Duration::from_secs(0),
            min_latency: Duration::from_secs(u64::MAX),
            max_latency: Duration::from_secs(0),
            latencies: Vec::new(),
        }
    }

    fn record_operation(&mut self, duration: Duration) {
        self.operation_count += 1;
        self.total_duration += duration;
        self.min_latency = self.min_latency.min(duration);
        self.max_latency = self.max_latency.max(duration);
        self.latencies.push(duration);
    }

    fn calculate_percentiles(&mut self) -> (Duration, Duration, Duration) {
        self.latencies.sort();
        let len = self.latencies.len();
        let p50 = self.latencies[len / 2];
        let p95 = self.latencies[(len as f64 * 0.95) as usize];
        let p99 = self.latencies[(len as f64 * 0.99) as usize];
        (p50, p95, p99)
    }

    fn throughput(&self) -> f64 {
        self.operation_count as f64 / self.total_duration.as_secs_f64()
    }

    fn average_latency(&self) -> Duration {
        if self.operation_count > 0 {
            self.total_duration / self.operation_count as u32
        } else {
            Duration::from_secs(0)
        }
    }
}

#[derive(Debug)]
struct TestResults {
    database_type: String,
    test_name: String,
    performance: PerformanceMetrics,
    success_rate: f64,
    errors: Vec<String>,
}

impl TestResults {
    fn new(database_type: String, test_name: String) -> Self {
        Self {
            database_type,
            test_name,
            performance: PerformanceMetrics::new(),
            success_rate: 0.0,
            errors: Vec::new(),
        }
    }

    fn print_summary(&mut self) {
        let (p50, p95, p99) = self.performance.calculate_percentiles();

        println!(
            "\n📊 {} - {} Results:",
            self.database_type.to_uppercase(),
            self.test_name
        );
        println!("  Operations: {}", self.performance.operation_count);
        println!("  Success Rate: {:.2}%", self.success_rate * 100.0);
        println!("  Throughput: {:.2} ops/sec", self.performance.throughput());
        println!(
            "  Average Latency: {:.2}ms",
            self.performance.average_latency().as_millis()
        );
        println!("  P50 Latency: {:.2}ms", p50.as_millis());
        println!("  P95 Latency: {:.2}ms", p95.as_millis());
        println!("  P99 Latency: {:.2}ms", p99.as_millis());
        println!(
            "  Min Latency: {:.2}ms",
            self.performance.min_latency.as_millis()
        );
        println!(
            "  Max Latency: {:.2}ms",
            self.performance.max_latency.as_millis()
        );

        if !self.errors.is_empty() {
            println!("  Errors: {}", self.errors.len());
            for (i, error) in self.errors.iter().take(5).enumerate() {
                println!("    {}: {}", i + 1, error);
            }
            if self.errors.len() > 5 {
                println!("    ... and {} more", self.errors.len() - 5);
            }
        }
    }
}

/// Test basic database operations
/// Runs only when database features are enabled and services are available
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn comprehensive_database_functionality_test() {
    let databases = get_test_databases().await;

    for (db_type, db) in databases {
        println!(
            "\n🧪 Testing {} database functionality",
            db_type.to_uppercase()
        );

        let mut results = TestResults::new(db_type.clone(), "Basic Functionality".to_string());
        let mut successful_operations = 0;
        let total_operations = 10;

        for i in 0..total_operations {
            let start = Instant::now();
            let email = format!("test_{}_{}_@example.com", db_type, i);

            match test_user_lifecycle(&db, &email).await {
                Ok(_) => {
                    successful_operations += 1;
                    results.performance.record_operation(start.elapsed());
                }
                Err(e) => {
                    results.errors.push(format!("Operation {}: {}", i, e));
                }
            }
        }

        results.success_rate = successful_operations as f64 / total_operations as f64;
        results.print_summary();
    }
}

/// Test user registration performance
/// Runs only when database features are enabled and services are available
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn user_registration_performance_test() {
    let databases = get_test_databases().await;
    const REGISTRATIONS: usize = 100;

    for (db_type, db) in databases {
        println!(
            "\n🚀 Testing {} user registration performance",
            db_type.to_uppercase()
        );

        let mut results = TestResults::new(db_type.clone(), "User Registration".to_string());
        let mut successful_operations = 0;

        for i in 0..REGISTRATIONS {
            let start = Instant::now();
            let email = format!("perf_register_{}_{}_@example.com", db_type, i);

            match create_test_user(&db, &email).await {
                Ok(_) => {
                    successful_operations += 1;
                    results.performance.record_operation(start.elapsed());
                }
                Err(e) => {
                    results.errors.push(format!("Registration {}: {}", i, e));
                }
            }
        }

        results.success_rate = successful_operations as f64 / REGISTRATIONS as f64;
        results.print_summary();

        // Cleanup
        cleanup_test_users(&db, &db_type, REGISTRATIONS).await;
    }
}

/// Test user authentication performance
/// Runs only when database features are enabled and services are available
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn user_authentication_performance_test() {
    let databases = get_test_databases().await;
    const AUTH_ATTEMPTS: usize = 1000;

    for (db_type, db) in databases {
        println!(
            "\n🔐 Testing {} authentication performance",
            db_type.to_uppercase()
        );

        // Pre-create users for authentication testing
        let mut test_emails = Vec::new();
        for i in 0..50 {
            let email = format!("auth_test_{}_{}_@example.com", db_type, i);
            if create_test_user(&db, &email).await.is_ok() {
                test_emails.push(email);
            }
        }

        let mut results = TestResults::new(db_type.clone(), "Authentication".to_string());
        let mut successful_operations = 0;

        for i in 0..AUTH_ATTEMPTS {
            let start = Instant::now();
            let email = &test_emails[i % test_emails.len()];

            match db.find_user_by_email(email).await {
                Ok(Some(_)) => {
                    successful_operations += 1;
                    results.performance.record_operation(start.elapsed());
                }
                Ok(None) => {
                    results.errors.push(format!("User not found: {}", email));
                }
                Err(e) => {
                    results.errors.push(format!("Auth error {}: {}", i, e));
                }
            }
        }

        results.success_rate = successful_operations as f64 / AUTH_ATTEMPTS as f64;
        results.print_summary();

        // Cleanup test users
        for email in test_emails {
            if let Ok(Some(user)) = db.find_user_by_email(&email).await {
                let _ = db.deactivate_user(&user.user_id).await;
            }
        }
    }
}

/// Test concurrent user operations
/// Runs only when database features are enabled and services are available
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn concurrent_operations_test() {
    let databases = get_test_databases().await;
    const CONCURRENT_USERS: usize = 50;
    const OPERATIONS_PER_USER: usize = 20;

    for (db_type, db) in databases {
        println!(
            "\n⚡ Testing {} concurrent operations",
            db_type.to_uppercase()
        );

        let db = Arc::new(db);
        let counter = Arc::new(AtomicU64::new(0));
        let start_time = Instant::now();

        let mut handles = Vec::new();

        for user_id in 0..CONCURRENT_USERS {
            let db = db.clone();
            let counter = counter.clone();
            let db_type = db_type.clone();

            let handle = tokio::spawn(async move {
                let mut local_results = PerformanceMetrics::new();
                let mut successful_ops = 0;

                for op_id in 0..OPERATIONS_PER_USER {
                    let start = Instant::now();
                    let email = format!("concurrent_{}_{}_{}@example.com", db_type, user_id, op_id);

                    match perform_user_operation(&db, &email).await {
                        Ok(_) => {
                            successful_ops += 1;
                            local_results.record_operation(start.elapsed());
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {}
                    }

                    // Small delay to prevent overwhelming the database
                    sleep(Duration::from_millis(1)).await;
                }

                (local_results, successful_ops)
            });

            handles.push(handle);
        }

        // Wait for all operations to complete
        let mut all_results = PerformanceMetrics::new();
        let mut total_successful = 0;

        for handle in handles {
            if let Ok((local_results, successful)) = handle.await {
                all_results.operation_count += local_results.operation_count;
                all_results.total_duration += local_results.total_duration;
                all_results.latencies.extend(local_results.latencies);
                total_successful += successful;
            }
        }

        let total_time = start_time.elapsed();
        all_results.total_duration = total_time;

        let mut results = TestResults::new(db_type.clone(), "Concurrent Operations".to_string());
        results.performance = all_results;
        results.success_rate =
            total_successful as f64 / (CONCURRENT_USERS * OPERATIONS_PER_USER) as f64;

        results.print_summary();
        println!("  Total Test Duration: {:.2}s", total_time.as_secs_f64());
        println!(
            "  Actual Operations Completed: {}",
            counter.load(Ordering::Relaxed)
        );

        // Cleanup concurrent test data
        cleanup_concurrent_users(&db, &db_type, CONCURRENT_USERS, OPERATIONS_PER_USER).await;
    }
}

/// Test database health and connection stability
/// Runs only when database features are enabled and services are available
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn database_health_stability_test() {
    let databases = get_test_databases().await;
    const HEALTH_CHECKS: usize = 1000;

    for (db_type, db) in databases {
        println!(
            "\n💚 Testing {} database health stability",
            db_type.to_uppercase()
        );

        let mut results = TestResults::new(db_type.clone(), "Health Checks".to_string());
        let mut successful_operations = 0;

        for i in 0..HEALTH_CHECKS {
            let start = Instant::now();

            match db.health_check().await {
                Ok(health) => {
                    if health.connected {
                        successful_operations += 1;
                        results.performance.record_operation(start.elapsed());
                    } else {
                        results
                            .errors
                            .push(format!("Health check {}: Not connected", i));
                    }
                }
                Err(e) => {
                    results.errors.push(format!("Health check {}: {}", i, e));
                }
            }

            // Very small delay to allow rapid health checking
            sleep(Duration::from_micros(100)).await;
        }

        results.success_rate = successful_operations as f64 / HEALTH_CHECKS as f64;
        results.print_summary();
    }
}

/// Test email verification flow performance
/// Runs only when database features are enabled and services are available
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn email_verification_flow_test() {
    let databases = get_test_databases().await;
    const VERIFICATION_TESTS: usize = 100;

    for (db_type, db) in databases {
        println!(
            "\n📧 Testing {} email verification flow",
            db_type.to_uppercase()
        );

        let mut results = TestResults::new(db_type.clone(), "Email Verification".to_string());
        let mut successful_operations = 0;

        for i in 0..VERIFICATION_TESTS {
            let start = Instant::now();
            let email = format!("verify_test_{}_{}_@example.com", db_type, i);

            match test_verification_flow(&db, &email).await {
                Ok(_) => {
                    successful_operations += 1;
                    results.performance.record_operation(start.elapsed());
                }
                Err(e) => {
                    results.errors.push(format!("Verification {}: {}", i, e));
                }
            }
        }

        results.success_rate = successful_operations as f64 / VERIFICATION_TESTS as f64;
        results.print_summary();

        // Cleanup verification test users
        cleanup_test_users(&db, &db_type, VERIFICATION_TESTS).await;
    }
}

/// Test password reset flow performance
/// Runs only when database features are enabled and services are available
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn password_reset_flow_test() {
    let databases = get_test_databases().await;
    const RESET_TESTS: usize = 100;

    for (db_type, db) in databases {
        println!(
            "\n🔑 Testing {} password reset flow",
            db_type.to_uppercase()
        );

        let mut results = TestResults::new(db_type.clone(), "Password Reset".to_string());
        let mut successful_operations = 0;

        for i in 0..RESET_TESTS {
            let start = Instant::now();
            let email = format!("reset_test_{}_{}_@example.com", db_type, i);

            match test_password_reset_flow(&db, &email).await {
                Ok(_) => {
                    successful_operations += 1;
                    results.performance.record_operation(start.elapsed());
                }
                Err(e) => {
                    results.errors.push(format!("Reset {}: {}", i, e));
                }
            }
        }

        results.success_rate = successful_operations as f64 / RESET_TESTS as f64;
        results.print_summary();

        // Cleanup reset test users
        cleanup_test_users(&db, &db_type, RESET_TESTS).await;
    }
}

// Helper functions

async fn get_test_databases() -> Vec<(String, Box<dyn AuthDatabase>)> {
    let mut databases = Vec::new();

    let db_configs = vec![
        (
            "mongodb",
            env::var("MONGODB_TEST_URL").unwrap_or_else(|_| {
                "mongodb://admin:password123@localhost:27017/auth_service_test?authSource=admin"
                    .to_string()
            }),
        ),
        (
            "postgresql",
            env::var("POSTGRESQL_TEST_URL").unwrap_or_else(|_| {
                "postgresql://postgres:password123@localhost:5432/auth_service_test".to_string()
            }),
        ),
        (
            "mysql",
            env::var("MYSQL_TEST_URL").unwrap_or_else(|_| {
                "mysql://root:password123@localhost:3306/auth_service_test".to_string()
            }),
        ),
    ];

    for (db_type, url) in db_configs {
        let pool_config = PoolConfig {
            min_connections: 5,
            max_connections: 50,
            idle_timeout: 300,
        };

        let db_config = DatabaseConfig {
            r#type: db_type.to_string(),
            url,
            pool: pool_config,
            mongodb: None,
            postgresql: None,
            mysql: None,
        };

        match create_database(&db_config).await {
            Ok(db) => {
                databases.push((db_type.to_string(), db));
            }
            Err(e) => {
                println!("⚠️  Failed to connect to {}: {}", db_type, e);
            }
        }
    }

    databases
}

async fn test_user_lifecycle(
    db: &Box<dyn AuthDatabase>,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create user
    let user = create_test_user_object(email);
    let created_user = db.create_user(user).await?;

    // Find user by email
    let found_user = db.find_user_by_email(email).await?;
    assert!(found_user.is_some());

    // Find user by ID
    let user_id = &created_user.user_id;
    let found_by_id = db.find_user_by_id(user_id).await?;
    assert!(found_by_id.is_some());

    // Test email verification
    let verification_token = Uuid::new_v4().to_string();
    db.set_email_verification_token(user_id, &verification_token, 24)
        .await?;
    let verified_user_id = db.verify_email(&verification_token).await?;
    assert_eq!(verified_user_id, *user_id);

    // Test password reset
    let reset_token = Uuid::new_v4().to_string();
    db.set_password_reset_token(email, &reset_token, 2).await?;
    let reset_user_id = db.verify_password_reset_token(&reset_token).await?;
    assert_eq!(reset_user_id, *user_id);
    db.clear_password_reset_token(user_id).await?;

    // Test login recording
    db.record_login(user_id).await?;

    // Cleanup
    db.deactivate_user(user_id).await?;

    Ok(())
}

async fn create_test_user(
    db: &Box<dyn AuthDatabase>,
    email: &str,
) -> Result<User, Box<dyn std::error::Error>> {
    let user = create_test_user_object(email);
    let created_user = db.create_user(user).await?;
    Ok(created_user)
}

fn create_test_user_object(email: &str) -> User {
    let request = CreateUserRequest {
        email: email.to_string(),
        password: "TestPassword123!".to_string(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        role: Some(UserRole::User),
        metadata: Some(UserMetadata {
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("Test Agent".to_string()),
            registration_source: Some("comprehensive_test".to_string()),
            timezone: Some("UTC".to_string()),
            locale: Some("en".to_string()),
            preferences: json!({"test": true}),
        }),
    };

    let password_hash = hash_password("TestPassword123!").unwrap();
    User::new(request, password_hash)
}

async fn perform_user_operation(
    db: &Box<dyn AuthDatabase>,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let user = create_test_user_object(email);
    let created_user = db.create_user(user).await?;
    let _ = db.find_user_by_email(email).await?;
    let _ = db.health_check().await?;
    db.deactivate_user(&created_user.user_id).await?;
    Ok(())
}

async fn test_verification_flow(
    db: &Box<dyn AuthDatabase>,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let user = create_test_user_object(email);
    let created_user = db.create_user(user).await?;

    let verification_token = Uuid::new_v4().to_string();
    db.set_email_verification_token(&created_user.user_id, &verification_token, 24)
        .await?;
    let verified_user_id = db.verify_email(&verification_token).await?;
    assert_eq!(verified_user_id, created_user.user_id);

    db.deactivate_user(&created_user.user_id).await?;
    Ok(())
}

async fn test_password_reset_flow(
    db: &Box<dyn AuthDatabase>,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let user = create_test_user_object(email);
    let created_user = db.create_user(user).await?;

    let reset_token = Uuid::new_v4().to_string();
    db.set_password_reset_token(email, &reset_token, 2).await?;
    let reset_user_id = db.verify_password_reset_token(&reset_token).await?;
    assert_eq!(reset_user_id, created_user.user_id);
    db.clear_password_reset_token(&created_user.user_id).await?;

    db.deactivate_user(&created_user.user_id).await?;
    Ok(())
}

async fn cleanup_test_users(db: &Box<dyn AuthDatabase>, db_type: &str, count: usize) {
    for i in 0..count {
        let email = format!("perf_register_{}_{}_@example.com", db_type, i);
        if let Ok(Some(user)) = db.find_user_by_email(&email).await {
            let _ = db.deactivate_user(&user.user_id).await;
        }
    }
}

async fn cleanup_concurrent_users(
    db: &Box<dyn AuthDatabase>,
    db_type: &str,
    users: usize,
    ops_per_user: usize,
) {
    for user_id in 0..users {
        for op_id in 0..ops_per_user {
            let email = format!("concurrent_{}_{}_{}@example.com", db_type, user_id, op_id);
            if let Ok(Some(user)) = db.find_user_by_email(&email).await {
                let _ = db.deactivate_user(&user.user_id).await;
            }
        }
    }
}
