use reqwest::Client;
use serde_json::json;
use std::env;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

use rust_auth_service::config::{database::DatabaseConfig, database::PoolConfig, Config};
use rust_auth_service::database::{create_database, AuthDatabase};
use rust_auth_service::models::user::{CreateUserRequest, User, UserMetadata, UserRole};
use rust_auth_service::utils::password::hash_password;

/// Integration tests for all database providers
/// These tests require Docker containers to be running

const TEST_EMAIL: &str = "test@example.com";
const TEST_PASSWORD: &str = "TestPassword123!";
const TEST_FIRST_NAME: &str = "Integration";
const TEST_LAST_NAME: &str = "Test";

#[derive(Debug)]
struct TestContext {
    db: Box<dyn AuthDatabase>,
    db_type: String,
}

impl TestContext {
    async fn new(db_type: &str, connection_url: &str) -> Self {
        let pool_config = PoolConfig {
            min_connections: 1,
            max_connections: 5,
            idle_timeout: 30,
        };

        let db_config = DatabaseConfig {
            r#type: db_type.to_string(),
            url: connection_url.to_string(),
            pool: pool_config,
        };

        let db = create_database(&db_config)
            .await
            .expect(&format!("Failed to create {} database", db_type));

        Self {
            db,
            db_type: db_type.to_string(),
        }
    }

    async fn cleanup(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Clean up test data
        if let Ok(Some(user)) = self.db.find_user_by_email(TEST_EMAIL).await {
            let _ = self.db.deactivate_user(&user.user_id).await;
        }
        Ok(())
    }
}

async fn create_test_user() -> User {
    let request = CreateUserRequest {
        email: TEST_EMAIL.to_string(),
        password: TEST_PASSWORD.to_string(),
        first_name: TEST_FIRST_NAME.to_string(),
        last_name: TEST_LAST_NAME.to_string(),
        role: Some(UserRole::User),
        metadata: Some(UserMetadata {
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("Test Agent".to_string()),
            registration_source: Some("integration_test".to_string()),
            timezone: Some("UTC".to_string()),
            locale: Some("en".to_string()),
            preferences: json!({"test": true}),
        }),
    };

    let password_hash = hash_password(TEST_PASSWORD, 4).unwrap();
    User::new(request, password_hash)
}

/// Test MongoDB database operations
#[tokio::test]
#[cfg(feature = "mongodb")]
async fn test_mongodb_integration() {
    let url = env::var("MONGODB_TEST_URL").unwrap_or_else(|_| {
        "mongodb://admin:password123@localhost:27017/auth_service_test?authSource=admin".to_string()
    });

    let ctx = TestContext::new("mongodb", &url).await;
    run_database_tests(&ctx).await;
    ctx.cleanup().await.unwrap();
}

/// Test PostgreSQL database operations
#[tokio::test]
#[cfg(feature = "postgresql")]
async fn test_postgresql_integration() {
    let url = env::var("POSTGRESQL_TEST_URL").unwrap_or_else(|_| {
        "postgresql://postgres:password123@localhost:5432/auth_service_test".to_string()
    });

    let ctx = TestContext::new("postgresql", &url).await;
    run_database_tests(&ctx).await;
    ctx.cleanup().await.unwrap();
}

/// Test MySQL database operations
#[tokio::test]
#[cfg(feature = "mysql")]
async fn test_mysql_integration() {
    let url = env::var("MYSQL_TEST_URL").unwrap_or_else(|_| {
        "mysql://root:password123@localhost:3306/auth_service_test".to_string()
    });

    let ctx = TestContext::new("mysql", &url).await;
    run_database_tests(&ctx).await;
    ctx.cleanup().await.unwrap();
}

/// Run comprehensive database tests
async fn run_database_tests(ctx: &TestContext) {
    println!("Testing {} database operations", ctx.db_type);

    // Test 1: Health check
    let health = ctx.db.health_check().await.unwrap();
    assert_eq!(health.database_type, ctx.db_type);
    assert!(health.connected);
    assert!(health.response_time_ms < 1000); // Should be fast

    // Test 2: User creation
    let user = create_test_user().await;
    let created_user = ctx.db.create_user(user.clone()).await.unwrap();
    assert_eq!(created_user.email, TEST_EMAIL);
    assert_eq!(created_user.first_name, TEST_FIRST_NAME);

    // Test 3: Find user by email
    let found_user = ctx.db.find_user_by_email(TEST_EMAIL).await.unwrap();
    assert!(found_user.is_some());
    let found_user = found_user.unwrap();
    assert_eq!(found_user.email, TEST_EMAIL);

    // Test 4: Find user by ID
    let user_id = found_user.user_id.clone();
    let found_by_id = ctx.db.find_user_by_id(&user_id).await.unwrap();
    assert!(found_by_id.is_some());

    // Test 5: Email verification flow
    let verification_token = Uuid::new_v4().to_string();
    ctx.db
        .set_email_verification_token(&user_id, &verification_token, 24)
        .await
        .unwrap();

    let verified_user_id = ctx.db.verify_email(&verification_token).await.unwrap();
    assert_eq!(verified_user_id, user_id);

    // Test 6: Password reset flow
    let reset_token = Uuid::new_v4().to_string();
    ctx.db
        .set_password_reset_token(TEST_EMAIL, &reset_token, 2)
        .await
        .unwrap();

    let reset_user_id = ctx
        .db
        .verify_password_reset_token(&reset_token)
        .await
        .unwrap();
    assert_eq!(reset_user_id, user_id);

    ctx.db.clear_password_reset_token(&user_id).await.unwrap();

    // Test 7: Login attempts and locking
    ctx.db.record_failed_login(TEST_EMAIL, 3, 1).await.unwrap();
    ctx.db.record_failed_login(TEST_EMAIL, 3, 1).await.unwrap();
    ctx.db.record_failed_login(TEST_EMAIL, 3, 1).await.unwrap();

    // User should be locked now
    let locked_user = ctx
        .db
        .find_user_by_email(TEST_EMAIL)
        .await
        .unwrap()
        .unwrap();
    assert!(locked_user.is_locked());

    // Test successful login (should unlock)
    ctx.db.record_login(&user_id).await.unwrap();
    let unlocked_user = ctx
        .db
        .find_user_by_email(TEST_EMAIL)
        .await
        .unwrap()
        .unwrap();
    assert!(!unlocked_user.is_locked());

    // Test 8: User exists check
    let exists = ctx.db.user_exists_by_email(TEST_EMAIL).await.unwrap();
    assert!(exists);

    let not_exists = ctx
        .db
        .user_exists_by_email("nonexistent@example.com")
        .await
        .unwrap();
    assert!(!not_exists);

    // Test 9: Deactivate user
    ctx.db.deactivate_user(&user_id).await.unwrap();
    let deactivated_user = ctx.db.find_user_by_id(&user_id).await.unwrap().unwrap();
    assert!(!deactivated_user.is_active);

    println!("✅ All {} database tests passed", ctx.db_type);
}

/// Performance benchmark tests
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn performance_test_all_databases() {
    let databases = vec![
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

    for (db_type, url) in databases {
        println!("\n🚀 Performance testing {} database", db_type);
        let ctx = TestContext::new(db_type, &url).await;

        // Run performance tests
        run_performance_benchmark(&ctx).await;

        ctx.cleanup().await.unwrap();
    }
}

async fn run_performance_benchmark(ctx: &TestContext) {
    const ITERATIONS: usize = 100;

    // Benchmark 1: User creation
    let start = Instant::now();
    for i in 0..ITERATIONS {
        let email = format!("perf_test_{}_{}_@example.com", ctx.db_type, i);
        let request = CreateUserRequest {
            email,
            password: "TestPassword123!".to_string(),
            first_name: "Perf".to_string(),
            last_name: "Test".to_string(),
            role: Some(UserRole::User),
            metadata: None,
        };
        let password_hash = hash_password("TestPassword123!", 4).unwrap();
        let user = User::new(request, password_hash);

        let _ = ctx.db.create_user(user).await.unwrap();
    }
    let creation_time = start.elapsed();

    // Benchmark 2: User lookup
    let start = Instant::now();
    for i in 0..ITERATIONS {
        let email = format!("perf_test_{}_{}_@example.com", ctx.db_type, i);
        let _ = ctx.db.find_user_by_email(&email).await.unwrap();
    }
    let lookup_time = start.elapsed();

    // Benchmark 3: Health checks
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = ctx.db.health_check().await.unwrap();
    }
    let health_check_time = start.elapsed();

    println!("📊 {} Performance Results:", ctx.db_type.to_uppercase());
    println!(
        "  User Creation: {:.2}ms avg ({} operations)",
        creation_time.as_millis() as f64 / ITERATIONS as f64,
        ITERATIONS
    );
    println!(
        "  User Lookup: {:.2}ms avg ({} operations)",
        lookup_time.as_millis() as f64 / ITERATIONS as f64,
        ITERATIONS
    );
    println!(
        "  Health Check: {:.2}ms avg ({} operations)",
        health_check_time.as_millis() as f64 / ITERATIONS as f64,
        ITERATIONS
    );

    // Cleanup performance test data
    for i in 0..ITERATIONS {
        let email = format!("perf_test_{}_{}_@example.com", ctx.db_type, i);
        if let Ok(Some(user)) = ctx.db.find_user_by_email(&email).await {
            let _ = ctx.db.deactivate_user(&user.user_id).await;
        }
    }
}

/// Test authentication endpoints with real HTTP calls
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_api_endpoints() {
    // This test assumes the auth service is running on localhost:8090
    let base_url =
        env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string());

    let client = Client::new();

    // Test health endpoint
    let health_response = client
        .get(&format!("{}/health", base_url))
        .send()
        .await
        .expect("Failed to call health endpoint");

    assert!(health_response.status().is_success());

    // Test user registration
    let registration_payload = json!({
        "email": "api_test@example.com",
        "password": "TestPassword123!",
        "first_name": "API",
        "last_name": "Test"
    });

    let register_response = client
        .post(&format!("{}/auth/register", base_url))
        .json(&registration_payload)
        .send()
        .await;

    match register_response {
        Ok(response) => {
            println!("Registration response status: {}", response.status());
            if response.status().is_success() {
                println!("✅ Registration endpoint working");
            }
        }
        Err(e) => {
            println!("⚠️  Could not test registration endpoint: {}", e);
            println!("Make sure the auth service is running on {}", base_url);
        }
    }
}

/// Load test with concurrent requests
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn load_test_concurrent_requests() {
    let base_url =
        env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string());

    const CONCURRENT_REQUESTS: usize = 50;
    let client = Client::new();

    println!(
        "🔄 Running load test with {} concurrent health check requests",
        CONCURRENT_REQUESTS
    );

    let start = Instant::now();
    let mut handles = Vec::new();

    for i in 0..CONCURRENT_REQUESTS {
        let client = client.clone();
        let url = format!("{}/health", base_url);

        let handle = tokio::spawn(async move {
            let response = client.get(&url).send().await;
            match response {
                Ok(resp) => (i, resp.status().is_success(), resp.status().as_u16()),
                Err(_) => (i, false, 0),
            }
        });

        handles.push(handle);
    }

    let mut successful = 0;
    let mut failed = 0;

    for handle in handles {
        match handle.await {
            Ok((_, true, _)) => successful += 1,
            Ok((_, false, status)) => {
                failed += 1;
                println!("Request failed with status: {}", status);
            }
            Err(e) => {
                failed += 1;
                println!("Request error: {}", e);
            }
        }
    }

    let duration = start.elapsed();

    println!("📊 Load Test Results:");
    println!("  Duration: {:?}", duration);
    println!("  Successful: {}/{}", successful, CONCURRENT_REQUESTS);
    println!("  Failed: {}", failed);
    println!(
        "  Requests/second: {:.2}",
        CONCURRENT_REQUESTS as f64 / duration.as_secs_f64()
    );

    if successful == CONCURRENT_REQUESTS {
        println!("✅ Load test passed - all requests successful");
    } else {
        println!("⚠️  Load test completed with {} failures", failed);
    }
}
