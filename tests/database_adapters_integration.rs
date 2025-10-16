use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use rust_auth_service::config::database::DatabaseConfig;
use rust_auth_service::database::{create_database, AuthDatabase};
use rust_auth_service::models::user::{User, UserError, UserMetadata, UserRole};

/// Database Adapter Integration Tests
///
/// This test suite validates all database adapters (MongoDB, PostgreSQL, MySQL)
/// Tests include connection validation, CRUD operations, authentication flows,
/// error handling, and adapter-specific functionality.
///
/// Run with: cargo test --test database_adapters_integration -- --include-ignored

struct TestDatabase {
    adapter: Box<dyn AuthDatabase + Send + Sync>,
    database_type: String,
}

/// Generate a unique test user for isolation
fn generate_test_user(prefix: &str) -> User {
    let unique_id = Uuid::new_v4().to_string()[..8].to_string();
    let email = format!("{}+{}@example.com", prefix, unique_id);

    User {
        id: None,
        user_id: Uuid::new_v4().to_string(),
        email,
        password_hash: "$2a$12$test.hash.for.testing.only".to_string(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        role: UserRole::User,
        is_active: true,
        email_verified: false,
        email_verification_token: Some(Uuid::new_v4().to_string()),
        email_verification_expires: Some(Utc::now() + chrono::Duration::hours(24)),
        password_reset_token: None,
        password_reset_expires: None,
        last_login: None,
        login_attempts: 0,
        locked_until: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        metadata: UserMetadata {
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("Test Agent".to_string()),
            registration_source: Some("test".to_string()),
            timezone: None,
            locale: None,
            preferences: json!({}),
        },
    }
}

/// Create test database configurations for all supported adapters
async fn create_test_databases() -> Vec<TestDatabase> {
    let mut databases = Vec::new();

    // MongoDB Test Database
    #[cfg(feature = "mongodb")]
    {
        if let Ok(mongo_url) = std::env::var("MONGODB_TEST_URL") {
            let config = DatabaseConfig {
                r#type: "mongodb".to_string(),
                url: mongo_url,
                pool: Default::default(),
            };

            match create_database(&config).await {
                Ok(adapter) => {
                    databases.push(TestDatabase {
                        adapter,
                        database_type: "mongodb".to_string(),
                    });
                    println!("✅ MongoDB test database ready");
                }
                Err(e) => println!("⚠️  MongoDB test database unavailable: {}", e),
            }
        } else {
            println!("⚠️  MONGODB_TEST_URL not set, skipping MongoDB tests");
        }
    }

    // PostgreSQL Test Database
    #[cfg(feature = "postgresql")]
    {
        if let Ok(pg_url) = std::env::var("POSTGRESQL_TEST_URL") {
            let config = DatabaseConfig {
                r#type: "postgresql".to_string(),
                url: pg_url,
                pool: Default::default(),
            };

            match create_database(&config).await {
                Ok(adapter) => {
                    databases.push(TestDatabase {
                        adapter,
                        database_type: "postgresql".to_string(),
                    });
                    println!("✅ PostgreSQL test database ready");
                }
                Err(e) => println!("⚠️  PostgreSQL test database unavailable: {}", e),
            }
        } else {
            println!("⚠️  POSTGRESQL_TEST_URL not set, skipping PostgreSQL tests");
        }
    }

    // MySQL Test Database
    #[cfg(feature = "mysql")]
    {
        if let Ok(mysql_url) = std::env::var("MYSQL_TEST_URL") {
            let config = DatabaseConfig {
                r#type: "mysql".to_string(),
                url: mysql_url,
                pool: Default::default(),
            };

            match create_database(&config).await {
                Ok(adapter) => {
                    databases.push(TestDatabase {
                        adapter,
                        database_type: "mysql".to_string(),
                    });
                    println!("✅ MySQL test database ready");
                }
                Err(e) => println!("⚠️  MySQL test database unavailable: {}", e),
            }
        } else {
            println!("⚠️  MYSQL_TEST_URL not set, skipping MySQL tests");
        }
    }

    if databases.is_empty() {
        panic!("No test databases available. Set at least one of: MONGODB_TEST_URL, POSTGRESQL_TEST_URL, MYSQL_TEST_URL");
    }

    databases
}

/// Test database health checks across all adapters
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_database_health_checks() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} health check", db.database_type);

        let health = db
            .adapter
            .health_check()
            .await
            .expect("Health check should complete");

        assert!(health.connected, "{} should be connected", db.database_type);
        assert_eq!(health.database_type, db.database_type);
        assert!(
            health.response_time_ms < 1000,
            "{} response time should be reasonable",
            db.database_type
        );

        println!(
            "✅ {} health check passed ({}ms)",
            db.database_type, health.response_time_ms
        );
    }
}

/// Test user creation across all database adapters
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_user_creation() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} user creation", db.database_type);

        let user = generate_test_user(&format!("create_{}", db.database_type));
        let original_email = user.email.clone();

        let created_user = db
            .adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        assert_eq!(created_user.email, original_email);
        assert!(created_user.user_id.len() > 0, "User ID should be set");
        assert!(
            !created_user.email_verified,
            "Email should not be verified initially"
        );

        println!("✅ {} user creation passed", db.database_type);
    }
}

/// Test duplicate email handling
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_duplicate_email_prevention() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} duplicate email prevention", db.database_type);

        let user = generate_test_user(&format!("duplicate_{}", db.database_type));
        let duplicate_user = user.clone();

        // First user should succeed
        db.adapter
            .create_user(user)
            .await
            .expect("First user creation should succeed");

        // Second user with same email should fail
        let result = db.adapter.create_user(duplicate_user).await;

        match result {
            Err(UserError::EmailAlreadyExists) => {
                println!(
                    "✅ {} correctly prevented duplicate email",
                    db.database_type
                );
            }
            Ok(_) => panic!("{} should have prevented duplicate email", db.database_type),
            Err(e) => panic!("{} returned unexpected error: {:?}", db.database_type, e),
        }
    }
}

/// Test user lookup by email
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_user_lookup_by_email() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} user lookup by email", db.database_type);

        let user = generate_test_user(&format!("lookup_email_{}", db.database_type));
        let email = user.email.clone();

        // Create user
        let created_user = db
            .adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        // Find by email
        let found_user = db
            .adapter
            .find_user_by_email(&email)
            .await
            .expect("Email lookup should succeed")
            .expect("User should be found");

        assert_eq!(found_user.email, email);
        assert_eq!(found_user.user_id, created_user.user_id);

        // Test case insensitive lookup
        let found_user_upper = db
            .adapter
            .find_user_by_email(&email.to_uppercase())
            .await
            .expect("Case insensitive lookup should succeed")
            .expect("User should be found with uppercase email");

        assert_eq!(found_user_upper.user_id, created_user.user_id);

        // Test non-existent email
        let not_found = db
            .adapter
            .find_user_by_email("nonexistent@example.com")
            .await
            .expect("Lookup should complete");

        assert!(not_found.is_none(), "Non-existent user should not be found");

        println!("✅ {} user lookup by email passed", db.database_type);
    }
}

/// Test user lookup by ID
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_user_lookup_by_id() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} user lookup by ID", db.database_type);

        let user = generate_test_user(&format!("lookup_id_{}", db.database_type));

        // Create user
        let created_user = db
            .adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        // Find by ID
        let found_user = db
            .adapter
            .find_user_by_id(&created_user.user_id)
            .await
            .expect("ID lookup should succeed")
            .expect("User should be found");

        assert_eq!(found_user.user_id, created_user.user_id);
        assert_eq!(found_user.email, created_user.email);

        // Test non-existent ID
        let not_found = db
            .adapter
            .find_user_by_id("nonexistent-id")
            .await
            .expect("Lookup should complete");

        assert!(not_found.is_none(), "Non-existent user should not be found");

        println!("✅ {} user lookup by ID passed", db.database_type);
    }
}

/// Test user updates
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_user_updates() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} user updates", db.database_type);

        let user = generate_test_user(&format!("update_{}", db.database_type));

        // Create user
        let mut created_user = db
            .adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        // Update user
        created_user.first_name = "Updated".to_string();
        created_user.last_name = "Name".to_string();
        created_user.email_verified = true;
        created_user.updated_at = Utc::now();

        let updated_user = db
            .adapter
            .update_user(&created_user)
            .await
            .expect("User update should succeed");

        assert_eq!(updated_user.first_name, "Updated");
        assert_eq!(updated_user.last_name, "Name");
        assert!(updated_user.email_verified);

        // Verify persistence
        let verified_user = db
            .adapter
            .find_user_by_id(&created_user.user_id)
            .await
            .expect("User lookup should succeed")
            .expect("User should be found");

        assert_eq!(verified_user.first_name, "Updated");
        assert_eq!(verified_user.last_name, "Name");
        assert!(verified_user.email_verified);

        println!("✅ {} user updates passed", db.database_type);
    }
}

/// Test password operations
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_password_operations() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} password operations", db.database_type);

        let user = generate_test_user(&format!("password_{}", db.database_type));
        let original_hash = user.password_hash.clone();

        // Create user
        let created_user = db
            .adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        // Update password
        let new_password_hash = "$2a$12$new.test.hash.for.testing.only";
        db.adapter
            .update_password(&created_user.user_id, new_password_hash)
            .await
            .expect("Password update should succeed");

        // Verify password was updated
        let updated_user = db
            .adapter
            .find_user_by_id(&created_user.user_id)
            .await
            .expect("User lookup should succeed")
            .expect("User should be found");

        assert_eq!(updated_user.password_hash, new_password_hash);
        assert_ne!(updated_user.password_hash, original_hash);

        println!("✅ {} password operations passed", db.database_type);
    }
}

/// Test email verification flow
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_email_verification_flow() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} email verification flow", db.database_type);

        let user = generate_test_user(&format!("verify_{}", db.database_type));

        // Create user
        let created_user = db
            .adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        assert!(!created_user.email_verified);

        // Set verification token
        let token = Uuid::new_v4().to_string();
        db.adapter
            .set_email_verification_token(&created_user.user_id, &token, 24)
            .await
            .expect("Setting verification token should succeed");

        // Verify email
        let verified_user_id = db
            .adapter
            .verify_email(&token)
            .await
            .expect("Email verification should succeed");

        assert_eq!(verified_user_id, created_user.user_id);

        // Check user is verified
        let verified_user = db
            .adapter
            .find_user_by_id(&created_user.user_id)
            .await
            .expect("User lookup should succeed")
            .expect("User should be found");

        assert!(verified_user.email_verified);
        assert!(verified_user.email_verification_token.is_none());

        println!("✅ {} email verification flow passed", db.database_type);
    }
}

/// Test password reset flow
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_password_reset_flow() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} password reset flow", db.database_type);

        let user = generate_test_user(&format!("reset_{}", db.database_type));
        let email = user.email.clone();

        // Create user
        let created_user = db
            .adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        // Set password reset token
        let token = Uuid::new_v4().to_string();
        db.adapter
            .set_password_reset_token(&email, &token, 24)
            .await
            .expect("Setting reset token should succeed");

        // Verify reset token
        let user_id = db
            .adapter
            .verify_password_reset_token(&token)
            .await
            .expect("Reset token verification should succeed");

        assert_eq!(user_id, created_user.user_id);

        // Clear reset token
        db.adapter
            .clear_password_reset_token(&created_user.user_id)
            .await
            .expect("Clearing reset token should succeed");

        // Verify token is cleared
        let result = db.adapter.verify_password_reset_token(&token).await;
        assert!(result.is_err(), "Token should be invalid after clearing");

        println!("✅ {} password reset flow passed", db.database_type);
    }
}

/// Test login attempt tracking
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_login_attempt_tracking() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} login attempt tracking", db.database_type);

        let user = generate_test_user(&format!("login_{}", db.database_type));
        let email = user.email.clone();

        // Create user
        let created_user = db
            .adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        // Record successful login
        db.adapter
            .record_login(&created_user.user_id)
            .await
            .expect("Recording login should succeed");

        // Check login was recorded
        let updated_user = db
            .adapter
            .find_user_by_id(&created_user.user_id)
            .await
            .expect("User lookup should succeed")
            .expect("User should be found");

        assert!(updated_user.last_login.is_some());
        assert_eq!(updated_user.login_attempts, 0);

        // Record failed login attempts
        for _ in 0..3 {
            db.adapter
                .record_failed_login(&email, 5, 1)
                .await
                .expect("Recording failed login should succeed");
        }

        // Check failed attempts were recorded
        let user_with_attempts = db
            .adapter
            .find_user_by_email(&email)
            .await
            .expect("User lookup should succeed")
            .expect("User should be found");

        assert_eq!(user_with_attempts.login_attempts, 3);

        println!("✅ {} login attempt tracking passed", db.database_type);
    }
}

/// Test account lockout functionality
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_account_lockout() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} account lockout", db.database_type);

        let user = generate_test_user(&format!("lockout_{}", db.database_type));
        let email = user.email.clone();

        // Create user
        db.adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        // Trigger account lockout (exceed max attempts)
        for _ in 0..5 {
            db.adapter
                .record_failed_login(&email, 3, 1)
                .await
                .expect("Recording failed login should succeed");
        }

        // Check account is locked
        let locked_user = db
            .adapter
            .find_user_by_email(&email)
            .await
            .expect("User lookup should succeed")
            .expect("User should be found");

        assert!(locked_user.locked_until.is_some());
        assert!(locked_user.locked_until.unwrap() > Utc::now());

        println!("✅ {} account lockout passed", db.database_type);
    }
}

/// Test user deactivation
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_user_deactivation() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} user deactivation", db.database_type);

        let user = generate_test_user(&format!("deactivate_{}", db.database_type));

        // Create user
        let created_user = db
            .adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        assert!(created_user.is_active);

        // Deactivate user
        db.adapter
            .deactivate_user(&created_user.user_id)
            .await
            .expect("User deactivation should succeed");

        // Check user is deactivated
        let deactivated_user = db
            .adapter
            .find_user_by_id(&created_user.user_id)
            .await
            .expect("User lookup should succeed")
            .expect("User should be found");

        assert!(!deactivated_user.is_active);

        println!("✅ {} user deactivation passed", db.database_type);
    }
}

/// Test user existence checks
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_user_existence_checks() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} user existence checks", db.database_type);

        let user = generate_test_user(&format!("exists_{}", db.database_type));
        let email = user.email.clone();

        // Check non-existent user
        let exists_before = db
            .adapter
            .user_exists_by_email(&email)
            .await
            .expect("Existence check should succeed");

        assert!(!exists_before);

        // Create user
        db.adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        // Check existing user
        let exists_after = db
            .adapter
            .user_exists_by_email(&email)
            .await
            .expect("Existence check should succeed");

        assert!(exists_after);

        // Test case insensitive check
        let exists_upper = db
            .adapter
            .user_exists_by_email(&email.to_uppercase())
            .await
            .expect("Case insensitive check should succeed");

        assert!(exists_upper);

        println!("✅ {} user existence checks passed", db.database_type);
    }
}

/// Test concurrent operations
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_concurrent_operations() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} concurrent operations", db.database_type);

        const CONCURRENT_USERS: usize = 10;
        let mut handles = Vec::new();

        for i in 0..CONCURRENT_USERS {
            let db_type = db.database_type.clone();

            let handle = tokio::spawn({
                let user = generate_test_user(&format!("concurrent_{}_{}", db_type, i));
                async move {
                    // Create a new connection for each concurrent operation
                    let config =
                        match std::env::var(&format!("{}_TEST_URL", db_type.to_uppercase())) {
                            Ok(url) => DatabaseConfig {
                                r#type: db_type.clone(),
                                url,
                                pool: Default::default(),
                            },
                            Err(_) => return Err(UserError::Database("No test URL".to_string())),
                        };

                    match create_database(&config).await {
                        Ok(adapter) => adapter.create_user(user).await,
                        Err(e) => Err(UserError::Database(format!(
                            "Failed to create adapter: {}",
                            e
                        ))),
                    }
                }
            });

            handles.push(handle);
        }

        let mut successful = 0;
        let mut failed = 0;

        for handle in handles {
            match handle.await {
                Ok(Ok(_)) => successful += 1,
                Ok(Err(_)) => failed += 1,
                Err(_) => failed += 1,
            }
        }

        println!(
            "📊 {} Concurrent Operations - Success: {}, Failed: {}",
            db.database_type, successful, failed
        );

        // At least 80% should succeed
        assert!(
            successful >= CONCURRENT_USERS * 8 / 10,
            "{} should handle concurrent operations effectively",
            db.database_type
        );

        println!("✅ {} concurrent operations passed", db.database_type);
    }
}

/// Test database adapter error handling
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_error_handling() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} error handling", db.database_type);

        // Test invalid user ID operations
        let result = db.adapter.find_user_by_id("invalid-id-format").await;
        assert!(result.is_ok(), "Invalid ID should return None, not error");

        // Test operations on non-existent users
        let result = db.adapter.update_password("nonexistent-user", "hash").await;
        assert!(
            matches!(result, Err(UserError::NotFound)),
            "Operations on non-existent users should return NotFound"
        );

        // Test invalid token operations
        let result = db.adapter.verify_email("invalid-token").await;
        assert!(result.is_err(), "Invalid tokens should return error");

        println!("✅ {} error handling passed", db.database_type);
    }
}

/// Full integration test combining all operations
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_complete_user_lifecycle() {
    let databases = create_test_databases().await;

    for db in databases {
        println!("🔍 Testing {} complete user lifecycle", db.database_type);

        let user = generate_test_user(&format!("lifecycle_{}", db.database_type));
        let email = user.email.clone();

        // 1. Create user
        let created_user = db
            .adapter
            .create_user(user)
            .await
            .expect("User creation should succeed");

        // 2. Verify email
        let token = Uuid::new_v4().to_string();
        db.adapter
            .set_email_verification_token(&created_user.user_id, &token, 24)
            .await
            .expect("Setting verification token should succeed");

        db.adapter
            .verify_email(&token)
            .await
            .expect("Email verification should succeed");

        // 3. Update profile
        let mut updated_user = created_user.clone();
        updated_user.first_name = "Updated".to_string();
        updated_user.updated_at = Utc::now();

        db.adapter
            .update_user(&updated_user)
            .await
            .expect("Profile update should succeed");

        // 4. Change password
        let new_hash = "$2a$12$lifecycle.test.hash";
        db.adapter
            .update_password(&created_user.user_id, new_hash)
            .await
            .expect("Password update should succeed");

        // 5. Record login activity
        db.adapter
            .record_login(&created_user.user_id)
            .await
            .expect("Login recording should succeed");

        // 6. Test failed login attempts
        db.adapter
            .record_failed_login(&email, 5, 1)
            .await
            .expect("Failed login recording should succeed");

        // 7. Deactivate user
        db.adapter
            .deactivate_user(&created_user.user_id)
            .await
            .expect("User deactivation should succeed");

        // 8. Verify final state
        let final_user = db
            .adapter
            .find_user_by_id(&created_user.user_id)
            .await
            .expect("Final user lookup should succeed")
            .expect("User should be found");

        assert!(!final_user.is_active);
        assert!(final_user.email_verified);
        assert_eq!(final_user.first_name, "Updated");
        assert_eq!(final_user.password_hash, new_hash);
        assert!(final_user.last_login.is_some());

        println!("✅ {} complete user lifecycle passed", db.database_type);
    }
}
