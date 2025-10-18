#[cfg(feature = "postgresql")]
use anyhow::Result;
#[cfg(feature = "postgresql")]
use tokio;
#[cfg(feature = "postgresql")]
use tracing::{info, debug};

#[cfg(feature = "postgresql")]
mod common;
#[cfg(feature = "postgresql")]
use common::{
    init_test_environment, create_test_database,
    fixtures::TestFixtures,
    database::DatabaseTestHelpers,
    utils::{measure_async, ConsistencyChecker, StressTestRunner},
    assertions::{assert_user_equals, assert_user_error_type},
};

#[cfg(feature = "postgresql")]
use rust_auth_service::models::user::{User, UserError};

/// PostgreSQL-specific integration tests
#[cfg(all(test, feature = "postgresql"))]
mod postgresql_integration {
    use super::*;

    #[tokio::test]
    async fn test_postgresql_user_lifecycle() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL user lifecycle");
        
        // Test user creation
        let user = TestFixtures::minimal_user();
        let (created_user, _metrics) = measure_async(
            "create_user",
            "postgresql",
            test_db.instance.create_user(user.clone())
        ).await?;
        
        assert!(created_user.id.is_some());
        assert_eq!(created_user.email, user.email);
        
        // Test user retrieval by email
        let found_user = test_db.instance.find_user_by_email(&user.email).await?;
        assert!(found_user.is_some());
        assert_user_equals(&found_user.unwrap(), &created_user);
        
        // Test user retrieval by ID
        if let Some(user_id) = &created_user.id {
            let found_by_id = test_db.instance.find_user_by_id(user_id).await?;
            assert!(found_by_id.is_some());
            assert_user_equals(&found_by_id.unwrap(), &created_user);
        }
        
        // Test user update
        let mut updated_user = created_user.clone();
        updated_user.full_name = "Updated PostgreSQL Name".to_string();
        updated_user.email_verified = true;
        
        let (result_user, _metrics) = measure_async(
            "update_user",
            "postgresql",
            test_db.instance.update_user(&updated_user)
        ).await?;
        
        assert_eq!(result_user.full_name, "Updated PostgreSQL Name");
        assert!(result_user.email_verified);
        
        info!("PostgreSQL user lifecycle test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_postgresql_authentication_flow() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL authentication flow");
        
        let user = TestFixtures::complete_user();
        let created_user = test_db.instance.create_user(user).await?;
        
        // Verify authentication helpers
        DatabaseTestHelpers::verify_authentication_flow(&test_db.instance, &created_user).await?;
        
        info!("PostgreSQL authentication flow test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_postgresql_email_verification_flow() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL email verification flow");
        
        let user = TestFixtures::unverified_user();
        let created_user = test_db.instance.create_user(user).await?;
        
        // Verify email verification helpers
        DatabaseTestHelpers::verify_email_verification_flow(&test_db.instance, &created_user).await?;
        
        info!("PostgreSQL email verification flow test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_postgresql_password_reset_flow() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL password reset flow");
        
        let user = TestFixtures::password_reset_user();
        let created_user = test_db.instance.create_user(user).await?;
        
        // Verify password reset helpers
        DatabaseTestHelpers::verify_password_reset_flow(&test_db.instance, &created_user).await?;
        
        info!("PostgreSQL password reset flow test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_postgresql_edge_cases() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL edge cases");
        
        // Test duplicate email prevention
        let user1 = TestFixtures::minimal_user();
        let user2 = user1.clone();
        
        test_db.instance.create_user(user1).await?;
        
        let duplicate_result = test_db.instance.create_user(user2).await;
        assert!(duplicate_result.is_err());
        if let Err(e) = duplicate_result {
            assert_user_error_type(&e, "already_exists");
        }
        
        // Test finding non-existent user
        let not_found = test_db.instance.find_user_by_email("nonexistent@postgresql.com").await?;
        assert!(not_found.is_none());
        
        // Test finding by invalid ID
        let invalid_id_result = test_db.instance.find_user_by_id("00000000-0000-0000-0000-000000000000").await;
        // PostgreSQL might return empty result instead of error for valid UUID format
        match invalid_id_result {
            Ok(None) => debug!("PostgreSQL returned None for non-existent UUID"),
            Err(e) => debug!("PostgreSQL returned error for invalid ID: {}", e),
            Ok(Some(_)) => panic!("PostgreSQL should not find user with invalid ID"),
        }
        
        // Test special characters (PostgreSQL should handle these better than MongoDB)
        for edge_user in TestFixtures::edge_case_users() {
            let result = test_db.instance.create_user(edge_user.clone()).await;
            match result {
                Ok(created) => {
                    debug!("Successfully created edge case user: {}", edge_user.email);
                    assert_eq!(created.email, edge_user.email);
                },
                Err(e) => {
                    debug!("Edge case user creation failed: {}", e);
                }
            }
        }
        
        info!("PostgreSQL edge cases test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_postgresql_transactions() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL transaction behavior");
        
        // Test that operations are atomic (this is more relevant for PostgreSQL)
        let user1 = TestFixtures::minimal_user();
        let user2 = TestFixtures::admin_user();
        
        // Create users
        let created_user1 = test_db.instance.create_user(user1).await?;
        let created_user2 = test_db.instance.create_user(user2).await?;
        
        // Test that both users exist
        let found1 = test_db.instance.find_user_by_email(&created_user1.email).await?;
        let found2 = test_db.instance.find_user_by_email(&created_user2.email).await?;
        
        assert!(found1.is_some());
        assert!(found2.is_some());
        
        // Test simultaneous updates don't interfere
        if let (Some(id1), Some(id2)) = (&created_user1.id, &created_user2.id) {
            let update1 = test_db.instance.update_last_login(id1);
            let update2 = test_db.instance.update_last_login(id2);
            
            // Run updates concurrently
            let (result1, result2) = tokio::join!(update1, update2);
            
            assert!(result1.is_ok(), "First update should succeed");
            assert!(result2.is_ok(), "Second update should succeed");
        }
        
        info!("PostgreSQL transaction behavior test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_postgresql_bulk_operations() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL bulk operations");
        
        let bulk_users = TestFixtures::bulk_users(50);
        let mut created_count = 0;
        
        for user in bulk_users {
            match test_db.instance.create_user(user.clone()).await {
                Ok(_) => created_count += 1,
                Err(e) => debug!("Failed to create bulk user {}: {}", user.email, e),
            }
        }
        
        assert!(created_count >= 40, "Should create at least 40 out of 50 users");
        info!("Created {} users in bulk operation", created_count);
        
        info!("PostgreSQL bulk operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_postgresql_concurrent_operations() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL concurrent operations");
        
        let stress_runner = StressTestRunner::new(10, 100);
        let db_instance = test_db.instance.clone();
        
        let duration = stress_runner.run_concurrent_test(move |operation_id| {
            let db = db_instance.clone();
            async move {
                let user = User {
                    id: None,
                    email: format!("pg_concurrent_{}@example.com", operation_id),
                    password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                    full_name: format!("PostgreSQL Concurrent User {}", operation_id),
                    role: "user".to_string(),
                    is_active: true,
                    email_verified: false,
                    email_verification_token: None,
                    email_verification_expires: None,
                    password_reset_token: None,
                    password_reset_expires: None,
                    failed_login_attempts: 0,
                    locked_until: None,
                    last_login: None,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                
                db.create_user(user).await.map_err(|e| anyhow::anyhow!("Create user failed: {:?}", e))?;
                Ok(())
            }
        }).await?;
        
        let success_rate = stress_runner.success_rate();
        assert!(success_rate > 0.95, "Success rate should be > 95%, got {:.2}", success_rate);
        
        info!(
            "PostgreSQL concurrent test: {:.1} ops/sec, {:.1}% success rate",
            100.0 / duration.as_secs_f64(),
            success_rate * 100.0
        );
        
        info!("PostgreSQL concurrent operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_postgresql_health_check() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL health check");
        
        let (health, _metrics) = measure_async(
            "health_check",
            "postgresql",
            test_db.instance.health_check()
        ).await?;
        
        assert!(health.connected);
        assert_eq!(health.database_type, "postgresql");
        assert!(health.response_time_ms < 1000); // Should be fast
        
        info!("PostgreSQL health check test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_postgresql_complex_queries() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL complex query operations");
        
        // Create various types of users
        let users = vec![
            TestFixtures::minimal_user(),
            TestFixtures::admin_user(),
            TestFixtures::locked_user(),
            TestFixtures::inactive_user(),
        ];
        
        let mut created_users = Vec::new();
        for user in users {
            let created = test_db.instance.create_user(user).await?;
            created_users.push(created);
        }
        
        // Test user existence checks
        for user in &created_users {
            let exists = test_db.instance.user_exists_by_email(&user.email).await?;
            assert!(exists, "User should exist: {}", user.email);
        }
        
        // Test non-existent user
        let not_exists = test_db.instance.user_exists_by_email("nonexistent@postgresql.test").await?;
        assert!(!not_exists, "Non-existent user should not exist");
        
        // Test login recording and attempts
        for user in &created_users {
            if let Some(user_id) = &user.id {
                // Record some failed login attempts
                test_db.instance.record_failed_login(&user.email, 5, 24).await?;
                
                // Record successful login
                test_db.instance.record_login(user_id).await?;
                
                // Update login attempts
                test_db.instance.update_login_attempts(user_id, 0, None).await?;
            }
        }
        
        info!("PostgreSQL complex query operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_postgresql_data_types() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL data type handling");
        
        // Test timestamp precision
        let now = chrono::Utc::now();
        let user = User {
            id: None,
            email: "timestamp.test@postgresql.com".to_string(),
            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
            full_name: "Timestamp Test User".to_string(),
            role: "user".to_string(),
            is_active: true,
            email_verified: false,
            email_verification_token: Some("token_with_precise_timestamp".to_string()),
            email_verification_expires: Some(now + chrono::Duration::hours(24)),
            password_reset_token: None,
            password_reset_expires: None,
            failed_login_attempts: 0,
            locked_until: Some(now + chrono::Duration::minutes(30)),
            last_login: Some(now - chrono::Duration::hours(2)),
            created_at: now,
            updated_at: now,
        };
        
        let created_user = test_db.instance.create_user(user.clone()).await?;
        
        // Verify timestamp precision is maintained
        let retrieved_user = test_db.instance.find_user_by_email(&user.email).await?;
        assert!(retrieved_user.is_some());
        
        let retrieved = retrieved_user.unwrap();
        
        // PostgreSQL should maintain good timestamp precision
        let time_diff = (retrieved.created_at - user.created_at).abs();
        assert!(
            time_diff <= chrono::Duration::seconds(1),
            "Timestamp precision should be maintained within 1 second, got diff: {:?}",
            time_diff
        );
        
        info!("PostgreSQL data type handling test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_postgresql_connection_pool() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("postgresql").await?;
        
        info!("Testing PostgreSQL connection pool behavior");
        
        // Simulate multiple concurrent database operations to test connection pooling
        let mut handles = Vec::new();
        
        for i in 0..20 {
            let db = test_db.instance.clone();
            let handle = tokio::spawn(async move {
                let user = User {
                    id: None,
                    email: format!("pool_test_{}@postgresql.com", i),
                    password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                    full_name: format!("Pool Test User {}", i),
                    role: "user".to_string(),
                    is_active: true,
                    email_verified: false,
                    email_verification_token: None,
                    email_verification_expires: None,
                    password_reset_token: None,
                    password_reset_expires: None,
                    failed_login_attempts: 0,
                    locked_until: None,
                    last_login: None,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                
                // Create and immediately query the user
                let created = db.create_user(user.clone()).await?;
                let found = db.find_user_by_email(&user.email).await?;
                
                Result::<bool>::Ok(found.is_some() && found.unwrap().id == created.id)
            });
            
            handles.push(handle);
        }
        
        // Wait for all operations and check success
        let mut success_count = 0;
        for handle in handles {
            match handle.await {
                Ok(Ok(true)) => success_count += 1,
                Ok(Ok(false)) => debug!("Operation completed but validation failed"),
                Ok(Err(e)) => debug!("Operation failed: {}", e),
                Err(e) => debug!("Task failed: {}", e),
            }
        }
        
        assert!(
            success_count >= 18,
            "At least 18 out of 20 operations should succeed, got {}",
            success_count
        );
        
        info!("PostgreSQL connection pool test completed successfully with {} successes", success_count);
        Ok(())
    }
}

// Tests that should run even without PostgreSQL feature for compilation verification
#[cfg(test)]
mod postgresql_compilation_tests {
    #[test]
    fn test_postgresql_feature_compilation() {
        #[cfg(not(feature = "postgresql"))]
        {
            println!("PostgreSQL tests skipped - feature not enabled");
            println!("To run PostgreSQL tests, use: cargo test --features postgresql");
        }
        
        #[cfg(feature = "postgresql")]
        {
            println!("PostgreSQL feature is enabled");
        }
    }
}