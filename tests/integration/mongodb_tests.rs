use anyhow::Result;
use tokio;
use tracing::{info, debug};

mod common;
use common::{
    init_test_environment, create_test_database,
    fixtures::TestFixtures,
    database::DatabaseTestHelpers,
    utils::{measure_async, ConsistencyChecker, StressTestRunner},
    assertions::{assert_user_equals, assert_user_error_type},
};

use rust_auth_service::models::user::{User, UserError};

/// MongoDB-specific integration tests
#[cfg(test)]
mod mongodb_integration {
    use super::*;

    #[tokio::test]
    async fn test_mongodb_user_lifecycle() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("mongodb").await?;
        
        info!("Testing MongoDB user lifecycle");
        
        // Test user creation
        let user = TestFixtures::minimal_user();
        let (created_user, _metrics) = measure_async(
            "create_user",
            "mongodb",
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
        updated_user.full_name = "Updated Name".to_string();
        updated_user.email_verified = true;
        
        let (result_user, _metrics) = measure_async(
            "update_user",
            "mongodb",
            test_db.instance.update_user(&updated_user)
        ).await?;
        
        assert_eq!(result_user.full_name, "Updated Name");
        assert!(result_user.email_verified);
        
        info!("MongoDB user lifecycle test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_mongodb_authentication_flow() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("mongodb").await?;
        
        info!("Testing MongoDB authentication flow");
        
        let user = TestFixtures::complete_user();
        let created_user = test_db.instance.create_user(user).await?;
        
        // Verify authentication helpers
        DatabaseTestHelpers::verify_authentication_flow(&test_db.instance, &created_user).await?;
        
        info!("MongoDB authentication flow test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_mongodb_email_verification_flow() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("mongodb").await?;
        
        info!("Testing MongoDB email verification flow");
        
        let user = TestFixtures::unverified_user();
        let created_user = test_db.instance.create_user(user).await?;
        
        // Verify email verification helpers
        DatabaseTestHelpers::verify_email_verification_flow(&test_db.instance, &created_user).await?;
        
        info!("MongoDB email verification flow test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_mongodb_password_reset_flow() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("mongodb").await?;
        
        info!("Testing MongoDB password reset flow");
        
        let user = TestFixtures::password_reset_user();
        let created_user = test_db.instance.create_user(user).await?;
        
        // Verify password reset helpers
        DatabaseTestHelpers::verify_password_reset_flow(&test_db.instance, &created_user).await?;
        
        info!("MongoDB password reset flow test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_mongodb_edge_cases() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("mongodb").await?;
        
        info!("Testing MongoDB edge cases");
        
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
        let not_found = test_db.instance.find_user_by_email("nonexistent@example.com").await?;
        assert!(not_found.is_none());
        
        // Test finding by invalid ID
        let invalid_id_result = test_db.instance.find_user_by_id("invalid_id").await;
        assert!(invalid_id_result.is_err());
        
        // Test special characters
        for edge_user in TestFixtures::edge_case_users() {
            let result = test_db.instance.create_user(edge_user.clone()).await;
            match result {
                Ok(created) => {
                    debug!("Successfully created edge case user: {}", edge_user.email);
                    assert_eq!(created.email, edge_user.email);
                },
                Err(e) => {
                    debug!("Edge case user creation failed (expected): {}", e);
                }
            }
        }
        
        info!("MongoDB edge cases test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_mongodb_bulk_operations() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("mongodb").await?;
        
        info!("Testing MongoDB bulk operations");
        
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
        
        info!("MongoDB bulk operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_mongodb_concurrent_operations() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("mongodb").await?;
        
        info!("Testing MongoDB concurrent operations");
        
        let stress_runner = StressTestRunner::new(10, 100);
        let db_instance = test_db.instance.clone();
        
        let duration = stress_runner.run_concurrent_test(move |operation_id| {
            let db = db_instance.clone();
            async move {
                let user = User {
                    id: None,
                    email: format!("concurrent_{}@example.com", operation_id),
                    password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                    full_name: format!("Concurrent User {}", operation_id),
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
            "MongoDB concurrent test: {:.1} ops/sec, {:.1}% success rate",
            100.0 / duration.as_secs_f64(),
            success_rate * 100.0
        );
        
        info!("MongoDB concurrent operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_mongodb_health_check() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("mongodb").await?;
        
        info!("Testing MongoDB health check");
        
        let (health, _metrics) = measure_async(
            "health_check",
            "mongodb",
            test_db.instance.health_check()
        ).await?;
        
        assert!(health.connected);
        assert_eq!(health.database_type, "mongodb");
        assert!(health.response_time_ms < 1000); // Should be fast
        
        info!("MongoDB health check test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_mongodb_login_attempts() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("mongodb").await?;
        
        info!("Testing MongoDB login attempts");
        
        let user = TestFixtures::minimal_user();
        let created_user = test_db.instance.create_user(user).await?;
        
        // Record successful login attempt
        let success_attempt = TestFixtures::successful_login_attempt(&created_user.email);
        test_db.instance.record_login_attempt(&success_attempt).await?;
        
        // Record failed login attempt
        let failed_attempt = TestFixtures::failed_login_attempt(&created_user.email, "Invalid password");
        test_db.instance.record_login_attempt(&failed_attempt).await?;
        
        // Record multiple failed attempts to test locking
        for i in 0..5 {
            let attempt = TestFixtures::failed_login_attempt(
                &created_user.email,
                &format!("Attempt {}", i + 1)
            );
            test_db.instance.record_login_attempt(&attempt).await?;
        }
        
        info!("MongoDB login attempts test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_mongodb_user_management_operations() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("mongodb").await?;
        
        info!("Testing MongoDB user management operations");
        
        let user = TestFixtures::complete_user();
        let created_user = test_db.instance.create_user(user).await?;
        
        if let Some(user_id) = &created_user.id {
            // Test password update
            let new_password_hash = "$2b$12$NEW_HASH_FOR_TESTING_PURPOSES";
            test_db.instance.update_password(user_id, new_password_hash).await?;
            
            // Test login attempts update
            test_db.instance.update_login_attempts(
                user_id,
                3,
                Some(chrono::Utc::now() + chrono::Duration::hours(1))
            ).await?;
            
            // Test last login update
            test_db.instance.update_last_login(user_id).await?;
            
            // Test user deactivation
            test_db.instance.deactivate_user(user_id).await?;
            
            // Verify user is deactivated
            let deactivated_user = test_db.instance.find_user_by_id(user_id).await?;
            if let Some(user) = deactivated_user {
                assert!(!user.is_active, "User should be deactivated");
            }
        }
        
        info!("MongoDB user management operations test completed successfully");
        Ok(())
    }

    #[tokio::test] 
    async fn test_mongodb_token_operations() -> Result<()> {
        init_test_environment().await?;
        let test_db = create_test_database("mongodb").await?;
        
        info!("Testing MongoDB token operations");
        
        let user = TestFixtures::minimal_user();
        let created_user = test_db.instance.create_user(user).await?;
        
        if let Some(user_id) = &created_user.id {
            // Test email verification token
            let verify_token = "test_verify_token_123";
            test_db.instance.set_email_verification_token(user_id, verify_token, 24).await?;
            
            let found_user = test_db.instance.get_user_by_verification_token(verify_token).await?;
            assert!(found_user.is_some());
            assert_eq!(found_user.unwrap().id, Some(user_id.clone()));
            
            // Test password reset token
            let reset_token = "test_reset_token_456";
            test_db.instance.set_password_reset_token(&created_user.email, reset_token, 1).await?;
            
            let found_by_reset = test_db.instance.get_user_by_reset_token(reset_token).await?;
            assert!(found_by_reset.is_some());
            assert_eq!(found_by_reset.unwrap().id, Some(user_id.clone()));
            
            // Test token verification
            let verified_user_id = test_db.instance.verify_email(verify_token).await?;
            assert_eq!(verified_user_id, *user_id);
            
            let reset_user_id = test_db.instance.verify_password_reset_token(reset_token).await?;
            assert_eq!(reset_user_id, *user_id);
            
            // Test token cleanup
            test_db.instance.clear_password_reset_token(user_id).await?;
        }
        
        info!("MongoDB token operations test completed successfully");
        Ok(())
    }
}