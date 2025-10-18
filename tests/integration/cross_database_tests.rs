use anyhow::Result;
use tokio;
use tracing::{info, debug, warn};
use std::collections::HashMap;

mod common;
use common::{
    init_test_environment, create_test_database,
    fixtures::TestFixtures,
    database::DatabaseTestHelpers,
    utils::{measure_async, ConsistencyChecker, StressTestRunner, TestEnvironment, PerformanceMetrics},
    assertions::{assert_user_equals, assert_user_error_type},
};

use rust_auth_service::{
    database::AuthDatabase,
    models::user::{User, UserError},
};

/// Cross-database consistency and compatibility tests
#[cfg(test)]
mod cross_database_integration {
    use super::*;

    #[tokio::test]
    async fn test_database_feature_parity() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing database feature parity across adapters");
        
        // Check which databases are available
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        if available_databases.len() < 2 {
            warn!("Skipping cross-database tests - need at least 2 databases, got: {:?}", available_databases);
            return Ok(());
        }
        
        let mut test_databases = HashMap::new();
        for db_type in &available_databases {
            let test_db = create_test_database(db_type).await?;
            test_databases.insert(db_type.clone(), test_db);
        }
        
        // Test basic CRUD operations across all databases
        let test_user = TestFixtures::minimal_user();
        let mut created_users = HashMap::new();
        
        for (db_type, test_db) in &test_databases {
            info!("Testing CRUD operations on {}", db_type);
            
            // Create user
            let created = test_db.instance.create_user(test_user.clone()).await?;
            assert!(created.id.is_some(), "{} should assign ID to created user", db_type);
            created_users.insert(db_type.clone(), created.clone());
            
            // Read user by email
            let found_by_email = test_db.instance.find_user_by_email(&test_user.email).await?;
            assert!(found_by_email.is_some(), "{} should find user by email", db_type);
            
            // Read user by ID
            if let Some(user_id) = &created.id {
                let found_by_id = test_db.instance.find_user_by_id(user_id).await?;
                assert!(found_by_id.is_some(), "{} should find user by ID", db_type);
            }
            
            // Update user
            let mut updated_user = created.clone();
            updated_user.full_name = format!("Updated {}", db_type);
            let updated = test_db.instance.update_user(&updated_user).await?;
            assert_eq!(updated.full_name, format!("Updated {}", db_type));
            
            // Health check
            let health = test_db.instance.health_check().await?;
            assert!(health.connected, "{} health check should pass", db_type);
        }
        
        info!("Database feature parity test completed successfully for: {:?}", available_databases);
        Ok(())
    }

    #[tokio::test]
    async fn test_cross_database_data_consistency() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing cross-database data consistency");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        if available_databases.len() < 2 {
            warn!("Skipping consistency tests - need at least 2 databases");
            return Ok(());
        }
        
        let mut test_databases = HashMap::new();
        for db_type in &available_databases {
            let test_db = create_test_database(db_type).await?;
            test_databases.insert(db_type.clone(), test_db);
        }
        
        // Create the same user in all databases
        let test_user = TestFixtures::complete_user();
        let mut created_users = HashMap::new();
        
        for (db_type, test_db) in &test_databases {
            let created = test_db.instance.create_user(test_user.clone()).await?;
            created_users.insert(db_type.clone(), created);
        }
        
        // Verify consistency using ConsistencyChecker
        let database_refs: Vec<(&str, &dyn AuthDatabase)> = test_databases
            .iter()
            .map(|(name, test_db)| (name.as_str(), test_db.instance.as_ref()))
            .collect();
        
        ConsistencyChecker::check_user_consistency(&database_refs, &test_user.email).await?;
        
        info!("Cross-database data consistency test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_authentication_flow_consistency() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing authentication flow consistency across databases");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        if available_databases.is_empty() {
            warn!("No databases available for authentication flow testing");
            return Ok(());
        }
        
        let mut test_databases = HashMap::new();
        for db_type in &available_databases {
            let test_db = create_test_database(db_type).await?;
            test_databases.insert(db_type.clone(), test_db);
        }
        
        // Test complete authentication flows
        for (db_type, test_db) in &test_databases {
            info!("Testing authentication flow on {}", db_type);
            
            let user = TestFixtures::complete_user();
            let created_user = test_db.instance.create_user(user).await?;
            
            // Test all authentication operations
            DatabaseTestHelpers::verify_authentication_flow(&test_db.instance, &created_user).await?;
            DatabaseTestHelpers::verify_email_verification_flow(&test_db.instance, &created_user).await?;
            DatabaseTestHelpers::verify_password_reset_flow(&test_db.instance, &created_user).await?;
        }
        
        info!("Authentication flow consistency test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_error_handling_consistency() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing error handling consistency across databases");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        if available_databases.is_empty() {
            warn!("No databases available for error handling testing");
            return Ok(());
        }
        
        let mut test_databases = HashMap::new();
        for db_type in &available_databases {
            let test_db = create_test_database(db_type).await?;
            test_databases.insert(db_type.clone(), test_db);
        }
        
        for (db_type, test_db) in &test_databases {
            info!("Testing error handling on {}", db_type);
            
            // Test duplicate email error
            let user1 = TestFixtures::minimal_user();
            let user2 = user1.clone();
            
            test_db.instance.create_user(user1).await?;
            let duplicate_result = test_db.instance.create_user(user2).await;
            assert!(duplicate_result.is_err(), "{} should prevent duplicate emails", db_type);
            
            // Test not found errors
            let not_found = test_db.instance.find_user_by_email("nonexistent@test.com").await?;
            assert!(not_found.is_none(), "{} should return None for non-existent users", db_type);
            
            // Test invalid token errors
            let invalid_token_result = test_db.instance.verify_email("invalid_token").await;
            assert!(invalid_token_result.is_err(), "{} should error on invalid tokens", db_type);
        }
        
        info!("Error handling consistency test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_performance_comparison() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing performance comparison across databases");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        if available_databases.is_empty() {
            warn!("No databases available for performance testing");
            return Ok(());
        }
        
        let mut test_databases = HashMap::new();
        for db_type in &available_databases {
            let test_db = create_test_database(db_type).await?;
            test_databases.insert(db_type.clone(), test_db);
        }
        
        let mut all_metrics = Vec::new();
        
        // Test each database with the same operations
        for (db_type, test_db) in &test_databases {
            info!("Performance testing {}", db_type);
            
            // User creation performance
            let user = TestFixtures::random_user();
            let (_, create_metrics) = measure_async(
                "create_user",
                db_type,
                test_db.instance.create_user(user.clone())
            ).await?;
            all_metrics.push(create_metrics);
            
            // User lookup performance
            let (_, lookup_metrics) = measure_async(
                "find_user_by_email",
                db_type,
                test_db.instance.find_user_by_email(&user.email)
            ).await?;
            all_metrics.push(lookup_metrics);
            
            // Health check performance
            let (_, health_metrics) = measure_async(
                "health_check",
                db_type,
                test_db.instance.health_check()
            ).await?;
            all_metrics.push(health_metrics);
        }
        
        // Generate performance report
        let report = TestEnvironment::generate_test_report(&available_databases, &all_metrics);
        info!("Performance Report:\n{}", report);
        
        // Basic performance assertions
        for metric in &all_metrics {
            assert!(
                metric.duration.as_millis() < 1000,
                "{} {} took too long: {}ms",
                metric.database_type,
                metric.operation,
                metric.duration.as_millis()
            );
        }
        
        info!("Performance comparison test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_operations_across_databases() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing concurrent operations across multiple databases");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        if available_databases.is_empty() {
            warn!("No databases available for concurrent testing");
            return Ok(());
        }
        
        let mut test_databases = HashMap::new();
        for db_type in &available_databases {
            let test_db = create_test_database(db_type).await?;
            test_databases.insert(db_type.clone(), test_db);
        }
        
        // Run concurrent operations on all databases simultaneously
        let mut handles = Vec::new();
        
        for (db_type, test_db) in test_databases {
            let handle = tokio::spawn(async move {
                let stress_runner = StressTestRunner::new(5, 50);
                let db_instance = test_db.instance.clone();
                
                stress_runner.run_concurrent_test(move |operation_id| {
                    let db = db_instance.clone();
                    let db_type_clone = db_type.clone();
                    async move {
                        let user = User {
                            id: None,
                            email: format!("cross_db_{}_{operation_id}@example.com", db_type_clone, operation_id = operation_id),
                            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                            full_name: format!("Cross DB {} User {}", db_type_clone, operation_id),
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
                }).await.map(|duration| (db_type, duration))
            });
            
            handles.push(handle);
        }
        
        // Wait for all database operations to complete
        let results = futures::future::join_all(handles).await;
        
        for result in results {
            match result {
                Ok(Ok((db_type, duration))) => {
                    info!("{} completed concurrent operations in {:.2}s", db_type, duration.as_secs_f64());
                }
                Ok(Err(e)) => {
                    warn!("Database operation failed: {}", e);
                }
                Err(e) => {
                    warn!("Task failed: {}", e);
                }
            }
        }
        
        info!("Concurrent operations across databases test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_data_migration_compatibility() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing data migration compatibility between databases");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        if available_databases.len() < 2 {
            warn!("Skipping migration compatibility tests - need at least 2 databases");
            return Ok(());
        }
        
        let mut test_databases = HashMap::new();
        for db_type in &available_databases {
            let test_db = create_test_database(db_type).await?;
            test_databases.insert(db_type.clone(), test_db);
        }
        
        // Create test data in the first database
        let source_db_type = &available_databases[0];
        let target_db_type = &available_databases[1];
        
        let source_db = &test_databases[source_db_type];
        let target_db = &test_databases[target_db_type];
        
        info!("Testing migration from {} to {}", source_db_type, target_db_type);
        
        // Create various types of users in source database
        let test_users = vec![
            TestFixtures::minimal_user(),
            TestFixtures::complete_user(),
            TestFixtures::admin_user(),
            TestFixtures::locked_user(),
        ];
        
        let mut created_users = Vec::new();
        for user in test_users {
            let created = source_db.instance.create_user(user).await?;
            created_users.push(created);
        }
        
        // "Migrate" data by creating equivalent users in target database
        for source_user in &created_users {
            // Create a new user with the same data (excluding ID which is database-specific)
            let migration_user = User {
                id: None, // Let target DB assign new ID
                email: format!("migrated_{}", source_user.email),
                password_hash: source_user.password_hash.clone(),
                full_name: source_user.full_name.clone(),
                role: source_user.role.clone(),
                is_active: source_user.is_active,
                email_verified: source_user.email_verified,
                email_verification_token: source_user.email_verification_token.clone(),
                email_verification_expires: source_user.email_verification_expires,
                password_reset_token: source_user.password_reset_token.clone(),
                password_reset_expires: source_user.password_reset_expires,
                failed_login_attempts: source_user.failed_login_attempts,
                locked_until: source_user.locked_until,
                last_login: source_user.last_login,
                created_at: source_user.created_at,
                updated_at: chrono::Utc::now(), // Update migration timestamp
            };
            
            let migrated_user = target_db.instance.create_user(migration_user).await?;
            
            // Verify migration preserved core data
            assert_eq!(migrated_user.password_hash, source_user.password_hash);
            assert_eq!(migrated_user.full_name, source_user.full_name);
            assert_eq!(migrated_user.role, source_user.role);
            assert_eq!(migrated_user.is_active, source_user.is_active);
            assert_eq!(migrated_user.email_verified, source_user.email_verified);
        }
        
        info!("Data migration compatibility test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_schema_compatibility() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing schema compatibility across databases");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        if available_databases.is_empty() {
            warn!("No databases available for schema testing");
            return Ok(());
        }
        
        let mut test_databases = HashMap::new();
        for db_type in &available_databases {
            let test_db = create_test_database(db_type).await?;
            test_databases.insert(db_type.clone(), test_db);
        }
        
        // Test that all databases can handle the same data structures
        let edge_case_users = TestFixtures::edge_case_users();
        
        for (db_type, test_db) in &test_databases {
            info!("Testing schema compatibility on {}", db_type);
            
            for (index, user) in edge_case_users.iter().enumerate() {
                // Modify email to be unique per database
                let mut test_user = user.clone();
                test_user.email = format!("{}_{}", db_type, user.email);
                
                match test_db.instance.create_user(test_user.clone()).await {
                    Ok(created) => {
                        debug!("{} successfully handled edge case user {}", db_type, index);
                        
                        // Verify the data round-trip
                        let retrieved = test_db.instance.find_user_by_email(&test_user.email).await?;
                        assert!(retrieved.is_some(), "{} should retrieve created user", db_type);
                        
                        let retrieved_user = retrieved.unwrap();
                        assert_eq!(retrieved_user.email, test_user.email);
                        assert_eq!(retrieved_user.full_name, test_user.full_name);
                    }
                    Err(e) => {
                        debug!("{} rejected edge case user {} (this may be expected): {}", db_type, index, e);
                    }
                }
            }
        }
        
        info!("Schema compatibility test completed successfully");
        Ok(())
    }
}