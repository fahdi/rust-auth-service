use anyhow::Result;
use tokio;
use tracing::{info, debug, warn, error};
use std::path::Path;

mod common;
use common::{
    init_test_environment, create_test_database,
    fixtures::TestFixtures,
    database::DatabaseTestHelpers,
    utils::{measure_async, TestEnvironment},
};

use rust_auth_service::{
    config::{Config, DatabaseConfig},
    database::{create_database, AuthDatabase},
    models::user::User,
};

/// Database migration and schema evolution tests
#[cfg(test)]
mod migration_integration {
    use super::*;

    #[tokio::test]
    async fn test_database_initialization() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing database initialization process");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        for db_type in &available_databases {
            info!("Testing initialization for {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            
            // Test that initialization was successful
            let health = test_db.instance.health_check().await?;
            assert!(health.connected, "{} should be connected after initialization", db_type);
            
            // Test that basic operations work immediately after initialization
            let test_user = TestFixtures::minimal_user();
            let created_user = test_db.instance.create_user(test_user.clone()).await?;
            assert!(created_user.id.is_some(), "{} should create users after initialization", db_type);
            
            // Test that indexes/constraints are working
            let duplicate_result = test_db.instance.create_user(test_user).await;
            assert!(duplicate_result.is_err(), "{} should enforce unique constraints after initialization", db_type);
        }
        
        info!("Database initialization test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_mongodb_index_creation() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing MongoDB index creation and validation");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb"]).await?;
        if !available_databases.contains(&"mongodb".to_string()) {
            warn!("Skipping MongoDB index tests - MongoDB not available");
            return Ok(());
        }
        
        let test_db = create_test_database("mongodb").await?;
        
        // Test unique email constraint
        let user1 = TestFixtures::minimal_user();
        let user2 = user1.clone();
        
        test_db.instance.create_user(user1).await?;
        let duplicate_result = test_db.instance.create_user(user2).await;
        assert!(duplicate_result.is_err(), "MongoDB should enforce unique email index");
        
        // Test query performance with indexes (basic check)
        let start = std::time::Instant::now();
        let _found = test_db.instance.find_user_by_email("nonexistent@example.com").await?;
        let query_time = start.elapsed();
        
        assert!(
            query_time.as_millis() < 100,
            "MongoDB email lookup should be fast with index, took {}ms",
            query_time.as_millis()
        );
        
        info!("MongoDB index creation test completed successfully");
        Ok(())
    }

    #[cfg(feature = "postgresql")]
    #[tokio::test]
    async fn test_postgresql_schema_creation() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing PostgreSQL schema creation and constraints");
        
        let available_databases = TestEnvironment::check_database_availability(&["postgresql"]).await?;
        if !available_databases.contains(&"postgresql".to_string()) {
            warn!("Skipping PostgreSQL schema tests - PostgreSQL not available");
            return Ok(());
        }
        
        let test_db = create_test_database("postgresql").await?;
        
        // Test table constraints
        let user1 = TestFixtures::minimal_user();
        let user2 = user1.clone();
        
        test_db.instance.create_user(user1).await?;
        let duplicate_result = test_db.instance.create_user(user2).await;
        assert!(duplicate_result.is_err(), "PostgreSQL should enforce unique email constraint");
        
        // Test foreign key constraints (if applicable)
        // This would test relationships between users and other tables
        
        // Test data type constraints
        let edge_user = TestFixtures::edge_case_users()[0].clone();
        let result = test_db.instance.create_user(edge_user).await;
        // PostgreSQL should handle most edge cases gracefully
        match result {
            Ok(_) => debug!("PostgreSQL handled edge case user successfully"),
            Err(e) => debug!("PostgreSQL rejected edge case user: {}", e),
        }
        
        info!("PostgreSQL schema creation test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_migration_script_validation() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing migration script validation");
        
        // Check if migration files exist and are well-formed
        let migration_paths = vec![
            "migrations/mongodb",
            "migrations/postgresql",
        ];
        
        for migration_path in migration_paths {
            if Path::new(migration_path).exists() {
                info!("Validating migration scripts in {}", migration_path);
                
                // Check for required migration files
                let expected_files = vec![
                    "001_initial_schema",
                    "002_add_indexes",
                ];
                
                for expected_file in expected_files {
                    let file_extensions = match migration_path {
                        path if path.contains("mongodb") => vec![".js", ".json"],
                        path if path.contains("postgresql") => vec![".sql", ".up.sql"],
                        _ => vec![".sql"],
                    };
                    
                    let mut found = false;
                    for ext in file_extensions {
                        let full_path = format!("{}/{}{}", migration_path, expected_file, ext);
                        if Path::new(&full_path).exists() {
                            found = true;
                            debug!("Found migration file: {}", full_path);
                            break;
                        }
                    }
                    
                    if !found {
                        warn!("Migration file not found: {}/{}", migration_path, expected_file);
                    }
                }
            } else {
                debug!("Migration directory not found: {}", migration_path);
            }
        }
        
        info!("Migration script validation completed");
        Ok(())
    }

    #[tokio::test]
    async fn test_database_version_compatibility() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing database version compatibility");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        for db_type in &available_databases {
            info!("Testing version compatibility for {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            
            // Test that current schema version works
            let health = test_db.instance.health_check().await?;
            assert!(health.connected, "{} should connect with current schema", db_type);
            
            // Test basic operations to ensure schema is functional
            let test_user = TestFixtures::complete_user();
            let created_user = test_db.instance.create_user(test_user).await?;
            
            // Test all major operations work
            DatabaseTestHelpers::verify_user_creation(&test_db.instance, &created_user).await?;
            DatabaseTestHelpers::verify_authentication_flow(&test_db.instance, &created_user).await?;
            DatabaseTestHelpers::verify_email_verification_flow(&test_db.instance, &created_user).await?;
            DatabaseTestHelpers::verify_password_reset_flow(&test_db.instance, &created_user).await?;
        }
        
        info!("Database version compatibility test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_schema_evolution_compatibility() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing schema evolution and backward compatibility");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        for db_type in &available_databases {
            info!("Testing schema evolution for {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            
            // Create users with current schema
            let current_users = vec![
                TestFixtures::minimal_user(),
                TestFixtures::complete_user(),
            ];
            
            let mut created_users = Vec::new();
            for user in current_users {
                let created = test_db.instance.create_user(user).await?;
                created_users.push(created);
            }
            
            // Simulate schema evolution by testing with different field combinations
            // This tests that the schema can handle optional/nullable fields gracefully
            
            // Test reading users still works after "schema evolution"
            for created_user in &created_users {
                let found = test_db.instance.find_user_by_email(&created_user.email).await?;
                assert!(found.is_some(), "User should still be readable after schema evolution");
                
                if let Some(user_id) = &created_user.id {
                    let found_by_id = test_db.instance.find_user_by_id(user_id).await?;
                    assert!(found_by_id.is_some(), "User should be findable by ID after schema evolution");
                }
            }
            
            // Test that updates still work
            if let Some(user_to_update) = created_users.first() {
                let mut updated_user = user_to_update.clone();
                updated_user.full_name = "Schema Evolution Test".to_string();
                
                let result = test_db.instance.update_user(&updated_user).await;
                assert!(result.is_ok(), "User updates should work after schema evolution");
            }
        }
        
        info!("Schema evolution compatibility test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_data_integrity_during_operations() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing data integrity during database operations");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        for db_type in &available_databases {
            info!("Testing data integrity for {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            
            // Create a user with all fields populated
            let complete_user = TestFixtures::complete_user();
            let created_user = test_db.instance.create_user(complete_user.clone()).await?;
            
            // Verify all fields were preserved
            let retrieved_user = test_db.instance.find_user_by_email(&complete_user.email).await?;
            assert!(retrieved_user.is_some(), "User should be retrievable");
            
            let retrieved = retrieved_user.unwrap();
            
            // Check field integrity
            assert_eq!(retrieved.email, complete_user.email);
            assert_eq!(retrieved.password_hash, complete_user.password_hash);
            assert_eq!(retrieved.full_name, complete_user.full_name);
            assert_eq!(retrieved.role, complete_user.role);
            assert_eq!(retrieved.is_active, complete_user.is_active);
            assert_eq!(retrieved.email_verified, complete_user.email_verified);
            assert_eq!(retrieved.failed_login_attempts, complete_user.failed_login_attempts);
            
            // Test timestamp integrity (allowing for small differences due to database precision)
            let created_diff = (retrieved.created_at - complete_user.created_at).abs();
            assert!(
                created_diff <= chrono::Duration::seconds(5),
                "Created timestamp should be preserved within 5 seconds"
            );
            
            // Test optional field integrity
            assert_eq!(retrieved.email_verification_token, complete_user.email_verification_token);
            assert_eq!(retrieved.password_reset_token, complete_user.password_reset_token);
            
            // Test that NULL/None values are handled correctly
            let minimal_user = TestFixtures::minimal_user();
            let created_minimal = test_db.instance.create_user(minimal_user.clone()).await?;
            let retrieved_minimal = test_db.instance.find_user_by_email(&minimal_user.email).await?;
            
            assert!(retrieved_minimal.is_some());
            let minimal_retrieved = retrieved_minimal.unwrap();
            
            assert!(minimal_retrieved.email_verification_token.is_none());
            assert!(minimal_retrieved.password_reset_token.is_none());
            assert!(minimal_retrieved.last_login.is_none());
        }
        
        info!("Data integrity test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_schema_operations() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing concurrent schema operations");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        for db_type in &available_databases {
            info!("Testing concurrent operations for {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            
            // Create multiple users concurrently to test schema stability
            let mut handles = Vec::new();
            
            for i in 0..10 {
                let db = test_db.instance.clone();
                let handle = tokio::spawn(async move {
                    let user = User {
                        id: None,
                        email: format!("concurrent_schema_{}@example.com", i),
                        password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                        full_name: format!("Concurrent Schema User {}", i),
                        role: "user".to_string(),
                        is_active: true,
                        email_verified: i % 2 == 0,
                        email_verification_token: if i % 3 == 0 { Some(format!("token_{}", i)) } else { None },
                        email_verification_expires: if i % 3 == 0 { Some(chrono::Utc::now() + chrono::Duration::hours(24)) } else { None },
                        password_reset_token: None,
                        password_reset_expires: None,
                        failed_login_attempts: i % 5,
                        locked_until: if i % 7 == 0 { Some(chrono::Utc::now() + chrono::Duration::hours(1)) } else { None },
                        last_login: if i % 4 == 0 { Some(chrono::Utc::now() - chrono::Duration::hours(i as i64)) } else { None },
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                    };
                    
                    // Create user and immediately try to read it back
                    let created = db.create_user(user.clone()).await?;
                    let retrieved = db.find_user_by_email(&user.email).await?;
                    
                    Result::<bool>::Ok(retrieved.is_some() && retrieved.unwrap().email == user.email)
                });
                
                handles.push(handle);
            }
            
            // Wait for all operations and verify success
            let mut success_count = 0;
            for handle in handles {
                match handle.await {
                    Ok(Ok(true)) => success_count += 1,
                    Ok(Ok(false)) => warn!("Schema operation completed but validation failed"),
                    Ok(Err(e)) => warn!("Schema operation failed: {}", e),
                    Err(e) => error!("Task failed: {}", e),
                }
            }
            
            assert!(
                success_count >= 8,
                "At least 8 out of 10 concurrent schema operations should succeed for {}, got {}",
                db_type,
                success_count
            );
            
            info!("{} concurrent schema operations: {}/10 successful", db_type, success_count);
        }
        
        info!("Concurrent schema operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_database_recovery_after_errors() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing database recovery after error conditions");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        for db_type in &available_databases {
            info!("Testing error recovery for {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            
            // Cause some errors and verify the database continues to work
            
            // Error 1: Duplicate email
            let user1 = TestFixtures::minimal_user();
            let user2 = user1.clone();
            
            test_db.instance.create_user(user1).await?;
            let _duplicate_error = test_db.instance.create_user(user2).await;
            // Ignore the error, we expect it
            
            // Verify database still works after error
            let health_after_dup = test_db.instance.health_check().await?;
            assert!(health_after_dup.connected, "Database should remain connected after duplicate error");
            
            // Error 2: Invalid operations
            let _invalid_find = test_db.instance.find_user_by_id("definitely_invalid_id").await;
            // Ignore potential error
            
            let _invalid_token = test_db.instance.verify_email("invalid_token").await;
            // Ignore error
            
            // Verify database still works
            let test_user = TestFixtures::random_user();
            let created = test_db.instance.create_user(test_user).await?;
            assert!(created.id.is_some(), "Database should continue working after errors");
            
            // Final health check
            let final_health = test_db.instance.health_check().await?;
            assert!(final_health.connected, "Database should be healthy after error recovery test");
        }
        
        info!("Database recovery test completed successfully");
        Ok(())
    }
}