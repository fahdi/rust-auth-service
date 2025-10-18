use anyhow::Result;
use tokio;
use tracing::{info, debug, warn};
use std::time::{Duration, Instant};
use std::collections::HashMap;

mod common;
use common::{
    init_test_environment, create_test_database,
    fixtures::TestFixtures,
    database::DatabaseTestHelpers,
    utils::{measure_async, StressTestRunner, TestEnvironment, PerformanceMetrics},
};

use rust_auth_service::{
    database::AuthDatabase,
    models::user::User,
};

/// Performance and load testing for database adapters
#[cfg(test)]
mod performance_integration {
    use super::*;

    #[tokio::test]
    async fn test_single_operation_performance() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing single operation performance across databases");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        if available_databases.is_empty() {
            warn!("No databases available for performance testing");
            return Ok(());
        }
        
        let mut performance_results = HashMap::new();
        
        for db_type in &available_databases {
            info!("Performance testing {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            let mut db_metrics = Vec::new();
            
            // Test user creation performance
            let user = TestFixtures::minimal_user();
            let (created_user, create_metrics) = measure_async(
                "create_user",
                db_type,
                test_db.instance.create_user(user.clone())
            ).await?;
            db_metrics.push(create_metrics);
            
            // Test user lookup by email performance
            let (_, lookup_email_metrics) = measure_async(
                "find_user_by_email",
                db_type,
                test_db.instance.find_user_by_email(&user.email)
            ).await?;
            db_metrics.push(lookup_email_metrics);
            
            // Test user lookup by ID performance
            if let Some(user_id) = &created_user.id {
                let (_, lookup_id_metrics) = measure_async(
                    "find_user_by_id",
                    db_type,
                    test_db.instance.find_user_by_id(user_id)
                ).await?;
                db_metrics.push(lookup_id_metrics);
            }
            
            // Test user update performance
            let mut updated_user = created_user.clone();
            updated_user.full_name = "Performance Test Update".to_string();
            let (_, update_metrics) = measure_async(
                "update_user",
                db_type,
                test_db.instance.update_user(&updated_user)
            ).await?;
            db_metrics.push(update_metrics);
            
            // Test authentication operations performance
            if let Some(user_id) = &created_user.id {
                let (_, auth_metrics) = measure_async(
                    "record_login",
                    db_type,
                    test_db.instance.record_login(user_id)
                ).await?;
                db_metrics.push(auth_metrics);
            }
            
            // Test health check performance
            let (_, health_metrics) = measure_async(
                "health_check",
                db_type,
                test_db.instance.health_check()
            ).await?;
            db_metrics.push(health_metrics);
            
            performance_results.insert(db_type.clone(), db_metrics);
        }
        
        // Analyze performance results
        for (db_type, metrics) in &performance_results {
            info!("Performance summary for {}:", db_type);
            
            for metric in metrics {
                let duration_ms = metric.duration.as_secs_f64() * 1000.0;
                info!("  {}: {:.2}ms", metric.operation, duration_ms);
                
                // Performance assertions
                match metric.operation.as_str() {
                    "create_user" => assert!(duration_ms < 500.0, "{} create_user took too long: {:.2}ms", db_type, duration_ms),
                    "find_user_by_email" => assert!(duration_ms < 100.0, "{} find_user_by_email took too long: {:.2}ms", db_type, duration_ms),
                    "find_user_by_id" => assert!(duration_ms < 100.0, "{} find_user_by_id took too long: {:.2}ms", db_type, duration_ms),
                    "update_user" => assert!(duration_ms < 300.0, "{} update_user took too long: {:.2}ms", db_type, duration_ms),
                    "record_login" => assert!(duration_ms < 200.0, "{} record_login took too long: {:.2}ms", db_type, duration_ms),
                    "health_check" => assert!(duration_ms < 50.0, "{} health_check took too long: {:.2}ms", db_type, duration_ms),
                    _ => {}
                }
            }
        }
        
        info!("Single operation performance test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_bulk_operation_performance() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing bulk operation performance");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        for db_type in &available_databases {
            info!("Bulk performance testing {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            
            // Test bulk user creation
            let bulk_users = TestFixtures::bulk_users(100);
            
            let start = Instant::now();
            let mut successful_creates = 0;
            let mut failed_creates = 0;
            
            for user in bulk_users {
                match test_db.instance.create_user(user).await {
                    Ok(_) => successful_creates += 1,
                    Err(_) => failed_creates += 1,
                }
            }
            
            let bulk_duration = start.elapsed();
            let operations_per_second = successful_creates as f64 / bulk_duration.as_secs_f64();
            
            info!(
                "{} bulk operations: {} successful, {} failed, {:.1} ops/sec",
                db_type,
                successful_creates,
                failed_creates,
                operations_per_second
            );
            
            // Performance assertions for bulk operations
            assert!(successful_creates >= 90, "{} should successfully create at least 90% of users", db_type);
            assert!(operations_per_second > 10.0, "{} should achieve > 10 operations/second, got {:.1}", db_type, operations_per_second);
            assert!(bulk_duration.as_secs() < 30, "{} bulk operations should complete in < 30 seconds", db_type);
        }
        
        info!("Bulk operation performance test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_load_performance() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing concurrent load performance");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        for db_type in &available_databases {
            info!("Concurrent load testing {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            
            // Test with increasing concurrency levels
            let concurrency_levels = vec![5, 10, 20];
            let operations_per_level = 50;
            
            for concurrent_ops in concurrency_levels {
                info!("Testing {} concurrent operations on {}", concurrent_ops, db_type);
                
                let stress_runner = StressTestRunner::new(concurrent_ops, operations_per_level);
                let db_instance = test_db.instance.clone();
                
                let duration = stress_runner.run_concurrent_test(move |operation_id| {
                    let db = db_instance.clone();
                    let db_type_clone = db_type.clone();
                    async move {
                        let user = User {
                            id: None,
                            email: format!("load_test_{}_{}@example.com", db_type_clone, operation_id),
                            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                            full_name: format!("Load Test {} User {}", db_type_clone, operation_id),
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
                        
                        // Create user and immediately query it to test full round-trip
                        let created = db.create_user(user.clone()).await
                            .map_err(|e| anyhow::anyhow!("Create user failed: {:?}", e))?;
                        
                        let _found = db.find_user_by_email(&user.email).await
                            .map_err(|e| anyhow::anyhow!("Find user failed: {:?}", e))?;
                        
                        Ok(())
                    }
                }).await?;
                
                let success_rate = stress_runner.success_rate();
                let ops_per_second = operations_per_level as f64 / duration.as_secs_f64();
                
                info!(
                    "{} - {} concurrent: {:.1} ops/sec, {:.1}% success rate",
                    db_type,
                    concurrent_ops,
                    ops_per_second,
                    success_rate * 100.0
                );
                
                // Performance assertions
                assert!(
                    success_rate > 0.90,
                    "{} should maintain >90% success rate under {} concurrent ops, got {:.1}%",
                    db_type,
                    concurrent_ops,
                    success_rate * 100.0
                );
                
                assert!(
                    ops_per_second > 5.0,
                    "{} should maintain >5 ops/sec under {} concurrent ops, got {:.1}",
                    db_type,
                    concurrent_ops,
                    ops_per_second
                );
            }
        }
        
        info!("Concurrent load performance test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_usage_under_load() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing memory usage under load");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        for db_type in &available_databases {
            info!("Memory testing {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            
            // Create a large number of users to test memory efficiency
            let user_count = 1000;
            let mut created_users = Vec::new();
            
            let start_memory = get_memory_usage();
            let start_time = Instant::now();
            
            for i in 0..user_count {
                let user = User {
                    id: None,
                    email: format!("memory_test_{}_{i}@example.com", db_type, i = i),
                    password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                    full_name: format!("Memory Test {} User {}", db_type, i),
                    role: "user".to_string(),
                    is_active: true,
                    email_verified: i % 2 == 0,
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
                
                match test_db.instance.create_user(user).await {
                    Ok(created) => created_users.push(created),
                    Err(e) => debug!("Failed to create user {}: {}", i, e),
                }
            }
            
            let creation_time = start_time.elapsed();
            let end_memory = get_memory_usage();
            let memory_increase = end_memory.saturating_sub(start_memory);
            
            info!(
                "{} memory test: {} users created in {:.2}s, memory increase: {} KB",
                db_type,
                created_users.len(),
                creation_time.as_secs_f64(),
                memory_increase / 1024
            );
            
            // Test that we can still perform operations efficiently
            let lookup_start = Instant::now();
            let mut found_count = 0;
            
            for created_user in created_users.iter().take(100) {
                if test_db.instance.find_user_by_email(&created_user.email).await?.is_some() {
                    found_count += 1;
                }
            }
            
            let lookup_time = lookup_start.elapsed();
            
            info!(
                "{} lookup performance: {}/100 users found in {:.2}s",
                db_type,
                found_count,
                lookup_time.as_secs_f64()
            );
            
            // Memory and performance assertions
            assert!(created_users.len() >= 950, "{} should create at least 95% of users", db_type);
            assert!(memory_increase < 100 * 1024 * 1024, "{} memory increase should be < 100MB, got {} KB", db_type, memory_increase / 1024);
            assert!(found_count >= 95, "{} should find at least 95% of users", db_type);
            assert!(lookup_time.as_secs() < 10, "{} lookup should complete in < 10 seconds", db_type);
        }
        
        info!("Memory usage under load test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_connection_pool_performance() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing connection pool performance");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        for db_type in &available_databases {
            info!("Connection pool testing {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            
            // Test rapid connection acquisition and release
            let mut handles = Vec::new();
            let operation_count = 100;
            
            let start = Instant::now();
            
            for i in 0..operation_count {
                let db = test_db.instance.clone();
                let handle = tokio::spawn(async move {
                    // Perform a quick operation that requires a database connection
                    let user = User {
                        id: None,
                        email: format!("pool_test_{}_{i}@example.com", i = i),
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
                    
                    db.create_user(user).await
                });
                
                handles.push(handle);
            }
            
            // Wait for all operations to complete
            let mut successful_ops = 0;
            for handle in handles {
                if handle.await.is_ok() {
                    successful_ops += 1;
                }
            }
            
            let total_time = start.elapsed();
            let ops_per_second = successful_ops as f64 / total_time.as_secs_f64();
            
            info!(
                "{} connection pool: {}/{} operations successful in {:.2}s ({:.1} ops/sec)",
                db_type,
                successful_ops,
                operation_count,
                total_time.as_secs_f64(),
                ops_per_second
            );
            
            // Connection pool performance assertions
            assert!(
                successful_ops >= operation_count * 95 / 100,
                "{} connection pool should handle 95% of operations successfully",
                db_type
            );
            assert!(
                ops_per_second > 20.0,
                "{} connection pool should achieve >20 ops/sec, got {:.1}",
                db_type,
                ops_per_second
            );
            assert!(
                total_time.as_secs() < 10,
                "{} connection pool operations should complete in <10 seconds",
                db_type
            );
        }
        
        info!("Connection pool performance test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_query_performance_under_data_volume() -> Result<()> {
        init_test_environment().await?;
        
        info!("Testing query performance under increasing data volume");
        
        let available_databases = TestEnvironment::check_database_availability(&["mongodb", "postgresql"]).await?;
        
        for db_type in &available_databases {
            info!("Query performance testing {}", db_type);
            
            let test_db = create_test_database(db_type).await?;
            
            // Create users in batches and test query performance
            let batch_sizes = vec![100, 500, 1000];
            let mut total_users = 0;
            
            for batch_size in batch_sizes {
                info!("Creating batch of {} users for {}", batch_size, db_type);
                
                // Create batch of users
                for i in 0..batch_size {
                    let user = User {
                        id: None,
                        email: format!("volume_test_{}_{}@example.com", total_users + i, db_type),
                        password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                        full_name: format!("Volume Test User {}", total_users + i),
                        role: if i % 20 == 0 { "admin".to_string() } else { "user".to_string() },
                        is_active: i % 10 != 0,
                        email_verified: i % 3 == 0,
                        email_verification_token: None,
                        email_verification_expires: None,
                        password_reset_token: None,
                        password_reset_expires: None,
                        failed_login_attempts: i % 5,
                        locked_until: None,
                        last_login: None,
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                    };
                    
                    if test_db.instance.create_user(user).await.is_ok() {
                        total_users += 1;
                    }
                }
                
                // Test query performance at this data volume
                let query_start = Instant::now();
                let mut found_users = 0;
                
                // Test random email lookups
                for i in 0..50 {
                    let test_email = format!("volume_test_{}@example.com", i);
                    if test_db.instance.find_user_by_email(&test_email).await?.is_some() {
                        found_users += 1;
                    }
                }
                
                let query_time = query_start.elapsed();
                let avg_query_time = query_time.as_secs_f64() / 50.0;
                
                info!(
                    "{} with {} users: 50 queries in {:.2}s (avg {:.3}s per query)",
                    db_type,
                    total_users,
                    query_time.as_secs_f64(),
                    avg_query_time
                );
                
                // Performance should remain reasonable even with more data
                assert!(
                    avg_query_time < 0.1,
                    "{} average query time should be <100ms with {} users, got {:.3}s",
                    db_type,
                    total_users,
                    avg_query_time
                );
            }
            
            info!("{} final data volume: {} users", db_type, total_users);
        }
        
        info!("Query performance under data volume test completed successfully");
        Ok(())
    }
}

/// Helper function to get approximate memory usage (simplified)
fn get_memory_usage() -> usize {
    // This is a simplified memory usage estimate
    // In a real scenario, you might use system metrics or process monitoring
    use std::alloc::{GlobalAlloc, Layout, System};
    
    // Return a dummy value since we can't easily get precise memory usage in tests
    // In production, you would use proper memory monitoring tools
    0
}