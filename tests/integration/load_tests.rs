//! # Load Testing Integration Tests
//!
//! Comprehensive load testing for authentication service endpoints.
//! Tests performance under load, concurrent operations, stress scenarios, and scalability limits.

use anyhow::Result;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use crate::helpers::*;
use crate::integration::test_framework::*;

/// Basic load test for authentication endpoints
#[tokio::test]
async fn test_basic_authentication_load() -> Result<()> {
    let framework = IntegrationTestFramework::new();

    if !framework.is_service_running().await? {
        println!(
            "⚠️ Auth service not running. Start it with: cargo run --features integration-tests"
        );
        return Ok(());
    }

    println!("🚀 Running basic authentication load test");

    let config = LoadTestConfig {
        concurrent_users: 20,
        operations_per_user: 5,
        delay_between_operations: Duration::from_millis(100),
        timeout: Duration::from_secs(60),
    };

    let results = framework.run_load_test(config).await?;
    results.print_summary("Basic Authentication Load");

    // Assert minimum performance requirements
    assert!(
        results.operations_per_second > 10.0,
        "Should handle at least 10 operations per second, got {:.2}",
        results.operations_per_second
    );

    assert!(
        results.successful_operations as f64 / results.total_operations as f64 > 0.90,
        "Should have >90% success rate, got {:.1}%",
        (results.successful_operations as f64 / results.total_operations as f64) * 100.0
    );

    assert!(
        results.average_response_time < Duration::from_millis(1000),
        "Average response time should be <1000ms, got {}ms",
        results.average_response_time.as_millis()
    );

    println!("✅ Basic load test passed");
    Ok(())
}

/// Stress test with high concurrency
#[tokio::test]
async fn test_high_concurrency_stress() -> Result<()> {
    let framework = IntegrationTestFramework::new();

    if !framework.is_service_running().await? {
        println!(
            "⚠️ Auth service not running. Start it with: cargo run --features integration-tests"
        );
        return Ok(());
    }

    println!("🔥 Running high concurrency stress test");

    const HIGH_CONCURRENCY: usize = 100;
    const OPERATIONS_PER_USER: usize = 3;

    let start_time = Instant::now();
    let mut handles = Vec::new();
    let semaphore = Arc::new(Semaphore::new(HIGH_CONCURRENCY));

    // Create users concurrently
    for i in 0..HIGH_CONCURRENCY {
        let client = framework.client.clone();
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        let handle = tokio::spawn(async move {
            let _permit = permit; // Hold permit for duration of task
            let mut user_results = Vec::new();
            let user = TestUser::new(&format!("stress_test_{}", i));

            for j in 0..OPERATIONS_PER_USER {
                let operation_start = Instant::now();
                let operation_name = format!("User {} Operation {}", i, j);

                let result = match j {
                    0 => {
                        // Registration
                        let result = client.register(&user).await;
                        (
                            operation_name,
                            "register".to_string(),
                            result.is_ok(),
                            operation_start.elapsed(),
                        )
                    }
                    1 => {
                        // Login
                        let result = client.login(&user).await;
                        (
                            operation_name,
                            "login".to_string(),
                            result.is_ok(),
                            operation_start.elapsed(),
                        )
                    }
                    2 => {
                        // Get profile (need token from login)
                        let login_result = client.login(&user).await;
                        if let Ok((tokens, _)) = login_result {
                            let profile_result = client.get_profile(&tokens.access_token).await;
                            (
                                operation_name,
                                "profile".to_string(),
                                profile_result.is_ok(),
                                operation_start.elapsed(),
                            )
                        } else {
                            (
                                operation_name,
                                "profile".to_string(),
                                false,
                                operation_start.elapsed(),
                            )
                        }
                    }
                    _ => (
                        operation_name,
                        "unknown".to_string(),
                        false,
                        operation_start.elapsed(),
                    ),
                };

                user_results.push(result);

                // Small delay between operations
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            user_results
        });

        handles.push(handle);
    }

    // Collect results
    let mut all_results = Vec::new();
    let mut successful_operations = 0;
    let mut failed_operations = 0;
    let mut total_response_time = Duration::from_secs(0);

    for handle in handles {
        match handle.await {
            Ok(user_results) => {
                for (_, _, success, response_time) in user_results {
                    if success {
                        successful_operations += 1;
                    } else {
                        failed_operations += 1;
                    }
                    total_response_time += response_time;
                    all_results.push(response_time);
                }
            }
            Err(e) => {
                println!("Task error: {}", e);
                failed_operations += OPERATIONS_PER_USER;
            }
        }
    }

    let total_duration = start_time.elapsed();
    let total_operations = successful_operations + failed_operations;
    let average_response_time = if !all_results.is_empty() {
        all_results.iter().sum::<Duration>() / all_results.len() as u32
    } else {
        Duration::from_secs(0)
    };
    let operations_per_second = successful_operations as f64 / total_duration.as_secs_f64();

    println!("📊 High Concurrency Stress Test Results:");
    println!("  Concurrent Users: {}", HIGH_CONCURRENCY);
    println!("  Operations per User: {}", OPERATIONS_PER_USER);
    println!("  Total Operations: {}", total_operations);
    println!(
        "  Successful: {} ({:.1}%)",
        successful_operations,
        (successful_operations as f64 / total_operations as f64) * 100.0
    );
    println!(
        "  Failed: {} ({:.1}%)",
        failed_operations,
        (failed_operations as f64 / total_operations as f64) * 100.0
    );
    println!("  Total Duration: {:.2}s", total_duration.as_secs_f64());
    println!(
        "  Average Response Time: {:.2}ms",
        average_response_time.as_millis()
    );
    println!("  Operations/Second: {:.2}", operations_per_second);

    // Performance assertions for stress test
    assert!(
        successful_operations as f64 / total_operations as f64 > 0.80,
        "Should have >80% success rate under stress, got {:.1}%",
        (successful_operations as f64 / total_operations as f64) * 100.0
    );

    assert!(
        operations_per_second > 5.0,
        "Should handle at least 5 operations per second under stress, got {:.2}",
        operations_per_second
    );

    println!("✅ High concurrency stress test passed");
    Ok(())
}

/// Load test focusing on registration endpoint
#[tokio::test]
async fn test_registration_endpoint_load() -> Result<()> {
    let framework = IntegrationTestFramework::new();

    if !framework.is_service_running().await? {
        println!(
            "⚠️ Auth service not running. Start it with: cargo run --features integration-tests"
        );
        return Ok(());
    }

    println!("📝 Running registration endpoint load test");

    const REGISTRATIONS: usize = 50;
    let start_time = Instant::now();
    let mut handles = Vec::new();

    for i in 0..REGISTRATIONS {
        let client = framework.client.clone();

        let handle = tokio::spawn(async move {
            let user = TestUser::new(&format!("reg_load_test_{}", i));
            let timer = PerformanceTimer::new(&format!("Registration {}", i));

            let result = client.register(&user).await;
            let elapsed = timer.finish();

            (i, result.is_ok(), elapsed, user.email)
        });

        handles.push(handle);
    }

    let mut successful = 0;
    let mut failed = 0;
    let mut response_times = Vec::new();
    let mut registered_emails = Vec::new();

    for handle in handles {
        match handle.await {
            Ok((_, true, elapsed, email)) => {
                successful += 1;
                response_times.push(elapsed);
                registered_emails.push(email);
            }
            Ok((_, false, elapsed, _)) => {
                failed += 1;
                response_times.push(elapsed);
            }
            Err(e) => {
                failed += 1;
                println!("Registration task error: {}", e);
            }
        }
    }

    let total_duration = start_time.elapsed();
    let avg_response_time = if !response_times.is_empty() {
        response_times.iter().sum::<Duration>() / response_times.len() as u32
    } else {
        Duration::from_secs(0)
    };
    let registrations_per_second = successful as f64 / total_duration.as_secs_f64();

    println!("📊 Registration Load Test Results:");
    println!("  Total Registrations: {}", REGISTRATIONS);
    println!(
        "  Successful: {} ({:.1}%)",
        successful,
        (successful as f64 / REGISTRATIONS as f64) * 100.0
    );
    println!(
        "  Failed: {} ({:.1}%)",
        failed,
        (failed as f64 / REGISTRATIONS as f64) * 100.0
    );
    println!("  Total Duration: {:.2}s", total_duration.as_secs_f64());
    println!(
        "  Average Response Time: {:.2}ms",
        avg_response_time.as_millis()
    );
    println!("  Registrations/Second: {:.2}", registrations_per_second);

    // Verify all successful registrations created unique users
    let unique_emails: std::collections::HashSet<_> = registered_emails.iter().collect();
    assert_eq!(
        unique_emails.len(),
        registered_emails.len(),
        "All registrations should be unique"
    );
    println!(
        "✅ All {} registrations were unique",
        registered_emails.len()
    );

    // Performance assertions
    assert!(
        successful as f64 / REGISTRATIONS as f64 > 0.90,
        "Should have >90% registration success rate, got {:.1}%",
        (successful as f64 / REGISTRATIONS as f64) * 100.0
    );

    assert!(
        avg_response_time < Duration::from_millis(2000),
        "Average registration time should be <2000ms, got {}ms",
        avg_response_time.as_millis()
    );

    println!("✅ Registration load test passed");
    Ok(())
}

/// Load test focusing on login endpoint
#[tokio::test]
async fn test_login_endpoint_load() -> Result<()> {
    let framework = IntegrationTestFramework::new();

    if !framework.is_service_running().await? {
        println!(
            "⚠️ Auth service not running. Start it with: cargo run --features integration-tests"
        );
        return Ok(());
    }

    println!("🔑 Running login endpoint load test");

    // First, create users for login testing
    const USERS_TO_CREATE: usize = 30;
    const LOGINS_PER_USER: usize = 3;

    println!(
        "📝 Creating {} test users for login load test...",
        USERS_TO_CREATE
    );
    let mut test_users = Vec::new();

    for i in 0..USERS_TO_CREATE {
        let user = TestUser::new(&format!("login_load_test_{}", i));
        let (_, _) = framework.client.register(&user).await?;
        test_users.push(user);
    }

    println!(
        "✅ Created {} test users, starting login load test",
        test_users.len()
    );

    // Now perform concurrent logins
    let start_time = Instant::now();
    let mut handles = Vec::new();

    for (user_idx, user) in test_users.iter().enumerate() {
        for login_idx in 0..LOGINS_PER_USER {
            let client = framework.client.clone();
            let user = user.clone();

            let handle = tokio::spawn(async move {
                let operation_id = format!("User {} Login {}", user_idx, login_idx);
                let timer = PerformanceTimer::new(&operation_id);

                let result = client.login(&user).await;
                let elapsed = timer.finish();

                match result {
                    Ok((tokens, _)) => {
                        // Verify token is valid by accessing profile
                        let profile_result = client.get_profile(&tokens.access_token).await;
                        (operation_id, true, elapsed, profile_result.is_ok())
                    }
                    Err(_) => (operation_id, false, elapsed, false),
                }
            });

            handles.push(handle);
        }
    }

    let mut successful_logins = 0;
    let mut failed_logins = 0;
    let mut successful_profile_access = 0;
    let mut response_times = Vec::new();

    for handle in handles {
        match handle.await {
            Ok((_, true, elapsed, profile_success)) => {
                successful_logins += 1;
                response_times.push(elapsed);
                if profile_success {
                    successful_profile_access += 1;
                }
            }
            Ok((_, false, elapsed, _)) => {
                failed_logins += 1;
                response_times.push(elapsed);
            }
            Err(e) => {
                failed_logins += 1;
                println!("Login task error: {}", e);
            }
        }
    }

    let total_duration = start_time.elapsed();
    let total_logins = successful_logins + failed_logins;
    let avg_response_time = if !response_times.is_empty() {
        response_times.iter().sum::<Duration>() / response_times.len() as u32
    } else {
        Duration::from_secs(0)
    };
    let logins_per_second = successful_logins as f64 / total_duration.as_secs_f64();

    println!("📊 Login Load Test Results:");
    println!("  Total Login Attempts: {}", total_logins);
    println!(
        "  Successful Logins: {} ({:.1}%)",
        successful_logins,
        (successful_logins as f64 / total_logins as f64) * 100.0
    );
    println!(
        "  Failed Logins: {} ({:.1}%)",
        failed_logins,
        (failed_logins as f64 / total_logins as f64) * 100.0
    );
    println!(
        "  Successful Profile Access: {} ({:.1}%)",
        successful_profile_access,
        (successful_profile_access as f64 / successful_logins as f64) * 100.0
    );
    println!("  Total Duration: {:.2}s", total_duration.as_secs_f64());
    println!(
        "  Average Response Time: {:.2}ms",
        avg_response_time.as_millis()
    );
    println!("  Logins/Second: {:.2}", logins_per_second);

    // Performance assertions
    assert!(
        successful_logins as f64 / total_logins as f64 > 0.95,
        "Should have >95% login success rate, got {:.1}%",
        (successful_logins as f64 / total_logins as f64) * 100.0
    );

    assert!(
        successful_profile_access as f64 / successful_logins as f64 > 0.95,
        "Should have >95% profile access success rate, got {:.1}%",
        (successful_profile_access as f64 / successful_logins as f64) * 100.0
    );

    assert!(
        avg_response_time < Duration::from_millis(1500),
        "Average login time should be <1500ms, got {}ms",
        avg_response_time.as_millis()
    );

    println!("✅ Login load test passed");
    Ok(())
}

/// Mixed workload test (registration, login, profile access)
#[tokio::test]
async fn test_mixed_workload() -> Result<()> {
    let framework = IntegrationTestFramework::new();

    if !framework.is_service_running().await? {
        println!(
            "⚠️ Auth service not running. Start it with: cargo run --features integration-tests"
        );
        return Ok(());
    }

    println!("🔄 Running mixed workload test");

    const CONCURRENT_OPERATIONS: usize = 60;
    let start_time = Instant::now();
    let mut handles = Vec::new();

    for i in 0..CONCURRENT_OPERATIONS {
        let client = framework.client.clone();

        let handle = tokio::spawn(async move {
            let operation_type = i % 4; // Distribute operations
            let user_id = format!("mixed_workload_{}", i);

            match operation_type {
                0 => {
                    // New user registration
                    let user = TestUser::new(&format!("new_{}", user_id));
                    let timer = PerformanceTimer::new(&format!("Register {}", i));
                    let result = client.register(&user).await;
                    let elapsed = timer.finish();
                    ("register".to_string(), result.is_ok(), elapsed)
                }
                1 => {
                    // User registration + login
                    let user = TestUser::new(&format!("reg_login_{}", user_id));
                    let timer = PerformanceTimer::new(&format!("Register+Login {}", i));

                    let register_result = client.register(&user).await;
                    if register_result.is_ok() {
                        let login_result = client.login(&user).await;
                        let elapsed = timer.finish();
                        ("register+login".to_string(), login_result.is_ok(), elapsed)
                    } else {
                        let elapsed = timer.finish();
                        ("register+login".to_string(), false, elapsed)
                    }
                }
                2 => {
                    // User registration + profile access
                    let user = TestUser::new(&format!("reg_profile_{}", user_id));
                    let timer = PerformanceTimer::new(&format!("Register+Profile {}", i));

                    let register_result = client.register(&user).await;
                    if let Ok((tokens, _)) = register_result {
                        let profile_result = client.get_profile(&tokens.access_token).await;
                        let elapsed = timer.finish();
                        (
                            "register+profile".to_string(),
                            profile_result.is_ok(),
                            elapsed,
                        )
                    } else {
                        let elapsed = timer.finish();
                        ("register+profile".to_string(), false, elapsed)
                    }
                }
                3 => {
                    // Full flow: register + login + profile + logout
                    let user = TestUser::new(&format!("full_flow_{}", user_id));
                    let timer = PerformanceTimer::new(&format!("Full Flow {}", i));

                    let register_result = client.register(&user).await;
                    if register_result.is_ok() {
                        let login_result = client.login(&user).await;
                        if let Ok((tokens, _)) = login_result {
                            let profile_result = client.get_profile(&tokens.access_token).await;
                            if profile_result.is_ok() {
                                let logout_result = client.logout(&tokens.access_token).await;
                                let elapsed = timer.finish();
                                ("full_flow".to_string(), logout_result.is_ok(), elapsed)
                            } else {
                                let elapsed = timer.finish();
                                ("full_flow".to_string(), false, elapsed)
                            }
                        } else {
                            let elapsed = timer.finish();
                            ("full_flow".to_string(), false, elapsed)
                        }
                    } else {
                        let elapsed = timer.finish();
                        ("full_flow".to_string(), false, elapsed)
                    }
                }
                _ => unreachable!(),
            }
        });

        handles.push(handle);
    }

    // Collect results by operation type
    let mut results = std::collections::HashMap::new();

    for handle in handles {
        match handle.await {
            Ok((operation_type, success, elapsed)) => {
                let entry = results
                    .entry(operation_type)
                    .or_insert_with(|| (0, 0, Vec::new()));
                if success {
                    entry.0 += 1;
                } else {
                    entry.1 += 1;
                }
                entry.2.push(elapsed);
            }
            Err(e) => {
                println!("Mixed workload task error: {}", e);
            }
        }
    }

    let total_duration = start_time.elapsed();
    let mut total_successful = 0;
    let mut total_failed = 0;
    let mut all_response_times = Vec::new();

    println!("📊 Mixed Workload Test Results:");

    for (operation_type, (successful, failed, response_times)) in results {
        let total = successful + failed;
        let avg_time = if !response_times.is_empty() {
            response_times.iter().sum::<Duration>() / response_times.len() as u32
        } else {
            Duration::from_secs(0)
        };

        println!("  {}:", operation_type);
        println!("    Total: {}", total);
        println!(
            "    Successful: {} ({:.1}%)",
            successful,
            (successful as f64 / total as f64) * 100.0
        );
        println!(
            "    Failed: {} ({:.1}%)",
            failed,
            (failed as f64 / total as f64) * 100.0
        );
        println!("    Average Time: {:.2}ms", avg_time.as_millis());

        total_successful += successful;
        total_failed += failed;
        all_response_times.extend(response_times);
    }

    let overall_avg_time = if !all_response_times.is_empty() {
        all_response_times.iter().sum::<Duration>() / all_response_times.len() as u32
    } else {
        Duration::from_secs(0)
    };
    let operations_per_second = total_successful as f64 / total_duration.as_secs_f64();

    println!("  Overall:");
    println!("    Total Operations: {}", total_successful + total_failed);
    println!(
        "    Successful: {} ({:.1}%)",
        total_successful,
        (total_successful as f64 / (total_successful + total_failed) as f64) * 100.0
    );
    println!(
        "    Failed: {} ({:.1}%)",
        total_failed,
        (total_failed as f64 / (total_successful + total_failed) as f64) * 100.0
    );
    println!("    Total Duration: {:.2}s", total_duration.as_secs_f64());
    println!(
        "    Average Response Time: {:.2}ms",
        overall_avg_time.as_millis()
    );
    println!("    Operations/Second: {:.2}", operations_per_second);

    // Performance assertions for mixed workload
    assert!(
        total_successful as f64 / (total_successful + total_failed) as f64 > 0.85,
        "Should have >85% success rate in mixed workload, got {:.1}%",
        (total_successful as f64 / (total_successful + total_failed) as f64) * 100.0
    );

    assert!(
        operations_per_second > 8.0,
        "Should handle at least 8 operations per second in mixed workload, got {:.2}",
        operations_per_second
    );

    println!("✅ Mixed workload test passed");
    Ok(())
}

/// Sustained load test (longer duration)
#[tokio::test]
async fn test_sustained_load() -> Result<()> {
    let framework = IntegrationTestFramework::new();

    if !framework.is_service_running().await? {
        println!(
            "⚠️ Auth service not running. Start it with: cargo run --features integration-tests"
        );
        return Ok(());
    }

    println!("⏳ Running sustained load test (2 minutes)");

    const CONCURRENT_USERS: usize = 15;
    const TEST_DURATION: Duration = Duration::from_secs(120); // 2 minutes
    const OPERATION_INTERVAL: Duration = Duration::from_millis(500);

    let start_time = Instant::now();
    let mut handles = Vec::new();

    for i in 0..CONCURRENT_USERS {
        let client = framework.client.clone();
        let end_time = start_time + TEST_DURATION;

        let handle = tokio::spawn(async move {
            let mut operations = 0;
            let mut successful = 0;
            let mut failed = 0;
            let mut response_times = Vec::new();

            while Instant::now() < end_time {
                let user = TestUser::new(&format!("sustained_{}_{}", i, operations));
                let operation_start = Instant::now();

                // Perform a complete auth flow
                let result = async {
                    let (tokens, _) = client.register(&user).await?;
                    let _ = client.get_profile(&tokens.access_token).await?;
                    let _ = client.logout(&tokens.access_token).await?;
                    anyhow::Ok(())
                }
                .await;

                let elapsed = operation_start.elapsed();
                response_times.push(elapsed);
                operations += 1;

                if result.is_ok() {
                    successful += 1;
                } else {
                    failed += 1;
                }

                // Report progress every 10 operations
                if operations % 10 == 0 {
                    let remaining = end_time.saturating_duration_since(Instant::now());
                    println!(
                        "User {}: {} operations, {:.1}s remaining",
                        i,
                        operations,
                        remaining.as_secs_f64()
                    );
                }

                // Wait before next operation (if we still have time)
                if Instant::now() + OPERATION_INTERVAL < end_time {
                    tokio::time::sleep(OPERATION_INTERVAL).await;
                }
            }

            (i, operations, successful, failed, response_times)
        });

        handles.push(handle);
    }

    // Collect results
    let mut total_operations = 0;
    let mut total_successful = 0;
    let mut total_failed = 0;
    let mut all_response_times = Vec::new();

    for handle in handles {
        match handle.await {
            Ok((user_id, operations, successful, failed, response_times)) => {
                println!(
                    "User {}: {} operations ({} successful, {} failed)",
                    user_id, operations, successful, failed
                );

                total_operations += operations;
                total_successful += successful;
                total_failed += failed;
                all_response_times.extend(response_times);
            }
            Err(e) => {
                println!("Sustained load task error: {}", e);
                total_failed += 1;
            }
        }
    }

    let actual_duration = start_time.elapsed();
    let avg_response_time = if !all_response_times.is_empty() {
        all_response_times.iter().sum::<Duration>() / all_response_times.len() as u32
    } else {
        Duration::from_secs(0)
    };
    let operations_per_second = total_successful as f64 / actual_duration.as_secs_f64();

    println!("📊 Sustained Load Test Results:");
    println!("  Test Duration: {:.2}s", actual_duration.as_secs_f64());
    println!("  Concurrent Users: {}", CONCURRENT_USERS);
    println!("  Total Operations: {}", total_operations);
    println!(
        "  Successful: {} ({:.1}%)",
        total_successful,
        (total_successful as f64 / total_operations as f64) * 100.0
    );
    println!(
        "  Failed: {} ({:.1}%)",
        total_failed,
        (total_failed as f64 / total_operations as f64) * 100.0
    );
    println!(
        "  Average Response Time: {:.2}ms",
        avg_response_time.as_millis()
    );
    println!("  Operations/Second: {:.2}", operations_per_second);

    // Calculate performance over time (stability check)
    if !all_response_times.is_empty() {
        let chunk_size = all_response_times.len() / 10; // Divide into 10 time periods
        if chunk_size > 0 {
            println!("  Performance over time:");
            for (i, chunk) in all_response_times.chunks(chunk_size).enumerate() {
                let avg_chunk_time = chunk.iter().sum::<Duration>() / chunk.len() as u32;
                println!(
                    "    Period {}: {:.2}ms average",
                    i + 1,
                    avg_chunk_time.as_millis()
                );
            }
        }
    }

    // Performance assertions for sustained load
    assert!(
        total_successful as f64 / total_operations as f64 > 0.90,
        "Should maintain >90% success rate during sustained load, got {:.1}%",
        (total_successful as f64 / total_operations as f64) * 100.0
    );

    assert!(
        operations_per_second > 3.0,
        "Should maintain at least 3 operations per second during sustained load, got {:.2}",
        operations_per_second
    );

    // Check that we actually ran for close to the expected duration
    assert!(
        actual_duration >= TEST_DURATION - Duration::from_secs(5),
        "Test should run for approximately the full duration"
    );

    println!("✅ Sustained load test passed");
    Ok(())
}

/// Memory and resource usage test
#[tokio::test]
async fn test_resource_usage_under_load() -> Result<()> {
    let framework = IntegrationTestFramework::new();

    if !framework.is_service_running().await? {
        println!(
            "⚠️ Auth service not running. Start it with: cargo run --features integration-tests"
        );
        return Ok(());
    }

    println!("💾 Running resource usage test under load");

    // Note: This test focuses on observing behavior rather than strict resource measurement
    // In a real production environment, you'd integrate with monitoring tools

    const USERS_TO_CREATE: usize = 100;
    let start_time = Instant::now();

    println!(
        "📈 Creating {} users to test resource usage...",
        USERS_TO_CREATE
    );

    // Create many users to test memory usage
    let mut handles = Vec::new();

    for i in 0..USERS_TO_CREATE {
        let client = framework.client.clone();

        let handle = tokio::spawn(async move {
            let user = TestUser::new(&format!("resource_test_{}", i));

            // Perform multiple operations per user
            let register_result = client.register(&user).await;
            if let Ok((tokens, _)) = register_result {
                let _ = client.get_profile(&tokens.access_token).await;
                let _ = client
                    .update_profile(
                        &tokens.access_token,
                        &json!({
                            "first_name": format!("Updated{}", i)
                        }),
                    )
                    .await;
                let _ = client.get_profile(&tokens.access_token).await;
                let _ = client.logout(&tokens.access_token).await;
                true
            } else {
                false
            }
        });

        handles.push(handle);

        // Pace the user creation to avoid overwhelming the system
        if i % 10 == 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // Wait for all operations to complete
    let mut successful_users = 0;
    let mut failed_users = 0;

    for handle in handles {
        match handle.await {
            Ok(true) => successful_users += 1,
            Ok(false) => failed_users += 1,
            Err(_) => failed_users += 1,
        }
    }

    let total_duration = start_time.elapsed();

    println!("📊 Resource Usage Test Results:");
    println!("  Users Created: {}", USERS_TO_CREATE);
    println!(
        "  Successful: {} ({:.1}%)",
        successful_users,
        (successful_users as f64 / USERS_TO_CREATE as f64) * 100.0
    );
    println!(
        "  Failed: {} ({:.1}%)",
        failed_users,
        (failed_users as f64 / USERS_TO_CREATE as f64) * 100.0
    );
    println!("  Total Duration: {:.2}s", total_duration.as_secs_f64());
    println!(
        "  Users/Second: {:.2}",
        successful_users as f64 / total_duration.as_secs_f64()
    );

    // Test that service is still responsive after creating many users
    println!("🔍 Testing service responsiveness after load...");
    let health_check_start = Instant::now();
    let health_result = framework.client.health_check().await;
    let health_check_time = health_check_start.elapsed();

    assert!(
        health_result.is_ok(),
        "Service should still be healthy after load test"
    );
    assert!(
        health_check_time < Duration::from_millis(5000),
        "Health check should be fast after load test, took {}ms",
        health_check_time.as_millis()
    );

    println!(
        "✅ Service remains responsive (health check: {:.2}ms)",
        health_check_time.as_millis()
    );

    // Test new user creation after load
    let new_user = TestUser::new("post_load_test");
    let new_user_start = Instant::now();
    let new_user_result = framework.client.register(&new_user).await;
    let new_user_time = new_user_start.elapsed();

    assert!(
        new_user_result.is_ok(),
        "Should be able to create new users after load test"
    );
    assert!(
        new_user_time < Duration::from_millis(3000),
        "New user creation should be fast after load test, took {}ms",
        new_user_time.as_millis()
    );

    println!(
        "✅ New user creation still works (time: {:.2}ms)",
        new_user_time.as_millis()
    );

    // Performance assertions
    assert!(
        successful_users as f64 / USERS_TO_CREATE as f64 > 0.85,
        "Should successfully create >85% of users under load, got {:.1}%",
        (successful_users as f64 / USERS_TO_CREATE as f64) * 100.0
    );

    println!("✅ Resource usage test passed");
    Ok(())
}
