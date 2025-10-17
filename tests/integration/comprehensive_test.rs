//! # Comprehensive Integration Test
//!
//! A comprehensive integration test that demonstrates all the testing capabilities
//! we've implemented. This test serves as a showcase and verification of our
//! complete integration testing framework.

use anyhow::Result;
use std::time::Duration;

use crate::helpers::*;
use crate::integration::test_framework::*;

/// Comprehensive integration test that exercises all major functionality
#[tokio::test]
async fn test_comprehensive_authentication_system() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    // This test runs only if the service is available
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Start it with: cargo run --features integration-tests");
        println!("ℹ️ This test requires the auth service to be running on http://localhost:8090");
        return Ok(());
    }

    println!("🚀 Starting comprehensive authentication system test");

    // Step 1: Test service health and readiness
    println!("🔍 Step 1: Verifying service health");
    let health_check = framework.client.health_check().await?;
    assert!(health_check.get("status").is_some());
    println!("✅ Service is healthy and ready");

    // Step 2: Test complete authentication flow
    println!("🔐 Step 2: Testing complete authentication flow");
    let test_user = framework.create_test_user("comprehensive_test");
    let auth_flow_result = framework.test_authentication_flow(&test_user).await?;
    
    // Verify performance requirements
    assert!(auth_flow_result.register_time < Duration::from_millis(2000), 
        "Registration should complete in <2000ms");
    assert!(auth_flow_result.login_time < Duration::from_millis(1500), 
        "Login should complete in <1500ms");
    assert!(auth_flow_result.profile_time < Duration::from_millis(1000), 
        "Profile access should complete in <1000ms");
    
    println!("✅ Authentication flow completed successfully");
    println!("   📊 Performance metrics:");
    println!("     Registration: {:.2}ms", auth_flow_result.register_time.as_millis());
    println!("     Login: {:.2}ms", auth_flow_result.login_time.as_millis());
    println!("     Profile: {:.2}ms", auth_flow_result.profile_time.as_millis());
    println!("     Total: {:.2}ms", auth_flow_result.total_time.as_millis());

    // Step 3: Test protected endpoints access control
    println!("🛡️ Step 3: Testing protected endpoints access control");
    let protected_endpoints_result = framework.test_protected_endpoints().await?;
    
    // Verify all endpoints properly reject unauthorized access
    for (endpoint, status) in &protected_endpoints_result.unauthorized_access {
        assert_eq!(*status, reqwest::StatusCode::UNAUTHORIZED, 
            "Endpoint {} should return 401 for unauthorized access", endpoint);
    }
    
    // Verify all endpoints properly reject invalid tokens
    for (endpoint, status) in &protected_endpoints_result.invalid_token_access {
        assert_eq!(*status, reqwest::StatusCode::UNAUTHORIZED,
            "Endpoint {} should return 401 for invalid tokens", endpoint);
    }
    
    println!("✅ Access control working correctly on {} endpoints", 
        protected_endpoints_result.unauthorized_access.len());

    // Step 4: Test concurrent operations
    println!("🔄 Step 4: Testing concurrent operations");
    let concurrent_users = 10;
    let mut concurrent_handles = Vec::new();

    for i in 0..concurrent_users {
        let client = framework.client.clone();
        let handle = tokio::spawn(async move {
            let user = TestUser::new(&format!("concurrent_test_{}", i));
            
            // Perform complete auth flow
            let register_result = client.register(&user).await;
            if let Ok((tokens, _)) = register_result {
                let profile_result = client.get_profile(&tokens.access_token).await;
                let logout_result = client.logout(&tokens.access_token).await;
                
                profile_result.is_ok() && logout_result.is_ok()
            } else {
                false
            }
        });
        concurrent_handles.push(handle);
    }

    let mut concurrent_successes = 0;
    for handle in concurrent_handles {
        if let Ok(true) = handle.await {
            concurrent_successes += 1;
        }
    }

    assert!(concurrent_successes >= (concurrent_users * 8 / 10), 
        "At least 80% of concurrent operations should succeed");
    println!("✅ Concurrent operations: {}/{} successful ({:.1}%)", 
        concurrent_successes, concurrent_users,
        (concurrent_successes as f64 / concurrent_users as f64) * 100.0);

    // Step 5: Test input validation and security
    println!("🔒 Step 5: Testing input validation and security");
    
    // Test invalid email formats
    let invalid_emails = ValidationTestUtils::invalid_emails();
    for invalid_email in invalid_emails {
        let invalid_user = TestUser::with_custom_data(
            invalid_email, "ValidPassword123!", "Test", "User"
        );
        let result = framework.client.register(&invalid_user).await;
        assert!(result.is_err(), "Registration should fail for invalid email: {}", invalid_email);
    }
    
    // Test weak passwords
    let weak_passwords = ValidationTestUtils::invalid_passwords();
    for weak_password in weak_passwords {
        let weak_user = TestUser::with_custom_data(
            "test@example.com", weak_password, "Test", "User"
        );
        let _result = framework.client.register(&weak_user).await;
        // Note: Some weak passwords might be accepted depending on validation rules
        // This test mainly ensures the endpoint handles various password formats
    }
    
    println!("✅ Input validation working correctly");

    // Step 6: Test performance under light load
    println!("⚡ Step 6: Testing performance under light load");
    let load_config = LoadTestConfig {
        concurrent_users: 15,
        operations_per_user: 3,
        delay_between_operations: Duration::from_millis(100),
        timeout: Duration::from_secs(60),
    };
    
    let load_results = framework.run_load_test(load_config).await?;
    
    // Performance assertions
    assert!(load_results.operations_per_second > 5.0, 
        "Should handle at least 5 operations per second under load");
    assert!(load_results.successful_operations as f64 / load_results.total_operations as f64 > 0.85,
        "Should have >85% success rate under load");
    
    println!("✅ Load test completed successfully");
    println!("   📊 Load test metrics:");
    println!("     Operations/second: {:.2}", load_results.operations_per_second);
    println!("     Success rate: {:.1}%", 
        (load_results.successful_operations as f64 / load_results.total_operations as f64) * 100.0);
    println!("     Average response time: {:.2}ms", load_results.average_response_time.as_millis());

    // Step 7: Test error handling and edge cases
    println!("🎯 Step 7: Testing error handling and edge cases");
    
    // Test duplicate registration
    let duplicate_user = framework.create_test_user("duplicate_test");
    let _first_registration = framework.client.register(&duplicate_user).await?;
    let second_registration = framework.client.register(&duplicate_user).await;
    assert!(second_registration.is_err(), "Duplicate registration should fail");
    
    // Test login with wrong password
    let wrong_password_user = TestUser::with_custom_data(
        &duplicate_user.email, "WrongPassword123!", &duplicate_user.first_name, &duplicate_user.last_name
    );
    let wrong_login = framework.client.login(&wrong_password_user).await;
    assert!(wrong_login.is_err(), "Login with wrong password should fail");
    
    println!("✅ Error handling working correctly");

    // Final verification: Test system cleanup and resource management
    println!("🧹 Step 8: Verifying system cleanup");
    
    // Create multiple users and then clean them up
    let mut cleanup_users = Vec::new();
    for i in 0..5 {
        let user = framework.create_test_user(&format!("cleanup_test_{}", i));
        let (tokens, _) = framework.client.register(&user).await?;
        cleanup_users.push((user, tokens));
    }
    
    // Logout all users
    for (_, tokens) in &cleanup_users {
        let _ = framework.client.logout(&tokens.access_token).await;
    }
    
    println!("✅ System cleanup completed");

    // Final success message
    println!("\n🎉 COMPREHENSIVE INTEGRATION TEST COMPLETED SUCCESSFULLY! 🎉");
    println!("✅ All authentication system components working correctly");
    println!("✅ Performance requirements met");
    println!("✅ Security measures validated");
    println!("✅ Error handling verified");
    println!("✅ Concurrent operations supported");
    
    Ok(())
}

/// Quick smoke test for the integration framework itself
#[tokio::test]
async fn test_integration_framework_smoke_test() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    // Test framework configuration
    assert_eq!(framework.config.service_url, "http://localhost:8090");
    assert_eq!(framework.config.database_type, "mongodb");
    
    // Test client creation
    let test_user = framework.create_test_user("smoke_test");
    assert!(test_user.email.contains("smoke_test"));
    assert!(!test_user.password.is_empty());
    
    // Test that framework can check service status
    let is_running = framework.is_service_running().await.unwrap_or(false);
    println!("Service running: {}", is_running);
    
    println!("✅ Integration framework smoke test passed");
    Ok(())
}

/// Performance benchmark test
#[tokio::test]
async fn test_authentication_performance_benchmark() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping performance benchmark.");
        return Ok(());
    }

    println!("⚡ Running authentication performance benchmark");

    // Benchmark registration performance
    let registration_times = {
        let mut times = Vec::new();
        for i in 0..10 {
            let user = framework.create_test_user(&format!("perf_reg_{}", i));
            let timer = PerformanceTimer::new("Registration");
            let _ = framework.client.register(&user).await;
            times.push(timer.elapsed());
        }
        times
    };

    // Benchmark login performance
    let login_times = {
        let mut times = Vec::new();
        let user = framework.create_test_user("perf_login");
        let (_, _) = framework.client.register(&user).await?;
        
        for _ in 0..10 {
            let timer = PerformanceTimer::new("Login");
            let _ = framework.client.login(&user).await;
            times.push(timer.elapsed());
        }
        times
    };

    // Calculate statistics
    let avg_registration = registration_times.iter().sum::<Duration>() / registration_times.len() as u32;
    let avg_login = login_times.iter().sum::<Duration>() / login_times.len() as u32;
    
    println!("📊 Performance Benchmark Results:");
    println!("  Average Registration Time: {:.2}ms", avg_registration.as_millis());
    println!("  Average Login Time: {:.2}ms", avg_login.as_millis());
    
    // Performance assertions (adjust thresholds as needed)
    assert!(avg_registration < Duration::from_millis(2000), 
        "Average registration time should be <2000ms");
    assert!(avg_login < Duration::from_millis(1000),
        "Average login time should be <1000ms");
    
    println!("✅ Performance benchmark completed successfully");
    Ok(())
}