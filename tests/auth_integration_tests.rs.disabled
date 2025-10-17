mod helpers;
mod integration;

use helpers::*;
use std::time::Duration;
use tokio::time::sleep;

/// Integration Test Runner for Authentication Flows
///
/// This test suite tests the actual HTTP endpoints of the running auth service.
/// Tests require the auth service to be running on localhost:8090.
///
/// ## Running Integration Tests
///
/// ```bash
/// # Start the auth service first
/// cargo run
///
/// # In another terminal, run integration tests
/// cargo test --test auth_integration_tests --features integration-tests
/// ```
///
/// ## Test Coverage
/// - Complete user registration and authentication flows
/// - JWT token validation and security
/// - Protected endpoint access control
/// - Authentication performance benchmarks
/// - Concurrent authentication operations
/// - Input validation and error handling
///
/// ## Prerequisites
/// - Auth service running on localhost:8090
/// - Test databases available and configured
/// - No more #[ignore] tags - tests run when integration-tests feature is enabled

const SERVICE_HEALTH_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_HEALTH_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Wait for the authentication service to be ready
async fn wait_for_service_ready(base_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = AuthTestClient::new(Some(base_url.to_string()));
    let mut attempts = 0;
    let max_attempts = SERVICE_HEALTH_TIMEOUT.as_secs() as usize;

    println!("🔍 Waiting for auth service at {} to be ready...", base_url);

    while attempts < max_attempts {
        match client.health_check().await {
            Ok(health) => {
                if health.get("status").and_then(|s| s.as_str()) == Some("healthy") {
                    println!("✅ Auth service is ready and healthy");
                    return Ok(());
                }
            }
            Err(_) => {
                // Service not ready yet, continue waiting
            }
        }

        attempts += 1;
        if attempts < max_attempts {
            sleep(SERVICE_HEALTH_RETRY_INTERVAL).await;
        }
    }

    Err(format!(
        "Auth service at {} did not become ready within {} seconds",
        base_url,
        SERVICE_HEALTH_TIMEOUT.as_secs()
    )
    .into())
}

/// Test authentication service health and basic connectivity
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_service_health() {
    let base_url =
        std::env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string());

    wait_for_service_ready(&base_url)
        .await
        .expect("Service should be healthy and ready");

    let client = AuthTestClient::new(Some(base_url));
    let health = client
        .health_check()
        .await
        .expect("Health check should succeed");

    // Validate health response structure
    assert!(
        health.get("status").is_some(),
        "Health response should include status"
    );
    assert!(
        health.get("database").is_some(),
        "Health response should include database info"
    );
    assert!(
        health.get("cache").is_some(),
        "Health response should include cache info"
    );
    assert!(
        health.get("timestamp").is_some(),
        "Health response should include timestamp"
    );

    println!("✅ Service health test passed");
}

/// Test complete user registration and authentication flow
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_complete_user_journey() {
    let base_url =
        std::env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string());

    wait_for_service_ready(&base_url)
        .await
        .expect("Service should be ready");

    let client = AuthTestClient::new(Some(base_url));
    let user = TestUser::new("journey_test");

    println!("🚀 Testing complete user journey for {}", user.email);

    // Step 1: Registration
    let timer = PerformanceTimer::new("User Registration");
    let (tokens, reg_response) = client
        .register(&user)
        .await
        .expect("Registration should succeed");
    timer.finish();

    ValidationTestUtils::validate_registration_response(&reg_response)
        .expect("Registration response should be valid");

    // Step 2: Profile access
    let timer = PerformanceTimer::new("Profile Access");
    let profile = client
        .get_profile(&tokens.access_token)
        .await
        .expect("Profile access should succeed");
    timer.finish();

    ValidationTestUtils::validate_profile_response(&profile)
        .expect("Profile response should be valid");

    assert_eq!(profile["email"], user.email, "Profile email should match");
    assert_eq!(
        profile["first_name"], user.first_name,
        "Profile first name should match"
    );

    // Step 3: Profile update
    let timer = PerformanceTimer::new("Profile Update");
    let update_data = serde_json::json!({
        "first_name": "Updated",
        "last_name": "Journey"
    });

    let updated = client
        .update_profile(&tokens.access_token, &update_data)
        .await
        .expect("Profile update should succeed");
    timer.finish();

    assert_eq!(
        updated["first_name"], "Updated",
        "First name should be updated"
    );
    assert_eq!(
        updated["last_name"], "Journey",
        "Last name should be updated"
    );

    // Step 4: Token refresh
    if let Some(refresh_token) = &tokens.refresh_token {
        let timer = PerformanceTimer::new("Token Refresh");
        let new_tokens = client
            .refresh_token(refresh_token)
            .await
            .expect("Token refresh should succeed");
        timer.finish();

        // Verify new token works
        let profile_with_new_token = client
            .get_profile(&new_tokens.access_token)
            .await
            .expect("New token should work");

        assert_eq!(
            profile_with_new_token["email"], user.email,
            "New token should access correct profile"
        );
    }

    // Step 5: Logout
    let timer = PerformanceTimer::new("User Logout");
    let logout_response = client
        .logout(&tokens.access_token)
        .await
        .expect("Logout should succeed");
    timer.finish();

    assert!(
        logout_response.get("message").is_some(),
        "Logout should return message"
    );

    // Step 6: Verify token is invalidated
    let profile_after_logout = client.get_profile(&tokens.access_token).await;
    assert!(
        profile_after_logout.is_err(),
        "Token should be invalidated after logout"
    );

    println!("✅ Complete user journey test passed");
}

/// Test authentication input validation
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_authentication_validation() {
    let base_url =
        std::env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string());

    wait_for_service_ready(&base_url)
        .await
        .expect("Service should be ready");

    let client = AuthTestClient::new(Some(base_url));

    println!("🔍 Testing authentication input validation");

    // Test invalid email formats
    for invalid_email in ValidationTestUtils::invalid_emails() {
        let invalid_user =
            TestUser::with_custom_data(invalid_email, "ValidPassword123!", "Test", "User");

        let result = client.register(&invalid_user).await;
        assert!(
            result.is_err(),
            "Registration with invalid email '{}' should fail",
            invalid_email
        );
    }

    // Test invalid passwords
    for invalid_password in ValidationTestUtils::invalid_passwords() {
        let invalid_user =
            TestUser::with_custom_data("valid@example.com", invalid_password, "Test", "User");

        let result = client.register(&invalid_user).await;
        assert!(
            result.is_err(),
            "Registration with invalid password should fail"
        );
    }

    // Test valid passwords work
    for valid_password in ValidationTestUtils::valid_passwords() {
        let valid_user = TestUser::with_custom_data(
            &format!("valid_{}@example.com", rand::random::<u32>()),
            valid_password,
            "Test",
            "User",
        );

        let result = client.register(&valid_user).await;
        assert!(
            result.is_ok(),
            "Registration with valid password '{}' should succeed",
            valid_password
        );
    }

    println!("✅ Authentication validation tests passed");
}

/// Test protected endpoint access control
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_access_control() {
    let base_url =
        std::env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string());

    wait_for_service_ready(&base_url)
        .await
        .expect("Service should be ready");

    let client = AuthTestClient::new(Some(base_url));

    println!("🛡️  Testing access control for protected endpoints");

    let protected_endpoints = vec!["/auth/me", "/auth/profile", "/auth/logout"];

    for endpoint in protected_endpoints {
        // Test 1: No authentication
        let status = client
            .test_unauthorized_access(endpoint)
            .await
            .expect("Request should complete");
        assert_eq!(
            status,
            reqwest::StatusCode::UNAUTHORIZED,
            "Access to {} without token should return 401",
            endpoint
        );

        // Test 2: Invalid token
        let status = client
            .test_invalid_token_access(endpoint)
            .await
            .expect("Request should complete");
        assert_eq!(
            status,
            reqwest::StatusCode::UNAUTHORIZED,
            "Access to {} with invalid token should return 401",
            endpoint
        );
    }

    // Test 3: Valid token access
    let user = TestUser::new("access_control");
    let (tokens, _) = client
        .register(&user)
        .await
        .expect("Registration should succeed");

    let profile_response = client
        .authenticated_request("GET", "/auth/me", &tokens.access_token, None)
        .await
        .expect("Authenticated request should succeed");

    assert_eq!(
        profile_response.status(),
        reqwest::StatusCode::OK,
        "Access with valid token should return 200"
    );

    println!("✅ Access control tests passed");
}

/// Test concurrent authentication operations
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_concurrent_authentication() {
    let base_url =
        std::env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string());

    wait_for_service_ready(&base_url)
        .await
        .expect("Service should be ready");

    const CONCURRENT_USERS: usize = 20;
    let mut handles = Vec::new();

    println!(
        "⚡ Testing concurrent authentication with {} users",
        CONCURRENT_USERS
    );

    for i in 0..CONCURRENT_USERS {
        let base_url = base_url.clone();
        let handle = tokio::spawn(async move {
            let client = AuthTestClient::new(Some(base_url));
            let user = TestUser::new(&format!("concurrent_{}", i));

            // Full authentication flow
            let register_result = client.register(&user).await;
            if register_result.is_err() {
                return (i, false, "Registration failed".to_string());
            }

            let (tokens, _) = register_result.unwrap();

            let profile_result = client.get_profile(&tokens.access_token).await;
            if profile_result.is_err() {
                return (i, false, "Profile access failed".to_string());
            }

            let logout_result = client.logout(&tokens.access_token).await;
            if logout_result.is_err() {
                return (i, false, "Logout failed".to_string());
            }

            (i, true, "Success".to_string())
        });

        handles.push(handle);
    }

    let mut successful = 0;
    let mut failed = 0;

    for handle in handles {
        match handle.await {
            Ok((_, true, _)) => successful += 1,
            Ok((id, false, error)) => {
                failed += 1;
                println!("❌ User {}: {}", id, error);
            }
            Err(e) => {
                failed += 1;
                println!("❌ Task error: {}", e);
            }
        }
    }

    println!("📊 Concurrent Authentication Results:");
    println!("  Successful: {}/{}", successful, CONCURRENT_USERS);
    println!("  Failed: {}", failed);
    println!(
        "  Success Rate: {:.1}%",
        (successful as f64 / CONCURRENT_USERS as f64) * 100.0
    );

    // At least 90% should succeed for concurrent operations
    assert!(
        successful >= CONCURRENT_USERS * 9 / 10,
        "At least 90% of concurrent operations should succeed"
    );

    println!("✅ Concurrent authentication tests passed");
}

/// Test authentication performance benchmarks
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_authentication_performance() {
    let base_url =
        std::env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string());

    wait_for_service_ready(&base_url)
        .await
        .expect("Service should be ready");

    let client = AuthTestClient::new(Some(base_url));

    println!("🏃 Testing authentication performance benchmarks");

    // Performance thresholds (adjust based on environment)
    let max_registration_time = Duration::from_millis(500);
    let max_login_time = Duration::from_millis(200);
    let max_profile_time = Duration::from_millis(100);

    // Test registration performance
    let user = TestUser::new("perf_test");
    let start = std::time::Instant::now();
    let (_tokens, _) = client
        .register(&user)
        .await
        .expect("Registration should succeed");
    let registration_time = start.elapsed();

    AuthAssertions::assert_response_time_acceptable(registration_time, max_registration_time)
        .expect("Registration time should be acceptable");

    // Test login performance
    let start = std::time::Instant::now();
    let (login_tokens, _) = client.login(&user).await.expect("Login should succeed");
    let login_time = start.elapsed();

    AuthAssertions::assert_response_time_acceptable(login_time, max_login_time)
        .expect("Login time should be acceptable");

    // Test profile access performance
    let start = std::time::Instant::now();
    let _profile = client
        .get_profile(&login_tokens.access_token)
        .await
        .expect("Profile access should succeed");
    let profile_time = start.elapsed();

    AuthAssertions::assert_response_time_acceptable(profile_time, max_profile_time)
        .expect("Profile access time should be acceptable");

    println!("📊 Performance Results:");
    println!(
        "  Registration: {:.2}ms (limit: {:.2}ms)",
        registration_time.as_millis(),
        max_registration_time.as_millis()
    );
    println!(
        "  Login: {:.2}ms (limit: {:.2}ms)",
        login_time.as_millis(),
        max_login_time.as_millis()
    );
    println!(
        "  Profile Access: {:.2}ms (limit: {:.2}ms)",
        profile_time.as_millis(),
        max_profile_time.as_millis()
    );

    println!("✅ Authentication performance tests passed");
}

/// Test JWT token validation and security
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_jwt_token_security() {
    let base_url =
        std::env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string());

    wait_for_service_ready(&base_url)
        .await
        .expect("Service should be ready");

    let client = AuthTestClient::new(Some(base_url));
    let user = TestUser::new("jwt_security");

    println!("🔐 Testing JWT token security");

    // Register and get tokens
    let (tokens, _) = client
        .register(&user)
        .await
        .expect("Registration should succeed");

    // Validate JWT token format
    AuthAssertions::assert_valid_jwt_token(&tokens.access_token)
        .expect("Access token should be valid JWT");

    if let Some(refresh_token) = &tokens.refresh_token {
        AuthAssertions::assert_valid_jwt_token(refresh_token)
            .expect("Refresh token should be valid JWT");
    }

    // Test token tampering protection
    let mut tampered_token = tokens.access_token.clone();
    tampered_token.push_str("tampered");

    let tampered_result = client.get_profile(&tampered_token).await;
    assert!(
        tampered_result.is_err(),
        "Tampered token should be rejected"
    );

    // Test malformed tokens
    let malformed_tokens = vec!["invalid.token", "invalid", "", "a.b", "a.b.c.d"];

    for malformed_token in malformed_tokens {
        let result = client.get_profile(malformed_token).await;
        assert!(
            result.is_err(),
            "Malformed token '{}' should be rejected",
            malformed_token
        );
    }

    println!("✅ JWT token security tests passed");
}
