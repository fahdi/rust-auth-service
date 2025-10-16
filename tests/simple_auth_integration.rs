use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

/// Simple authentication integration tests
///
/// This test suite requires the auth service to be running on localhost:8090
/// Run with: cargo test --test simple_auth_integration -- --include-ignored

const SERVICE_URL: &str = "http://localhost:8090";

async fn wait_for_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new();
    let mut attempts = 0;
    let max_attempts = 30;

    println!("🔍 Waiting for auth service to be ready...");

    while attempts < max_attempts {
        match client.get(&format!("{}/health", SERVICE_URL)).send().await {
            Ok(response) if response.status().is_success() => {
                println!("✅ Auth service is ready");
                return Ok(());
            }
            _ => {
                attempts += 1;
                if attempts < max_attempts {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    Err("Auth service not available".into())
}

fn generate_test_user(prefix: &str) -> (String, Value) {
    let unique_id = Uuid::new_v4().to_string()[..8].to_string();
    let email = format!("{}+{}@example.com", prefix, unique_id);

    let payload = json!({
        "email": email,
        "password": "TestPassword123!",
        "first_name": "Test",
        "last_name": "User"
    });

    (email, payload)
}

/// Test service health endpoint
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_service_health() {
    wait_for_service().await.expect("Service should be ready");

    let client = Client::new();
    let response = client
        .get(&format!("{}/health", SERVICE_URL))
        .send()
        .await
        .expect("Health check should complete");

    assert!(
        response.status().is_success(),
        "Health check should return success"
    );

    let health: Value = response
        .json()
        .await
        .expect("Health response should be JSON");
    assert!(
        health.get("status").is_some(),
        "Health response should include status"
    );

    println!("✅ Service health test passed");
}

/// Test user registration
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_user_registration() {
    wait_for_service().await.expect("Service should be ready");

    let client = Client::new();
    let (_email, payload) = generate_test_user("registration_test");

    let response = client
        .post(&format!("{}/auth/register", SERVICE_URL))
        .json(&payload)
        .send()
        .await
        .expect("Registration request should complete");

    assert!(
        response.status().is_success(),
        "Registration should succeed"
    );

    let result: Value = response
        .json()
        .await
        .expect("Registration response should be JSON");
    assert!(
        result.get("user").is_some(),
        "Registration should return user data"
    );
    assert!(
        result.get("access_token").is_some(),
        "Registration should return access token"
    );

    println!("✅ User registration test passed");
}

/// Test user login
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_user_login() {
    wait_for_service().await.expect("Service should be ready");

    let client = Client::new();
    let (email, register_payload) = generate_test_user("login_test");

    // First register the user
    let register_response = client
        .post(&format!("{}/auth/register", SERVICE_URL))
        .json(&register_payload)
        .send()
        .await
        .expect("Registration should complete");

    assert!(
        register_response.status().is_success(),
        "Registration should succeed"
    );

    // Then try to login
    let login_payload = json!({
        "email": email,
        "password": "TestPassword123!"
    });

    let login_response = client
        .post(&format!("{}/auth/login", SERVICE_URL))
        .json(&login_payload)
        .send()
        .await
        .expect("Login request should complete");

    assert!(login_response.status().is_success(), "Login should succeed");

    let result: Value = login_response
        .json()
        .await
        .expect("Login response should be JSON");
    assert!(
        result.get("access_token").is_some(),
        "Login should return access token"
    );

    println!("✅ User login test passed");
}

/// Test protected endpoint access
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_protected_endpoint_access() {
    wait_for_service().await.expect("Service should be ready");

    let client = Client::new();
    let (_email, register_payload) = generate_test_user("protected_test");

    // Register user and get token
    let register_response = client
        .post(&format!("{}/auth/register", SERVICE_URL))
        .json(&register_payload)
        .send()
        .await
        .expect("Registration should complete");

    let register_result: Value = register_response
        .json()
        .await
        .expect("Registration response should be JSON");
    let access_token = register_result
        .get("access_token")
        .and_then(|t| t.as_str())
        .expect("Registration should return access token");

    // Test access without token (should fail)
    let unauthorized_response = client
        .get(&format!("{}/auth/me", SERVICE_URL))
        .send()
        .await
        .expect("Request should complete");

    assert_eq!(
        unauthorized_response.status(),
        StatusCode::UNAUTHORIZED,
        "Access without token should return 401"
    );

    // Test access with valid token (should succeed)
    let authorized_response = client
        .get(&format!("{}/auth/me", SERVICE_URL))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("Authorized request should complete");

    assert!(
        authorized_response.status().is_success(),
        "Access with valid token should succeed"
    );

    let profile: Value = authorized_response
        .json()
        .await
        .expect("Profile response should be JSON");
    assert!(
        profile.get("email").is_some(),
        "Profile should include email"
    );

    println!("✅ Protected endpoint access test passed");
}

/// Test registration validation
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_registration_validation() {
    wait_for_service().await.expect("Service should be ready");

    let client = Client::new();

    // Test invalid email
    let invalid_email_payload = json!({
        "email": "invalid-email",
        "password": "TestPassword123!",
        "first_name": "Test",
        "last_name": "User"
    });

    let response = client
        .post(&format!("{}/auth/register", SERVICE_URL))
        .json(&invalid_email_payload)
        .send()
        .await
        .expect("Request should complete");

    assert!(
        !response.status().is_success(),
        "Invalid email should be rejected"
    );

    // Test weak password
    let weak_password_payload = json!({
        "email": "test@example.com",
        "password": "123",
        "first_name": "Test",
        "last_name": "User"
    });

    let response = client
        .post(&format!("{}/auth/register", SERVICE_URL))
        .json(&weak_password_payload)
        .send()
        .await
        .expect("Request should complete");

    assert!(
        !response.status().is_success(),
        "Weak password should be rejected"
    );

    println!("✅ Registration validation test passed");
}

/// Test complete authentication flow
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_complete_authentication_flow() {
    wait_for_service().await.expect("Service should be ready");

    let client = Client::new();
    let (email, register_payload) = generate_test_user("complete_flow");

    println!("🚀 Testing complete authentication flow for {}", email);

    // Step 1: Register
    let register_response = client
        .post(&format!("{}/auth/register", SERVICE_URL))
        .json(&register_payload)
        .send()
        .await
        .expect("Registration should complete");

    assert!(
        register_response.status().is_success(),
        "Registration should succeed"
    );

    let register_result: Value = register_response
        .json()
        .await
        .expect("Registration response should be JSON");
    let access_token = register_result
        .get("access_token")
        .and_then(|t| t.as_str())
        .expect("Registration should return access token");

    // Step 2: Access profile
    let profile_response = client
        .get(&format!("{}/auth/me", SERVICE_URL))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("Profile request should complete");

    assert!(
        profile_response.status().is_success(),
        "Profile access should succeed"
    );

    let profile: Value = profile_response
        .json()
        .await
        .expect("Profile response should be JSON");
    assert_eq!(profile["email"], email, "Profile email should match");

    // Step 3: Update profile
    let update_payload = json!({
        "first_name": "Updated",
        "last_name": "Name"
    });

    let update_response = client
        .put(&format!("{}/auth/profile", SERVICE_URL))
        .bearer_auth(access_token)
        .json(&update_payload)
        .send()
        .await
        .expect("Profile update should complete");

    assert!(
        update_response.status().is_success(),
        "Profile update should succeed"
    );

    let updated_profile: Value = update_response
        .json()
        .await
        .expect("Update response should be JSON");
    assert_eq!(
        updated_profile["first_name"], "Updated",
        "First name should be updated"
    );

    // Step 4: Logout
    let logout_response = client
        .post(&format!("{}/auth/logout", SERVICE_URL))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("Logout should complete");

    assert!(
        logout_response.status().is_success(),
        "Logout should succeed"
    );

    // Step 5: Verify token is invalidated
    let profile_after_logout = client
        .get(&format!("{}/auth/me", SERVICE_URL))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("Request should complete");

    assert_eq!(
        profile_after_logout.status(),
        StatusCode::UNAUTHORIZED,
        "Token should be invalidated after logout"
    );

    println!("✅ Complete authentication flow test passed");
}

/// Test concurrent registrations
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_concurrent_registrations() {
    wait_for_service().await.expect("Service should be ready");

    const CONCURRENT_USERS: usize = 10;
    let mut handles = Vec::new();

    println!("⚡ Testing {} concurrent registrations", CONCURRENT_USERS);

    for i in 0..CONCURRENT_USERS {
        let handle = tokio::spawn(async move {
            let client = Client::new();
            let (_email, payload) = generate_test_user(&format!("concurrent_{}", i));

            let response = client
                .post(&format!("{}/auth/register", SERVICE_URL))
                .json(&payload)
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => (i, true, "Success".to_string()),
                Ok(resp) => (i, false, format!("Status: {}", resp.status())),
                Err(e) => (i, false, format!("Error: {}", e)),
            }
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

    println!("📊 Concurrent Registration Results:");
    println!("  Successful: {}/{}", successful, CONCURRENT_USERS);
    println!("  Failed: {}", failed);
    println!(
        "  Success Rate: {:.1}%",
        (successful as f64 / CONCURRENT_USERS as f64) * 100.0
    );

    // At least 80% should succeed for concurrent operations
    assert!(
        successful >= CONCURRENT_USERS * 8 / 10,
        "At least 80% of concurrent operations should succeed"
    );

    println!("✅ Concurrent registration test passed");
}
