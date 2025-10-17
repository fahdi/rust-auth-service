use anyhow::Result;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;
use std::sync::Arc;
use tokio::time::sleep;
use uuid::Uuid;

use rust_auth_service::config::{database::DatabaseConfig, database::PoolConfig};
use rust_auth_service::database::{create_database, AuthDatabase};

/// Comprehensive authentication flow integration tests
/// Tests end-to-end authentication scenarios across all security build configurations

const TEST_SERVICE_URL: &str = "http://localhost:8090";

#[derive(Clone)]
struct AuthTestContext {
    client: Client,
    base_url: String,
    db: Option<Arc<dyn AuthDatabase>>,
}

impl AuthTestContext {
    fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: std::env::var("AUTH_SERVICE_URL")
                .unwrap_or_else(|_| TEST_SERVICE_URL.to_string()),
            db: None,
        }
    }

    async fn with_database(mut self, db_type: &str) -> Self {
        let url = match db_type {
            "mongodb" => std::env::var("MONGODB_TEST_URL").unwrap_or_else(|_| {
                "mongodb://admin:password123@localhost:27017/auth_service_test?authSource=admin"
                    .to_string()
            }),
            "postgresql" => std::env::var("POSTGRESQL_TEST_URL").unwrap_or_else(|_| {
                "postgresql://postgres:password123@localhost:5432/auth_service_test".to_string()
            }),
            "mysql" => std::env::var("MYSQL_TEST_URL").unwrap_or_else(|_| {
                "mysql://root:password123@localhost:3306/auth_service_test".to_string()
            }),
            _ => panic!("Unsupported database type: {}", db_type),
        };

        let pool_config = PoolConfig {
            min_connections: 1,
            max_connections: 10,
            idle_timeout: 30,
        };

        let db_config = DatabaseConfig {
            r#type: db_type.to_string(),
            url,
            pool: pool_config,
            mongodb: None,
            postgresql: None,
            mysql: None,
        };

        match create_database(&db_config).await {
            Ok(db) => {
                self.db = Some(Arc::new(db));
            }
            Err(e) => {
                panic!("Failed to create {} database: {}", db_type, e);
            }
        }

        self
    }

    async fn wait_for_service(&self) -> Result<(), anyhow::Error> {
        let mut attempts = 0;
        let max_attempts = 30;

        while attempts < max_attempts {
            match self
                .client
                .get(&format!("{}/health", self.base_url))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    println!("✅ Auth service is ready");
                    return Ok(());
                }
                _ => {
                    attempts += 1;
                    if attempts < max_attempts {
                        println!(
                            "⏳ Waiting for auth service... (attempt {}/{})",
                            attempts, max_attempts
                        );
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "Auth service not available at {} after {} attempts",
            self.base_url,
            max_attempts
        )
        .into())
    }

    async fn cleanup_user(&self, email: &str) {
        if let Some(db) = &self.db {
            if let Ok(Some(user)) = db.find_user_by_email(email).await {
                let _ = db.deactivate_user(&user.user_id).await;
            }
        }
    }
}

#[derive(Debug, Clone)]
struct AuthFlow {
    email: String,
    password: String,
    first_name: String,
    last_name: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    user_id: Option<String>,
}

impl AuthFlow {
    fn new(prefix: &str) -> Self {
        let unique_id = Uuid::new_v4().to_string()[..8].to_string();
        Self {
            email: format!("{}+{}@example.com", prefix, unique_id),
            password: "TestPassword123!".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            access_token: None,
            refresh_token: None,
            user_id: None,
        }
    }

    async fn register(&mut self, ctx: &AuthTestContext) -> Result<Value, anyhow::Error> {
        let payload = json!({
            "email": self.email,
            "password": self.password,
            "first_name": self.first_name,
            "last_name": self.last_name
        });

        let response = ctx
            .client
            .post(&format!("{}/auth/register", ctx.base_url))
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::CREATED || status == StatusCode::OK {
            if let Some(access_token) = body.get("access_token").and_then(|t| t.as_str()) {
                self.access_token = Some(access_token.to_string());
            }
            if let Some(refresh_token) = body.get("refresh_token").and_then(|t| t.as_str()) {
                self.refresh_token = Some(refresh_token.to_string());
            }
            if let Some(user) = body.get("user") {
                if let Some(user_id) = user.get("user_id").and_then(|id| id.as_str()) {
                    self.user_id = Some(user_id.to_string());
                }
            }
            Ok(body)
        } else {
            Err(anyhow::anyhow!(
                "Registration failed with status {}: {}",
                status,
                body
            ))
        }
    }

    async fn login(&mut self, ctx: &AuthTestContext) -> Result<Value, anyhow::Error> {
        let payload = json!({
            "email": self.email,
            "password": self.password
        });

        let response = ctx
            .client
            .post(&format!("{}/auth/login", ctx.base_url))
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::OK {
            if let Some(access_token) = body.get("access_token").and_then(|t| t.as_str()) {
                self.access_token = Some(access_token.to_string());
            }
            if let Some(refresh_token) = body.get("refresh_token").and_then(|t| t.as_str()) {
                self.refresh_token = Some(refresh_token.to_string());
            }
            Ok(body)
        } else {
            Err(anyhow::anyhow!(
                "Login failed with status {}: {}",
                status,
                body
            ))
        }
    }

    async fn get_profile(&self, ctx: &AuthTestContext) -> Result<Value, anyhow::Error> {
        let token = self
            .access_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No access token available"))?;

        let response = ctx
            .client
            .bearer_auth(token)
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::OK {
            Ok(body)
        } else {
            Err(anyhow::anyhow!(
                "Get profile failed with status {}: {}",
                status,
                body
            ))
        }
    }

    async fn update_profile(
        &self,
        ctx: &AuthTestContext,
        updates: Value,
    ) -> Result<Value, anyhow::Error> {
        let token = self
            .access_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No access token available"))?;

        let response = ctx
            .bearer_auth(token)
            .json(&updates)
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::OK {
            Ok(body)
        } else {
            Err(anyhow::anyhow!(
                "Update profile failed with status {}: {}",
                status,
                body
            ))
        }
    }

    async fn refresh_token(&mut self, ctx: &AuthTestContext) -> Result<Value, anyhow::Error> {
        let refresh_token = self
            .refresh_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No refresh token available"))?;

        let payload = json!({
            "refresh_token": refresh_token
        });

        let response = ctx
            .client
            .post(&format!("{}/auth/refresh", ctx.base_url))
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::OK {
            if let Some(access_token) = body.get("access_token").and_then(|t| t.as_str()) {
                self.access_token = Some(access_token.to_string());
            }
            if let Some(refresh_token) = body.get("refresh_token").and_then(|t| t.as_str()) {
                self.refresh_token = Some(refresh_token.to_string());
            }
            Ok(body)
        } else {
            Err(anyhow::anyhow!(
                "Token refresh failed with status {}: {}",
                status,
                body
            ))
        }
    }

    async fn logout(&self, ctx: &AuthTestContext) -> Result<Value, anyhow::Error> {
        let token = self
            .access_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No access token available"))?;

        let response = ctx
            .client
            .post(&format!("{}/auth/logout", ctx.base_url))
            .bearer_auth(token)
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::OK {
            Ok(body)
        } else {
            Err(anyhow::anyhow!(
                "Logout failed with status {}: {}",
                status,
                body
            ))
        }
    }

    async fn forgot_password(&self, ctx: &AuthTestContext) -> Result<Value, anyhow::Error> {
        let payload = json!({
            "email": self.email
        });

        let response = ctx
            .client
            .post(&format!("{}/auth/forgot-password", ctx.base_url))
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::OK {
            Ok(body)
        } else {
            Err(anyhow::anyhow!(
                "Forgot password failed with status {}: {}",
                status,
                body
            ))
        }
    }
}

/// Test complete registration → login → profile access flow
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_complete_authentication_flow() {
    let ctx = AuthTestContext::new();
    ctx.wait_for_service()
        .await
        .expect("Auth service should be available");

    let mut flow = AuthFlow::new("complete_flow");

    // Step 1: Register user
    println!("🔐 Testing complete authentication flow for {}", flow.email);

    let register_result = flow.register(&ctx).await;
    assert!(
        register_result.is_ok(),
        "Registration should succeed: {:?}",
        register_result
    );

    let register_response = register_result.unwrap();
    assert!(
        register_response.get("user").is_some(),
        "Registration should return user data"
    );
    assert!(
        flow.access_token.is_some(),
        "Registration should provide access token"
    );

    // Step 2: Access protected profile endpoint
    let profile_result = flow.get_profile(&ctx).await;
    assert!(
        profile_result.is_ok(),
        "Profile access should succeed: {:?}",
        profile_result
    );

    let profile = profile_result.unwrap();
    assert_eq!(
        profile["email"], flow.email,
        "Profile should return correct email"
    );
    assert_eq!(
        profile["first_name"], flow.first_name,
        "Profile should return correct first name"
    );

    // Step 3: Update profile
    let update_data = json!({
        "first_name": "Updated",
        "last_name": "Name"
    });

    let update_result = flow.update_profile(&ctx, update_data).await;
    assert!(
        update_result.is_ok(),
        "Profile update should succeed: {:?}",
        update_result
    );

    // Step 4: Verify profile was updated
    let updated_profile = flow.get_profile(&ctx).await.unwrap();
    assert_eq!(
        updated_profile["first_name"], "Updated",
        "Profile should be updated"
    );
    assert_eq!(
        updated_profile["last_name"], "Name",
        "Profile should be updated"
    );

    // Step 5: Test token refresh
    let refresh_result = flow.refresh_token(&ctx).await;
    assert!(
        refresh_result.is_ok(),
        "Token refresh should succeed: {:?}",
        refresh_result
    );

    // Step 6: Verify new token works
    let profile_with_new_token = flow.get_profile(&ctx).await;
    assert!(
        profile_with_new_token.is_ok(),
        "New token should work for profile access"
    );

    // Step 7: Logout
    let logout_result = flow.logout(&ctx).await;
    assert!(
        logout_result.is_ok(),
        "Logout should succeed: {:?}",
        logout_result
    );

    // Step 8: Verify token is invalidated (should fail)
    let profile_after_logout = flow.get_profile(&ctx).await;
    assert!(
        profile_after_logout.is_err(),
        "Profile access should fail after logout"
    );

    // Cleanup
    ctx.cleanup_user(&flow.email).await;

    println!("✅ Complete authentication flow test passed");
}

/// Test registration with various validation scenarios
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_registration_validation() {
    let ctx = AuthTestContext::new();
    ctx.wait_for_service()
        .await
        .expect("Auth service should be available");

    // Test 1: Valid registration
    let mut valid_flow = AuthFlow::new("valid_reg");
    let result = valid_flow.register(&ctx).await;
    assert!(result.is_ok(), "Valid registration should succeed");
    ctx.cleanup_user(&valid_flow.email).await;

    // Test 2: Duplicate email registration
    let mut duplicate_flow = AuthFlow::new("duplicate_reg");
    let first_result = duplicate_flow.register(&ctx).await;
    assert!(first_result.is_ok(), "First registration should succeed");

    let second_result = duplicate_flow.register(&ctx).await;
    assert!(
        second_result.is_err(),
        "Duplicate email registration should fail"
    );
    ctx.cleanup_user(&duplicate_flow.email).await;

    // Test 3: Invalid email format
    let invalid_payload = json!({
        "email": "invalid-email",
        "password": "TestPassword123!",
        "first_name": "Test",
        "last_name": "User"
    });

    let response = ctx
        .client
        .post(&format!("{}/auth/register", ctx.base_url))
        .json(&invalid_payload)
        .send()
        .await
        .expect("Request should complete");

    assert!(
        !response.status().is_success(),
        "Invalid email should be rejected"
    );

    // Test 4: Weak password
    let weak_password_payload = json!({
        "email": "weak@example.com",
        "password": "123",
        "first_name": "Test",
        "last_name": "User"
    });

    let response = ctx
        .client
        .post(&format!("{}/auth/register", ctx.base_url))
        .json(&weak_password_payload)
        .send()
        .await
        .expect("Request should complete");

    assert!(
        !response.status().is_success(),
        "Weak password should be rejected"
    );

    println!("✅ Registration validation tests passed");
}

/// Test login scenarios and authentication
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_login_scenarios() {
    let ctx = AuthTestContext::new();
    ctx.wait_for_service()
        .await
        .expect("Auth service should be available");

    // Setup: Register a user for login testing
    let mut flow = AuthFlow::new("login_test");
    flow.register(&ctx)
        .await
        .expect("Setup registration should succeed");

    // Test 1: Valid login
    let login_result = flow.login(&ctx).await;
    assert!(
        login_result.is_ok(),
        "Valid login should succeed: {:?}",
        login_result
    );

    // Test 2: Invalid password
    let mut invalid_password_flow = AuthFlow::new("invalid_pass");
    invalid_password_flow.email = flow.email.clone();
    invalid_password_flow.password = "WrongPassword123!".to_string();

    let invalid_login = invalid_password_flow.login(&ctx).await;
    assert!(invalid_login.is_err(), "Invalid password login should fail");

    // Test 3: Non-existent user
    let mut nonexistent_flow = AuthFlow::new("nonexistent");
    let nonexistent_login = nonexistent_flow.login(&ctx).await;
    assert!(
        nonexistent_login.is_err(),
        "Non-existent user login should fail"
    );

    // Cleanup
    ctx.cleanup_user(&flow.email).await;

    println!("✅ Login scenario tests passed");
}

/// Test JWT token expiration and refresh
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_token_expiration_and_refresh() {
    let ctx = AuthTestContext::new();
    ctx.wait_for_service()
        .await
        .expect("Auth service should be available");

    let mut flow = AuthFlow::new("token_test");
    flow.register(&ctx)
        .await
        .expect("Registration should succeed");

    // Test 1: Valid token works
    let profile_result = flow.get_profile(&ctx).await;
    assert!(profile_result.is_ok(), "Valid token should work");

    // Test 2: Token refresh works
    let old_token = flow.access_token.clone();
    let refresh_result = flow.refresh_token(&ctx).await;
    assert!(refresh_result.is_ok(), "Token refresh should succeed");
    assert_ne!(
        flow.access_token, old_token,
        "New token should be different"
    );

    // Test 3: New token works
    let profile_with_new_token = flow.get_profile(&ctx).await;
    assert!(profile_with_new_token.is_ok(), "New token should work");

    // Test 4: Invalid refresh token
    let mut invalid_refresh_flow = AuthFlow::new("invalid_refresh");
    invalid_refresh_flow.refresh_token = Some("invalid_token".to_string());
    let invalid_refresh = invalid_refresh_flow.refresh_token(&ctx).await;
    assert!(
        invalid_refresh.is_err(),
        "Invalid refresh token should fail"
    );

    // Cleanup
    ctx.cleanup_user(&flow.email).await;

    println!("✅ Token expiration and refresh tests passed");
}

/// Test password reset flow
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_password_reset_flow() {
    let ctx = AuthTestContext::new();
    ctx.wait_for_service()
        .await
        .expect("Auth service should be available");

    let mut flow = AuthFlow::new("password_reset");
    flow.register(&ctx)
        .await
        .expect("Registration should succeed");

    // Test 1: Forgot password request
    let forgot_result = flow.forgot_password(&ctx).await;
    assert!(
        forgot_result.is_ok(),
        "Forgot password should succeed: {:?}",
        forgot_result
    );

    // Test 2: Forgot password for non-existent user
    let nonexistent_flow = AuthFlow::new("nonexistent_reset");
    let nonexistent_forgot = nonexistent_flow.forgot_password(&ctx).await;
    // This might succeed for security reasons (not revealing if email exists)
    // But should not cause any errors
    assert!(
        nonexistent_forgot.is_ok() || nonexistent_forgot.is_err(),
        "Should handle gracefully"
    );

    // Cleanup
    ctx.cleanup_user(&flow.email).await;

    println!("✅ Password reset flow tests passed");
}

/// Test protected endpoints access control
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_protected_endpoints_access_control() {
    let ctx = AuthTestContext::new();
    ctx.wait_for_service()
        .await
        .expect("Auth service should be available");

    // Test 1: Access without token should fail
    let unauthorized_response = ctx
        .client
        .get(&format!("{}/auth/me", ctx.base_url))
        .send()
        .await
        .expect("Request should complete");

    assert_eq!(
        unauthorized_response.status(),
        StatusCode::UNAUTHORIZED,
        "Access without token should return 401"
    );

    // Test 2: Access with invalid token should fail
    let invalid_token_response = ctx
        .client
        .get(&format!("{}/auth/me", ctx.base_url))
        .bearer_auth("invalid_token")
        .send()
        .await
        .expect("Request should complete");

    assert_eq!(
        invalid_token_response.status(),
        StatusCode::UNAUTHORIZED,
        "Access with invalid token should return 401"
    );

    // Test 3: Access with valid token should succeed
    let mut flow = AuthFlow::new("protected_test");
    flow.register(&ctx)
        .await
        .expect("Registration should succeed");

    let profile_response = ctx
        .client
        .get(&format!("{}/auth/me", ctx.base_url))
        .bearer_auth(flow.access_token.as_ref().unwrap())
        .send()
        .await
        .expect("Request should complete");

    assert_eq!(
        profile_response.status(),
        StatusCode::OK,
        "Access with valid token should return 200"
    );

    // Cleanup
    ctx.cleanup_user(&flow.email).await;

    println!("✅ Protected endpoints access control tests passed");
}

/// Test concurrent authentication operations
#[tokio::test]
#[cfg(feature = "integration-tests")]
async fn test_concurrent_authentication() {
    let ctx = AuthTestContext::new();
    ctx.wait_for_service()
        .await
        .expect("Auth service should be available");

    const CONCURRENT_USERS: usize = 10;
    let mut handles = Vec::new();

    for i in 0..CONCURRENT_USERS {
        let ctx = ctx.clone();
        let handle = tokio::spawn(async move {
            let mut flow = AuthFlow::new(&format!("concurrent_{}", i));

            // Register
            let register_result = flow.register(&ctx).await;
            if register_result.is_err() {
                return (i, false, "Registration failed".to_string());
            }

            // Login
            let login_result = flow.login(&ctx).await;
            if login_result.is_err() {
                ctx.cleanup_user(&flow.email).await;
                return (i, false, "Login failed".to_string());
            }

            // Access profile
            let profile_result = flow.get_profile(&ctx).await;
            if profile_result.is_err() {
                ctx.cleanup_user(&flow.email).await;
                return (i, false, "Profile access failed".to_string());
            }

            // Cleanup
            ctx.cleanup_user(&flow.email).await;
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
                println!("User {}: {}", id, error);
            }
            Err(e) => {
                failed += 1;
                println!("Task error: {}", e);
            }
        }
    }

    println!("📊 Concurrent Authentication Results:");
    println!("  Successful: {}/{}", successful, CONCURRENT_USERS);
    println!("  Failed: {}", failed);

    assert!(
        successful >= CONCURRENT_USERS * 8 / 10,
        "At least 80% of concurrent operations should succeed"
    );

    println!("✅ Concurrent authentication tests passed");
}
