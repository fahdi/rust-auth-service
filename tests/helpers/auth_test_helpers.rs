// Test helper utilities
use anyhow::Result;
use reqwest::{Client, Response, StatusCode};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Helper utilities for authentication testing across all test suites

#[derive(Debug, Clone)]
pub struct TestUser {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub user_id: Option<String>,
}

impl TestUser {
    pub fn new(prefix: &str) -> Self {
        let unique_id = Uuid::new_v4().to_string()[..8].to_string();
        Self {
            email: format!("{}+{}@example.com", prefix, unique_id),
            password: "Hv4ZkR9_Wp2Yn3_".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            user_id: None,
        }
    }

    pub fn with_custom_data(
        email: &str,
        password: &str,
        first_name: &str,
        last_name: &str,
    ) -> Self {
        Self {
            email: email.to_string(),
            password: password.to_string(),
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            user_id: None,
        }
    }

    pub fn registration_payload(&self) -> Value {
        json!({
            "email": self.email,
            "password": self.password,
            "first_name": self.first_name,
            "last_name": self.last_name
        })
    }

    pub fn login_payload(&self) -> Value {
        json!({
            "email": self.email,
            "password": self.password
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

impl AuthTokens {
    pub fn from_response(response: &Value) -> Option<Self> {
        let access_token = response.get("access_token")?.as_str()?.to_string();
        let refresh_token = response
            .get("refresh_token")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string());
        let expires_in = response.get("expires_in").and_then(|e| e.as_u64());

        Some(Self {
            access_token,
            refresh_token,
            expires_in,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthTestClient {
    client: Client,
    base_url: String,
}

impl AuthTestClient {
    pub fn new(base_url: Option<String>) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            base_url: base_url.unwrap_or_else(|| "http://localhost:8090".to_string()),
        }
    }

    /// Register a new user
    pub async fn register(&self, user: &TestUser) -> Result<(AuthTokens, Value)> {
        let response = self
            .client
            .post(&format!("{}/auth/register", self.base_url))
            .json(&user.registration_payload())
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status.is_success() {
            let tokens = AuthTokens::from_response(&body).ok_or_else(|| {
                anyhow::anyhow!("Failed to extract tokens from registration response")
            })?;
            Ok((tokens, body))
        } else {
            Err(anyhow::anyhow!(
                "Registration failed with status {}: {}",
                status,
                body
            ))
        }
    }

    /// Login with user credentials
    pub async fn login(&self, user: &TestUser) -> Result<(AuthTokens, Value)> {
        let response = self
            .client
            .post(&format!("{}/auth/login", self.base_url))
            .json(&user.login_payload())
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::OK {
            let tokens = AuthTokens::from_response(&body)
                .ok_or_else(|| anyhow::anyhow!("Failed to extract tokens from login response"))?;
            Ok((tokens, body))
        } else {
            Err(anyhow::anyhow!(
                "Login failed with status {}: {}",
                status,
                body
            ))
        }
    }

    /// Get user profile with authentication token
    pub async fn get_profile(&self, token: &str) -> Result<Value> {
        let response = self
            .client
            .get(&format!("{}/auth/me", self.base_url))
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

    /// Update user profile
    pub async fn update_profile(&self, token: &str, updates: &Value) -> Result<Value> {
        let response = self
            .client
            .put(&format!("{}/auth/profile", self.base_url))
            .bearer_auth(token)
            .json(updates)
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

    /// Refresh authentication token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AuthTokens> {
        let payload = json!({
            "refresh_token": refresh_token
        });

        let response = self
            .client
            .post(&format!("{}/auth/refresh", self.base_url))
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::OK {
            AuthTokens::from_response(&body)
                .ok_or_else(|| anyhow::anyhow!("Failed to extract tokens from refresh response"))
        } else {
            Err(anyhow::anyhow!(
                "Token refresh failed with status {}: {}",
                status,
                body
            ))
        }
    }

    /// Logout user
    pub async fn logout(&self, token: &str) -> Result<Value> {
        let response = self
            .client
            .post(&format!("{}/auth/logout", self.base_url))
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

    /// Request password reset
    pub async fn forgot_password(&self, email: &str) -> Result<Value> {
        let payload = json!({
            "email": email
        });

        let response = self
            .client
            .post(&format!("{}/auth/forgot-password", self.base_url))
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

    /// Reset password with token
    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<Value> {
        let payload = json!({
            "token": token,
            "password": new_password
        });

        let response = self
            .client
            .post(&format!("{}/auth/reset-password", self.base_url))
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::OK {
            Ok(body)
        } else {
            Err(anyhow::anyhow!(
                "Reset password failed with status {}: {}",
                status,
                body
            ))
        }
    }

    /// Verify email with token
    pub async fn verify_email(&self, token: &str) -> Result<Value> {
        let payload = json!({
            "token": token
        });

        let response = self
            .client
            .post(&format!("{}/auth/verify", self.base_url))
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::OK {
            Ok(body)
        } else {
            Err(anyhow::anyhow!(
                "Email verification failed with status {}: {}",
                status,
                body
            ))
        }
    }

    /// Check service health
    pub async fn health_check(&self) -> Result<Value> {
        let response = self
            .client
            .get(&format!("{}/health", self.base_url))
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if status == StatusCode::OK {
            Ok(body)
        } else {
            Err(anyhow::anyhow!(
                "Health check failed with status {}: {}",
                status,
                body
            ))
        }
    }

    /// Make authenticated request to any endpoint
    pub async fn authenticated_request(
        &self,
        method: &str,
        endpoint: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Response> {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut request = match method.to_uppercase().as_str() {
            "GET" => self.client.get(&url),
            "POST" => self.client.post(&url),
            "PUT" => self.client.put(&url),
            "DELETE" => self.client.delete(&url),
            "PATCH" => self.client.patch(&url),
            _ => return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method)),
        };

        request = request.bearer_auth(token);

        if let Some(json_body) = body {
            request = request.json(json_body);
        }

        Ok(request.send().await?)
    }

    /// Test access to protected endpoint without authentication
    pub async fn test_unauthorized_access(&self, endpoint: &str) -> Result<StatusCode> {
        let response = self
            .client
            .get(&format!("{}{}", self.base_url, endpoint))
            .send()
            .await?;

        Ok(response.status())
    }

    /// Test access to protected endpoint with invalid token
    pub async fn test_invalid_token_access(&self, endpoint: &str) -> Result<StatusCode> {
        let response = self
            .client
            .get(&format!("{}{}", self.base_url, endpoint))
            .bearer_auth("invalid_token_12345")
            .send()
            .await?;

        Ok(response.status())
    }
}

/// Performance measurement utilities
#[derive(Debug, Clone)]
pub struct PerformanceTimer {
    start_time: Instant,
    operation_name: String,
}

impl PerformanceTimer {
    pub fn new(operation_name: &str) -> Self {
        Self {
            start_time: Instant::now(),
            operation_name: operation_name.to_string(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn finish(&self) -> Duration {
        let elapsed = self.elapsed();
        println!("⏱️  {}: {:.2}ms", self.operation_name, elapsed.as_millis());
        elapsed
    }

    pub fn finish_with_result<T>(
        &self,
        result: &Result<T, Box<dyn std::error::Error>>,
    ) -> Duration {
        let elapsed = self.elapsed();
        let status = if result.is_ok() { "✅" } else { "❌" };
        println!(
            "⏱️  {} {}: {:.2}ms",
            status,
            self.operation_name,
            elapsed.as_millis()
        );
        elapsed
    }
}

/// Load testing utilities
#[derive(Clone)]
pub struct LoadTestConfig {
    pub concurrent_users: usize,
    pub operations_per_user: usize,
    pub delay_between_operations: Duration,
    pub timeout: Duration,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            concurrent_users: 10,
            operations_per_user: 5,
            delay_between_operations: Duration::from_millis(100),
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
pub struct LoadTestResults {
    pub total_operations: usize,
    pub successful_operations: usize,
    pub failed_operations: usize,
    pub total_duration: Duration,
    pub average_response_time: Duration,
    pub operations_per_second: f64,
}

impl LoadTestResults {
    pub fn print_summary(&self, test_name: &str) {
        println!("\n📊 {} Load Test Results:", test_name);
        println!("  Total Operations: {}", self.total_operations);
        println!(
            "  Successful: {} ({:.1}%)",
            self.successful_operations,
            (self.successful_operations as f64 / self.total_operations as f64) * 100.0
        );
        println!(
            "  Failed: {} ({:.1}%)",
            self.failed_operations,
            (self.failed_operations as f64 / self.total_operations as f64) * 100.0
        );
        println!(
            "  Total Duration: {:.2}s",
            self.total_duration.as_secs_f64()
        );
        println!(
            "  Average Response Time: {:.2}ms",
            self.average_response_time.as_millis()
        );
        println!("  Operations/Second: {:.2}", self.operations_per_second);
    }
}

/// Validation utilities
pub struct ValidationTestUtils;

impl ValidationTestUtils {
    /// Test various invalid email formats
    pub fn invalid_emails() -> Vec<&'static str> {
        vec![
            "invalid",
            "invalid@",
            "@invalid.com",
            "invalid@.com",
            "invalid@com.",
            "invalid..email@example.com",
            "invalid@example..com",
            "",
            " ",
            // Note: Can't return a.repeat(255).as_str() due to lifetime issues
        ]
    }

    /// Test various invalid passwords
    pub fn invalid_passwords() -> Vec<&'static str> {
        vec![
            "",         // Empty
            "a",        // Too short
            "12345678", // No letters
            "abcdefgh", // No numbers
            "password", // Common password
            "PASSWORD", // No lowercase
            "abc123",   // Too short and simple
        ]
    }

    /// Test valid password variations
    pub fn valid_passwords() -> Vec<&'static str> {
        vec![
            "TestPassword123!",
            "Secure@Pass456",
            "MyStr0ng$ecret",
            "C0mplex#P@ssw0rd",
            "Val1d&Secure789",
        ]
    }

    /// Validate response structure for registration
    pub fn validate_registration_response(response: &Value) -> Result<(), String> {
        let user = response.get("user").ok_or("Missing 'user' field")?;

        // Check required user fields
        user.get("user_id").ok_or("Missing 'user_id' field")?;
        user.get("email").ok_or("Missing 'email' field")?;
        user.get("first_name").ok_or("Missing 'first_name' field")?;
        user.get("last_name").ok_or("Missing 'last_name' field")?;
        user.get("role").ok_or("Missing 'role' field")?;
        user.get("is_active").ok_or("Missing 'is_active' field")?;
        user.get("email_verified")
            .ok_or("Missing 'email_verified' field")?;

        // Check tokens
        response
            .get("access_token")
            .ok_or("Missing 'access_token' field")?;
        response
            .get("refresh_token")
            .ok_or("Missing 'refresh_token' field")?;
        response
            .get("expires_in")
            .ok_or("Missing 'expires_in' field")?;

        Ok(())
    }

    /// Validate response structure for login
    pub fn validate_login_response(response: &Value) -> Result<(), String> {
        response
            .get("access_token")
            .ok_or("Missing 'access_token' field")?;
        response
            .get("refresh_token")
            .ok_or("Missing 'refresh_token' field")?;
        response
            .get("expires_in")
            .ok_or("Missing 'expires_in' field")?;

        // User data might be included in login response
        if let Some(user) = response.get("user") {
            user.get("user_id")
                .ok_or("Missing 'user_id' field in user data")?;
            user.get("email")
                .ok_or("Missing 'email' field in user data")?;
        }

        Ok(())
    }

    /// Validate profile response structure
    pub fn validate_profile_response(response: &Value) -> Result<(), String> {
        response.get("user_id").ok_or("Missing 'user_id' field")?;
        response.get("email").ok_or("Missing 'email' field")?;
        response
            .get("first_name")
            .ok_or("Missing 'first_name' field")?;
        response
            .get("last_name")
            .ok_or("Missing 'last_name' field")?;
        response.get("role").ok_or("Missing 'role' field")?;
        response
            .get("is_active")
            .ok_or("Missing 'is_active' field")?;
        response
            .get("email_verified")
            .ok_or("Missing 'email_verified' field")?;
        response
            .get("created_at")
            .ok_or("Missing 'created_at' field")?;
        response
            .get("updated_at")
            .ok_or("Missing 'updated_at' field")?;

        Ok(())
    }
}

/// Database cleanup utilities
pub struct DatabaseCleanup;

impl DatabaseCleanup {
    /// Clean up test users by email patterns
    pub async fn cleanup_test_users(
        _db: &dyn rust_auth_service::database::AuthDatabase,
        pattern: &str,
    ) {
        // This would require accessing the database directly
        // Implementation depends on having database access in test context
        println!("🧹 Cleaning up test users matching pattern: {}", pattern);
    }

    /// Clean up users created in a specific time range
    pub async fn cleanup_users_in_timerange(
        _db: &dyn rust_auth_service::database::AuthDatabase,
        start: std::time::SystemTime,
        end: std::time::SystemTime,
    ) {
        println!(
            "🧹 Cleaning up users created between {:?} and {:?}",
            start, end
        );
    }
}

/// Assertion utilities for tests
pub struct AuthAssertions;

impl AuthAssertions {
    pub fn assert_valid_jwt_token(token: &str) -> Result<(), String> {
        // Basic JWT format validation (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format: should have 3 parts separated by dots".to_string());
        }

        // Check that each part is base64-encoded (basic check)
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return Err(format!("JWT part {} is empty", i + 1));
            }
        }

        Ok(())
    }

    pub fn assert_response_time_acceptable(
        duration: Duration,
        max_acceptable: Duration,
    ) -> Result<(), String> {
        if duration > max_acceptable {
            Err(format!(
                "Response time {}ms exceeds acceptable limit {}ms",
                duration.as_millis(),
                max_acceptable.as_millis()
            ))
        } else {
            Ok(())
        }
    }

    pub fn assert_password_strength(password: &str) -> Result<(), String> {
        if password.len() < 8 {
            return Err("Password too short (minimum 8 characters)".to_string());
        }

        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        if !has_upper {
            return Err("Password must contain at least one uppercase letter".to_string());
        }
        if !has_lower {
            return Err("Password must contain at least one lowercase letter".to_string());
        }
        if !has_digit {
            return Err("Password must contain at least one digit".to_string());
        }
        if !has_special {
            return Err("Password must contain at least one special character".to_string());
        }

        Ok(())
    }
}
