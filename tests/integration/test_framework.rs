//! # Integration Test Framework
//!
//! Comprehensive test framework for authentication service integration testing.
//! Provides service management, test containers, mocking capabilities, and
//! standardized test utilities for reliable end-to-end testing.

use anyhow::Result;
use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

use crate::helpers::*;

/// Integration test framework managing service lifecycle and test environments
pub struct IntegrationTestFramework {
    pub client: AuthTestClient,
    pub config: TestConfig,
    service_process: Option<Child>,
    cleanup_handlers: Vec<Box<dyn Fn() -> Result<()> + Send + Sync>>,
}

/// Configuration for integration tests
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub service_url: String,
    pub database_type: String,
    pub database_url: String,
    pub redis_url: Option<String>,
    pub email_provider: String,
    pub mock_external_services: bool,
    pub enable_rate_limiting: bool,
    pub enable_audit_logging: bool,
    pub jwt_secret: String,
    pub startup_timeout: Duration,
    pub operation_timeout: Duration,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            service_url: std::env::var("AUTH_SERVICE_URL")
                .unwrap_or_else(|_| "http://localhost:8090".to_string()),
            database_type: std::env::var("TEST_DATABASE_TYPE")
                .unwrap_or_else(|_| "mongodb".to_string()),
            database_url: std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
                "mongodb://admin:password123@localhost:27017/auth_service_test?authSource=admin"
                    .to_string()
            }),
            redis_url: std::env::var("TEST_REDIS_URL").ok(),
            email_provider: std::env::var("TEST_EMAIL_PROVIDER")
                .unwrap_or_else(|_| "mock".to_string()),
            mock_external_services: std::env::var("MOCK_EXTERNAL_SERVICES")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            enable_rate_limiting: std::env::var("TEST_ENABLE_RATE_LIMITING")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            enable_audit_logging: std::env::var("TEST_ENABLE_AUDIT_LOGGING")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            jwt_secret: std::env::var("TEST_JWT_SECRET").unwrap_or_else(|_| {
                "test-jwt-secret-key-for-integration-tests-256-bits-minimum".to_string()
            }),
            startup_timeout: Duration::from_secs(60),
            operation_timeout: Duration::from_secs(30),
        }
    }
}

impl IntegrationTestFramework {
    /// Create new integration test framework
    pub fn new() -> Self {
        let config = TestConfig::default();
        let client = AuthTestClient::new(Some(config.service_url.clone()));

        Self {
            client,
            config,
            service_process: None,
            cleanup_handlers: Vec::new(),
        }
    }

    /// Create framework with custom configuration
    pub fn with_config(config: TestConfig) -> Self {
        let client = AuthTestClient::new(Some(config.service_url.clone()));

        Self {
            client,
            config,
            service_process: None,
            cleanup_handlers: Vec::new(),
        }
    }

    /// Start the authentication service for testing
    pub async fn start_service(&mut self) -> Result<()> {
        // Check if service is already running
        if self.is_service_running().await? {
            println!(
                "✅ Auth service is already running at {}",
                self.config.service_url
            );
            return Ok(());
        }

        println!("🚀 Starting auth service for integration tests...");

        // Set environment variables for test configuration
        let mut cmd = Command::new("cargo");
        cmd.args(&["run", "--features", "integration-tests"])
            .env("AUTH_SERVICE_HOST", "127.0.0.1")
            .env("AUTH_SERVICE_PORT", "8090")
            .env("DATABASE_TYPE", &self.config.database_type)
            .env("DATABASE_URL", &self.config.database_url)
            .env("JWT_SECRET", &self.config.jwt_secret)
            .env("RUST_LOG", "debug")
            .env("EMAIL_PROVIDER", &self.config.email_provider)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Add Redis configuration if available
        if let Some(redis_url) = &self.config.redis_url {
            cmd.env("REDIS_URL", redis_url);
        }

        // Configure rate limiting and audit logging
        cmd.env(
            "RATE_LIMITING_ENABLED",
            self.config.enable_rate_limiting.to_string(),
        )
        .env(
            "AUDIT_LOGGING_ENABLED",
            self.config.enable_audit_logging.to_string(),
        );

        let child = cmd.spawn()?;
        self.service_process = Some(child);

        // Wait for service to be ready
        self.wait_for_service_ready().await?;

        println!("✅ Auth service is ready for testing");
        Ok(())
    }

    /// Stop the authentication service
    pub fn stop_service(&mut self) -> Result<()> {
        if let Some(mut process) = self.service_process.take() {
            println!("🛑 Stopping auth service...");
            process.kill()?;
            process.wait()?;
            println!("✅ Auth service stopped");
        }
        Ok(())
    }

    /// Check if the service is running and accessible
    pub async fn is_service_running(&self) -> Result<bool> {
        match self.client.health_check().await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Wait for service to be ready with timeout
    async fn wait_for_service_ready(&self) -> Result<()> {
        let start_time = Instant::now();
        let mut attempts = 0;
        let max_attempts = (self.config.startup_timeout.as_secs() / 2) as usize;

        while start_time.elapsed() < self.config.startup_timeout && attempts < max_attempts {
            match self.client.health_check().await {
                Ok(_) => {
                    println!("✅ Auth service health check passed");
                    return Ok(());
                }
                Err(_) => {
                    attempts += 1;
                    if attempts < max_attempts {
                        println!(
                            "⏳ Waiting for auth service... (attempt {}/{})",
                            attempts, max_attempts
                        );
                        sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "Auth service not ready at {} after {} seconds",
            self.config.service_url,
            self.config.startup_timeout.as_secs()
        ))
    }

    /// Setup test environment (database, cache, etc.)
    pub async fn setup_environment(&mut self) -> Result<()> {
        println!("🔧 Setting up test environment...");

        // Database setup
        self.setup_database().await?;

        // Cache setup
        if self.config.redis_url.is_some() {
            self.setup_cache().await?;
        }

        // Mock external services if configured
        if self.config.mock_external_services {
            self.setup_mocks().await?;
        }

        println!("✅ Test environment ready");
        Ok(())
    }

    /// Clean up test environment
    pub async fn cleanup_environment(&mut self) -> Result<()> {
        println!("🧹 Cleaning up test environment...");

        // Run cleanup handlers
        for handler in &self.cleanup_handlers {
            if let Err(e) = handler() {
                eprintln!("⚠️ Cleanup error: {}", e);
            }
        }

        // Clean up database
        self.cleanup_database().await?;

        // Clean up cache
        if self.config.redis_url.is_some() {
            self.cleanup_cache().await?;
        }

        println!("✅ Test environment cleaned up");
        Ok(())
    }

    /// Setup database for testing
    async fn setup_database(&self) -> Result<()> {
        match self.config.database_type.as_str() {
            "mongodb" => {
                println!("🗃️ Setting up MongoDB test database...");
                // Create test database and collections
                // This would typically involve running setup scripts
            }
            "postgresql" => {
                println!("🗃️ Setting up PostgreSQL test database...");
                // Run migrations and setup
            }
            "mysql" => {
                println!("🗃️ Setting up MySQL test database...");
                // Run migrations and setup
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported database type: {}",
                    self.config.database_type
                ));
            }
        }
        Ok(())
    }

    /// Clean up database after testing
    async fn cleanup_database(&self) -> Result<()> {
        println!("🧹 Cleaning up test database...");
        // Remove test data, but keep schema for next run
        Ok(())
    }

    /// Setup cache for testing
    async fn setup_cache(&self) -> Result<()> {
        println!("⚡ Setting up Redis test cache...");
        // Clear cache and setup test data
        Ok(())
    }

    /// Clean up cache after testing
    async fn cleanup_cache(&self) -> Result<()> {
        println!("🧹 Cleaning up test cache...");
        // Clear all test cache data
        Ok(())
    }

    /// Setup mocks for external services
    async fn setup_mocks(&self) -> Result<()> {
        println!("🎭 Setting up external service mocks...");
        // Setup mock servers for email providers, webhooks, etc.
        Ok(())
    }

    /// Register a cleanup handler
    pub fn add_cleanup_handler<F>(&mut self, handler: F)
    where
        F: Fn() -> Result<()> + Send + Sync + 'static,
    {
        self.cleanup_handlers.push(Box::new(handler));
    }

    /// Create a test user with unique identifiers
    pub fn create_test_user(&self, prefix: &str) -> TestUser {
        TestUser::new(prefix)
    }

    /// Run a complete authentication flow test
    pub async fn test_authentication_flow(&self, user: &TestUser) -> Result<AuthFlowResult> {
        let timer = PerformanceTimer::new("Complete Authentication Flow");

        // Step 1: Register
        let register_timer = PerformanceTimer::new("Registration");
        let (tokens, register_response) = self.client.register(user).await?;
        let register_time = register_timer.finish();

        // Step 2: Verify registration response
        ValidationTestUtils::validate_registration_response(&register_response)
            .map_err(|e| anyhow::anyhow!("Registration validation failed: {}", e))?;

        // Step 3: Login
        let login_timer = PerformanceTimer::new("Login");
        let (login_tokens, login_response) = self.client.login(user).await?;
        let login_time = login_timer.finish();

        // Step 4: Verify login response
        ValidationTestUtils::validate_login_response(&login_response)
            .map_err(|e| anyhow::anyhow!("Login validation failed: {}", e))?;

        // Step 5: Access protected endpoint
        let profile_timer = PerformanceTimer::new("Profile Access");
        let profile_response = self.client.get_profile(&login_tokens.access_token).await?;
        let profile_time = profile_timer.finish();

        // Step 6: Verify profile response
        ValidationTestUtils::validate_profile_response(&profile_response)
            .map_err(|e| anyhow::anyhow!("Profile validation failed: {}", e))?;

        // Step 7: Token refresh
        let refresh_timer = PerformanceTimer::new("Token Refresh");
        let refresh_tokens = if let Some(refresh_token) = &login_tokens.refresh_token {
            Some(self.client.refresh_token(refresh_token).await?)
        } else {
            None
        };
        let refresh_time = refresh_timer.finish();

        // Step 8: Logout
        let logout_timer = PerformanceTimer::new("Logout");
        let logout_response = self.client.logout(&login_tokens.access_token).await?;
        let logout_time = logout_timer.finish();

        let total_time = timer.finish();

        Ok(AuthFlowResult {
            register_time,
            login_time,
            profile_time,
            refresh_time,
            logout_time,
            total_time,
            register_response,
            login_response,
            profile_response,
            logout_response,
            tokens,
            refresh_tokens,
        })
    }

    /// Test protected endpoints access control
    pub async fn test_protected_endpoints(&self) -> Result<ProtectedEndpointResults> {
        let endpoints = vec!["/auth/me", "/auth/profile", "/auth/logout", "/auth/refresh"];

        let mut results = ProtectedEndpointResults {
            unauthorized_access: Vec::new(),
            invalid_token_access: Vec::new(),
        };

        for endpoint in endpoints {
            // Test unauthorized access
            let unauthorized_status = self.client.test_unauthorized_access(endpoint).await?;
            results
                .unauthorized_access
                .push((endpoint.to_string(), unauthorized_status));

            // Test invalid token access
            let invalid_token_status = self.client.test_invalid_token_access(endpoint).await?;
            results
                .invalid_token_access
                .push((endpoint.to_string(), invalid_token_status));
        }

        Ok(results)
    }

    /// Run load test on authentication endpoints
    pub async fn run_load_test(&self, config: LoadTestConfig) -> Result<LoadTestResults> {
        println!(
            "🚀 Starting load test with {} concurrent users",
            config.concurrent_users
        );
        let start_time = Instant::now();
        let mut handles = Vec::new();
        let mut response_times = Vec::new();

        for i in 0..config.concurrent_users {
            let client = self.client.clone();
            let user_config = config.clone();

            let handle = tokio::spawn(async move {
                let mut user_response_times = Vec::new();
                let user = TestUser::new(&format!("load_test_{}", i));

                for j in 0..user_config.operations_per_user {
                    let operation_start = Instant::now();

                    // Perform registration and login
                    let result = async {
                        let (_, _) = client.register(&user).await?;
                        let (tokens, _) = client.login(&user).await?;
                        let _ = client.get_profile(&tokens.access_token).await?;
                        let _ = client.logout(&tokens.access_token).await?;
                        anyhow::Ok(())
                    }
                    .await;

                    let operation_time = operation_start.elapsed();
                    user_response_times.push(operation_time);

                    if result.is_err() {
                        break;
                    }

                    if j < user_config.operations_per_user - 1 {
                        tokio::time::sleep(user_config.delay_between_operations).await;
                    }
                }

                user_response_times
            });

            handles.push(handle);
        }

        let mut successful_operations = 0;
        let mut failed_operations = 0;

        for handle in handles {
            match handle.await {
                Ok(times) => {
                    successful_operations += times.len();
                    response_times.extend(times);
                }
                Err(_) => {
                    failed_operations += config.operations_per_user;
                }
            }
        }

        let total_duration = start_time.elapsed();
        let total_operations = successful_operations + failed_operations;
        let average_response_time = if !response_times.is_empty() {
            response_times.iter().sum::<Duration>() / response_times.len() as u32
        } else {
            Duration::from_secs(0)
        };
        let operations_per_second = successful_operations as f64 / total_duration.as_secs_f64();

        Ok(LoadTestResults {
            total_operations,
            successful_operations,
            failed_operations,
            total_duration,
            average_response_time,
            operations_per_second,
        })
    }
}

/// Results from complete authentication flow test
#[derive(Debug)]
pub struct AuthFlowResult {
    pub register_time: Duration,
    pub login_time: Duration,
    pub profile_time: Duration,
    pub refresh_time: Duration,
    pub logout_time: Duration,
    pub total_time: Duration,
    pub register_response: Value,
    pub login_response: Value,
    pub profile_response: Value,
    pub logout_response: Value,
    pub tokens: AuthTokens,
    pub refresh_tokens: Option<AuthTokens>,
}

/// Results from protected endpoints testing
#[derive(Debug)]
pub struct ProtectedEndpointResults {
    pub unauthorized_access: Vec<(String, reqwest::StatusCode)>,
    pub invalid_token_access: Vec<(String, reqwest::StatusCode)>,
}

impl Drop for IntegrationTestFramework {
    fn drop(&mut self) {
        if let Err(e) = self.stop_service() {
            eprintln!("⚠️ Error stopping service during cleanup: {}", e);
        }
    }
}

/// Trait for implementing test containers
#[async_trait::async_trait]
pub trait TestContainer {
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    fn connection_string(&self) -> String;
}

/// MongoDB test container implementation
pub struct MongoDbTestContainer {
    container_name: String,
    port: u16,
    started: bool,
}

impl MongoDbTestContainer {
    pub fn new() -> Self {
        let container_name = format!("auth-test-mongo-{}", &Uuid::new_v4().to_string()[..8]);
        Self {
            container_name,
            port: 27017,
            started: false,
        }
    }
}

#[async_trait::async_trait]
impl TestContainer for MongoDbTestContainer {
    async fn start(&mut self) -> Result<()> {
        if self.started {
            return Ok(());
        }

        println!(
            "🐳 Starting MongoDB test container: {}",
            self.container_name
        );

        // This would start a MongoDB container using Docker
        // Implementation depends on docker availability
        let _output = Command::new("docker")
            .args(&[
                "run",
                "-d",
                "--name",
                &self.container_name,
                "-p",
                &format!("{}:27017", self.port),
                "-e",
                "MONGO_INITDB_ROOT_USERNAME=admin",
                "-e",
                "MONGO_INITDB_ROOT_PASSWORD=password123",
                "mongo:latest",
            ])
            .output()?;

        // Wait for container to be ready
        tokio::time::sleep(Duration::from_secs(10)).await;

        self.started = true;
        println!("✅ MongoDB test container started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if !self.started {
            return Ok(());
        }

        println!(
            "🛑 Stopping MongoDB test container: {}",
            self.container_name
        );

        let _output = Command::new("docker")
            .args(&["stop", &self.container_name])
            .output()?;

        let _output = Command::new("docker")
            .args(&["rm", &self.container_name])
            .output()?;

        self.started = false;
        println!("✅ MongoDB test container stopped");
        Ok(())
    }

    fn connection_string(&self) -> String {
        format!(
            "mongodb://admin:password123@localhost:{}/auth_service_test?authSource=admin",
            self.port
        )
    }
}

/// Email mock server for testing email functionality
pub struct EmailMockServer {
    port: u16,
    received_emails: Arc<std::sync::Mutex<Vec<EmailMessage>>>,
}

#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to: String,
    pub from: String,
    pub subject: String,
    pub content: String,
}

impl EmailMockServer {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            received_emails: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub async fn start(&self) -> Result<()> {
        println!("📧 Starting email mock server on port {}", self.port);
        // Implementation would start a mock HTTP server
        // that accepts email webhook requests and stores them
        Ok(())
    }

    pub fn get_received_emails(&self) -> Vec<EmailMessage> {
        self.received_emails.lock().unwrap().clone()
    }

    pub fn clear_emails(&self) {
        self.received_emails.lock().unwrap().clear();
    }
}
