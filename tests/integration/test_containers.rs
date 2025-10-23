//! # Test Containers Integration
//!
//! Implementation of test containers for integration testing.
//! Provides automated setup and teardown of external services like databases,
//! Redis, and email servers for reliable integration testing.

use anyhow::Result;
use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

/// Test container management for integration tests
pub struct TestContainerManager {
    containers: HashMap<String, Box<dyn TestContainer>>,
    networks: Vec<String>,
}

impl TestContainerManager {
    pub fn new() -> Self {
        Self {
            containers: HashMap::new(),
            networks: Vec::new(),
        }
    }

    /// Start a MongoDB test container
    pub async fn start_mongodb(&mut self, name: &str) -> Result<String> {
        let mut container = Box::new(MongoDbContainer::new(name));
        container.start().await?;
        let connection_string = container.connection_string();
        self.containers.insert(name.to_string(), container);
        Ok(connection_string)
    }

    /// Start a Redis test container
    pub async fn start_redis(&mut self, name: &str) -> Result<String> {
        let mut container = Box::new(RedisContainer::new(name));
        container.start().await?;
        let connection_string = container.connection_string();
        self.containers.insert(name.to_string(), container);
        Ok(connection_string)
    }

    /// Start a mock email server
    pub async fn start_email_mock(&mut self, name: &str) -> Result<String> {
        let mut container = Box::new(EmailMockContainer::new(name));
        container.start().await?;
        let connection_string = container.connection_string();
        self.containers.insert(name.to_string(), container);
        Ok(connection_string)
    }

    /// Stop all containers and clean up
    pub async fn cleanup(&mut self) -> Result<()> {
        for (name, mut container) in self.containers.drain() {
            println!("🧹 Stopping container: {}", name);
            if let Err(e) = container.stop().await {
                eprintln!("⚠️ Error stopping container {}: {}", name, e);
            }
        }

        // Clean up networks
        for network in &self.networks {
            let _ = Command::new("docker")
                .args(&["network", "rm", network])
                .output();
        }
        self.networks.clear();

        Ok(())
    }

    /// Create a test network for containers
    pub async fn create_network(&mut self, name: &str) -> Result<()> {
        let output = Command::new("docker")
            .args(&["network", "create", name])
            .output()?;

        if output.status.success() {
            self.networks.push(name.to_string());
            println!("🌐 Created test network: {}", name);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to create network: {}", name))
        }
    }

    /// Check if Docker is available
    pub fn is_docker_available() -> bool {
        Command::new("docker")
            .args(&["--version"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

impl Drop for TestContainerManager {
    fn drop(&mut self) {
        // Best effort cleanup
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.block_on(async {
                let _ = self.cleanup().await;
            });
        }
    }
}

/// Trait for test containers
#[async_trait::async_trait]
pub trait TestContainer: Send + Sync {
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    fn connection_string(&self) -> String;
    fn is_running(&self) -> bool;
}

/// MongoDB test container
pub struct MongoDbContainer {
    name: String,
    port: u16,
    container_id: Option<String>,
    started: bool,
}

impl MongoDbContainer {
    pub fn new(name: &str) -> Self {
        Self {
            name: format!("test-mongo-{}-{}", name, &Uuid::new_v4().to_string()[..8]),
            port: 27017,
            container_id: None,
            started: false,
        }
    }

    async fn wait_for_ready(&self) -> Result<()> {
        let start_time = Instant::now();
        let timeout = Duration::from_secs(30);

        while start_time.elapsed() < timeout {
            let output = Command::new("docker")
                .args(&[
                    "exec",
                    &self.name,
                    "mongosh",
                    "--eval",
                    "db.adminCommand('ping')",
                ])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    println!("✅ MongoDB container {} is ready", self.name);
                    return Ok(());
                }
            }

            sleep(Duration::from_secs(2)).await;
        }

        Err(anyhow::anyhow!(
            "MongoDB container {} not ready after 30 seconds",
            self.name
        ))
    }
}

#[async_trait::async_trait]
impl TestContainer for MongoDbContainer {
    async fn start(&mut self) -> Result<()> {
        if self.started {
            return Ok(());
        }

        if !TestContainerManager::is_docker_available() {
            return Err(anyhow::anyhow!("Docker is not available"));
        }

        println!("🐳 Starting MongoDB container: {}", self.name);

        let output = Command::new("docker")
            .args(&[
                "run",
                "-d",
                "--name",
                &self.name,
                "-p",
                &format!("{}:27017", self.port),
                "-e",
                "MONGO_INITDB_ROOT_USERNAME=admin",
                "-e",
                "MONGO_INITDB_ROOT_PASSWORD=password123",
                "mongo:7-jammy",
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to start MongoDB container: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        self.container_id = Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        self.started = true;

        // Wait for MongoDB to be ready
        self.wait_for_ready().await?;

        println!("✅ MongoDB container {} started successfully", self.name);
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if !self.started {
            return Ok(());
        }

        println!("🛑 Stopping MongoDB container: {}", self.name);

        let _ = Command::new("docker")
            .args(&["stop", &self.name])
            .output()?;

        let _ = Command::new("docker").args(&["rm", &self.name]).output()?;

        self.started = false;
        self.container_id = None;
        println!("✅ MongoDB container {} stopped", self.name);
        Ok(())
    }

    fn connection_string(&self) -> String {
        format!(
            "mongodb://admin:password123@localhost:{}/auth_service_test?authSource=admin",
            self.port
        )
    }

    fn is_running(&self) -> bool {
        self.started
    }
}

/// Redis test container
pub struct RedisContainer {
    name: String,
    port: u16,
    container_id: Option<String>,
    started: bool,
}

impl RedisContainer {
    pub fn new(name: &str) -> Self {
        Self {
            name: format!("test-redis-{}-{}", name, &Uuid::new_v4().to_string()[..8]),
            port: 6379,
            container_id: None,
            started: false,
        }
    }

    async fn wait_for_ready(&self) -> Result<()> {
        let start_time = Instant::now();
        let timeout = Duration::from_secs(20);

        while start_time.elapsed() < timeout {
            let output = Command::new("docker")
                .args(&["exec", &self.name, "redis-cli", "ping"])
                .output();

            if let Ok(output) = output {
                if output.status.success()
                    && String::from_utf8_lossy(&output.stdout).trim() == "PONG"
                {
                    println!("✅ Redis container {} is ready", self.name);
                    return Ok(());
                }
            }

            sleep(Duration::from_secs(1)).await;
        }

        Err(anyhow::anyhow!(
            "Redis container {} not ready after 20 seconds",
            self.name
        ))
    }
}

#[async_trait::async_trait]
impl TestContainer for RedisContainer {
    async fn start(&mut self) -> Result<()> {
        if self.started {
            return Ok(());
        }

        if !TestContainerManager::is_docker_available() {
            return Err(anyhow::anyhow!("Docker is not available"));
        }

        println!("🐳 Starting Redis container: {}", self.name);

        let output = Command::new("docker")
            .args(&[
                "run",
                "-d",
                "--name",
                &self.name,
                "-p",
                &format!("{}:6379", self.port),
                "redis:7-alpine",
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to start Redis container: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        self.container_id = Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        self.started = true;

        // Wait for Redis to be ready
        self.wait_for_ready().await?;

        println!("✅ Redis container {} started successfully", self.name);
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if !self.started {
            return Ok(());
        }

        println!("🛑 Stopping Redis container: {}", self.name);

        let _ = Command::new("docker")
            .args(&["stop", &self.name])
            .output()?;

        let _ = Command::new("docker").args(&["rm", &self.name]).output()?;

        self.started = false;
        self.container_id = None;
        println!("✅ Redis container {} stopped", self.name);
        Ok(())
    }

    fn connection_string(&self) -> String {
        format!("redis://localhost:{}", self.port)
    }

    fn is_running(&self) -> bool {
        self.started
    }
}

/// Mock email server container
pub struct EmailMockContainer {
    name: String,
    port: u16,
    container_id: Option<String>,
    started: bool,
    process: Option<Child>,
}

impl EmailMockContainer {
    pub fn new(name: &str) -> Self {
        Self {
            name: format!(
                "test-email-mock-{}-{}",
                name,
                &Uuid::new_v4().to_string()[..8]
            ),
            port: 1080,
            container_id: None,
            started: false,
            process: None,
        }
    }

    async fn wait_for_ready(&self) -> Result<()> {
        let start_time = Instant::now();
        let timeout = Duration::from_secs(15);

        while start_time.elapsed() < timeout {
            let client = reqwest::Client::new();
            let health_check = client
                .get(&format!("http://localhost:{}/health", self.port))
                .send()
                .await;

            if health_check.is_ok() {
                println!("✅ Email mock server {} is ready", self.name);
                return Ok(());
            }

            sleep(Duration::from_secs(1)).await;
        }

        Err(anyhow::anyhow!(
            "Email mock server {} not ready after 15 seconds",
            self.name
        ))
    }
}

#[async_trait::async_trait]
impl TestContainer for EmailMockContainer {
    async fn start(&mut self) -> Result<()> {
        if self.started {
            return Ok(());
        }

        println!("📧 Starting email mock server: {}", self.name);

        // Start a simple Python HTTP server that acts as an email mock
        let child = Command::new("python3")
            .args(&[
                "-c",
                &format!(
                    r#"
import http.server
import socketserver
import json
from urllib.parse import urlparse, parse_qs

class EmailMockHandler(http.server.BaseHTTPRequestHandler):
    emails = []
    
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{{"status": "ok"}}')
        elif self.path == '/emails':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(self.emails).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path.startswith('/send'):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                email_data = json.loads(post_data.decode())
                self.emails.append(email_data)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{{"message": "Email sent"}}')
            except:
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass  # Suppress logs

with socketserver.TCPServer(("", {}), EmailMockHandler) as httpd:
    httpd.serve_forever()
"#,
                    self.port
                ),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        self.process = Some(child);
        self.started = true;

        // Wait for server to be ready
        self.wait_for_ready().await?;

        println!("✅ Email mock server {} started successfully", self.name);
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if !self.started {
            return Ok(());
        }

        println!("🛑 Stopping email mock server: {}", self.name);

        if let Some(mut process) = self.process.take() {
            let _ = process.kill();
            let _ = process.wait();
        }

        self.started = false;
        println!("✅ Email mock server {} stopped", self.name);
        Ok(())
    }

    fn connection_string(&self) -> String {
        format!("http://localhost:{}", self.port)
    }

    fn is_running(&self) -> bool {
        self.started
    }
}

/// Integration test with containers
pub async fn run_test_with_containers<F, Fut>(test_name: &str, test_fn: F) -> Result<()>
where
    F: FnOnce(TestContainerManager) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    println!("🚀 Starting integration test: {}", test_name);

    let container_manager = TestContainerManager::new();

    // Check if Docker is available
    if !TestContainerManager::is_docker_available() {
        println!(
            "⚠️ Docker not available, skipping container-based test: {}",
            test_name
        );
        return Ok(());
    }

    let result = test_fn(container_manager).await;

    match result {
        Ok(_) => {
            println!("✅ Integration test completed successfully: {}", test_name);
            Ok(())
        }
        Err(e) => {
            println!("❌ Integration test failed: {} - {}", test_name, e);
            Err(e)
        }
    }
}

/// Test with MongoDB container
#[tokio::test]
#[cfg(feature = "test-containers")]
async fn test_with_mongodb_container() -> Result<()> {
    run_test_with_containers("MongoDB Container Test", |containers| async move {
        let mut containers = containers;
        // Start MongoDB container
        let mongo_connection = containers.start_mongodb("test").await?;
        println!("📊 MongoDB connection: {}", mongo_connection);

        // Test connection (this would typically involve actual database operations)
        assert!(mongo_connection.contains("mongodb://"));
        assert!(mongo_connection.contains("auth_service_test"));

        println!("✅ MongoDB container test completed");
        Ok(())
    })
    .await
}

/// Test with Redis container
#[tokio::test]
#[cfg(feature = "test-containers")]
async fn test_with_redis_container() -> Result<()> {
    run_test_with_containers("Redis Container Test", |containers| async move {
        let mut containers = containers;
        // Start Redis container
        let redis_connection = containers.start_redis("test").await?;
        println!("⚡ Redis connection: {}", redis_connection);

        // Test connection
        assert!(redis_connection.contains("redis://"));
        assert!(redis_connection.contains("localhost"));

        println!("✅ Redis container test completed");
        Ok(())
    })
    .await
}

/// Test with email mock container
#[tokio::test]
#[cfg(feature = "test-containers")]
async fn test_with_email_mock_container() -> Result<()> {
    run_test_with_containers("Email Mock Container Test", |containers| async move {
        let mut containers = containers;
        // Start email mock server
        let email_endpoint = containers.start_email_mock("test").await?;
        println!("📧 Email mock endpoint: {}", email_endpoint);

        // Test mock server
        let client = reqwest::Client::new();
        let health_response = client
            .get(format!("{}/health", email_endpoint))
            .send()
            .await?;

        assert!(health_response.status().is_success());

        // Test sending mock email
        let email_data = serde_json::json!({
            "to": "test@example.com",
            "subject": "Test Email",
            "body": "This is a test email"
        });

        let send_response = client
            .post(format!("{}/send", email_endpoint))
            .json(&email_data)
            .send()
            .await?;

        assert!(send_response.status().is_success());

        // Verify email was received
        let emails_response = client
            .get(format!("{}/emails", email_endpoint))
            .send()
            .await?;

        assert!(emails_response.status().is_success());
        let emails: serde_json::Value = emails_response.json().await?;
        assert!(!emails.as_array().unwrap().is_empty());

        println!("✅ Email mock container test completed");
        Ok(())
    })
    .await
}
