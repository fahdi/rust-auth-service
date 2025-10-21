use anyhow::Result;
use reqwest::Client;
#[allow(unused_imports)]
use rust_auth_service::{
    config::Config,
    database::create_database,
    models::user::{CreateUserRequest, UserRole},
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
#[allow(unused_imports)]
use tokio::time::sleep;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("🚀 Starting comprehensive API endpoint testing...");

    // Test configurations for different databases
    let database_configs = vec![
        (
            "PostgreSQL",
            "postgresql://postgres:password@localhost:5432/rust_auth_service",
        ),
        (
            "MySQL",
            "mysql://root:password@localhost:3306/rust_auth_service",
        ),
        ("MongoDB", "mongodb://localhost:27017/rust_auth_service"),
    ];

    for (db_name, db_url) in database_configs {
        info!("\n=== Testing with {} ===", db_name);

        match test_database_endpoints(db_name, db_url).await {
            Ok(stats) => {
                info!("✅ {} endpoint tests completed successfully", db_name);
                info!("📊 Performance Stats:");
                info!("   Total requests: {}", stats.total_requests);
                info!("   Average response time: {:.2}ms", stats.avg_response_time);
                info!("   Success rate: {:.1}%", stats.success_rate);
            }
            Err(e) => {
                error!("❌ {} endpoint tests failed: {}", db_name, e);
            }
        }
    }

    info!("\n🎯 Endpoint testing completed!");
    Ok(())
}

#[derive(Debug)]
struct TestStats {
    total_requests: u32,
    successful_requests: u32,
    avg_response_time: f64,
    success_rate: f64,
}

impl TestStats {
    fn new() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            avg_response_time: 0.0,
            success_rate: 0.0,
        }
    }

    fn add_request(&mut self, success: bool, response_time: Duration) {
        self.total_requests += 1;
        if success {
            self.successful_requests += 1;
        }

        let old_avg = self.avg_response_time;
        let new_time = response_time.as_millis() as f64;
        self.avg_response_time =
            (old_avg * (self.total_requests - 1) as f64 + new_time) / self.total_requests as f64;
        self.success_rate = (self.successful_requests as f64 / self.total_requests as f64) * 100.0;
    }
}

async fn test_database_endpoints(db_name: &str, db_url: &str) -> Result<TestStats> {
    let mut stats = TestStats::new();

    // Start the auth service with the specific database
    info!("Starting auth service with {}...", db_name);

    // Set up environment for this database
    std::env::set_var("DATABASE_URL", db_url);
    std::env::set_var(
        "DATABASE_TYPE",
        match db_name {
            "PostgreSQL" => "postgresql",
            "MySQL" => "mysql",
            "MongoDB" => "mongodb",
            _ => "postgresql",
        },
    );

    // Wait for service to start (in a real test, we'd spawn the service)
    // For now, we'll assume it's running on localhost:3000
    let base_url = "http://localhost:3000";
    let client = Client::new();

    // Test 1: Health check
    info!("Testing health endpoints...");
    test_health_endpoints(&client, base_url, &mut stats).await?;

    // Test 2: User registration flow
    info!("Testing registration flow...");
    let user_data = test_registration_flow(&client, base_url, &mut stats).await?;

    // Test 3: Login flow
    info!("Testing login flow...");
    let auth_data = test_login_flow(&client, base_url, &user_data, &mut stats).await?;

    // Test 4: Protected endpoints
    info!("Testing protected endpoints...");
    test_protected_endpoints(&client, base_url, &auth_data, &mut stats).await?;

    // Test 5: Password reset flow
    info!("Testing password reset flow...");
    test_password_reset_flow(&client, base_url, &user_data, &mut stats).await?;

    // Test 6: Error handling
    info!("Testing error handling...");
    test_error_scenarios(&client, base_url, &mut stats).await?;

    // Test 7: Performance under load
    info!("Testing performance under load...");
    test_performance_load(&client, base_url, &mut stats).await?;

    Ok(stats)
}

async fn test_health_endpoints(
    client: &Client,
    base_url: &str,
    stats: &mut TestStats,
) -> Result<()> {
    let endpoints = vec!["/health", "/ready", "/live"];

    for endpoint in endpoints {
        let start = Instant::now();
        let response = client.get(format!("{base_url}{endpoint}")).send().await;
        let duration = start.elapsed();

        match response {
            Ok(resp) if resp.status().is_success() => {
                stats.add_request(true, duration);
                info!("✅ {} - {}ms", endpoint, duration.as_millis());
            }
            Ok(resp) => {
                stats.add_request(false, duration);
                warn!(
                    "⚠️ {} - Status: {} - {}ms",
                    endpoint,
                    resp.status(),
                    duration.as_millis()
                );
            }
            Err(e) => {
                stats.add_request(false, duration);
                error!(
                    "❌ {} - Error: {} - {}ms",
                    endpoint,
                    e,
                    duration.as_millis()
                );
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct UserTestData {
    email: String,
    password: String,
    first_name: String,
    last_name: String,
}

async fn test_registration_flow(
    client: &Client,
    base_url: &str,
    stats: &mut TestStats,
) -> Result<UserTestData> {
    let user_data = UserTestData {
        email: format!("test_{}@example.com", chrono::Utc::now().timestamp()),
        password: "SecurePassword123!".to_string(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
    };

    let registration_payload = json!({
        "email": user_data.email,
        "password": user_data.password,
        "first_name": user_data.first_name,
        "last_name": user_data.last_name,
        "role": "user"
    });

    let start = Instant::now();
    let response = client
        .post(format!("{}/auth/register", base_url))
        .json(&registration_payload)
        .send()
        .await;
    let duration = start.elapsed();

    match response {
        Ok(resp) if resp.status().is_success() => {
            stats.add_request(true, duration);
            let body: Value = resp.json().await?;
            info!("✅ Registration successful - {}ms", duration.as_millis());
            info!("   Response: {}", serde_json::to_string_pretty(&body)?);
        }
        Ok(resp) => {
            stats.add_request(false, duration);
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                "⚠️ Registration failed - Status: {} - {}ms",
                status,
                duration.as_millis()
            );
            warn!("   Response: {}", body);
        }
        Err(e) => {
            stats.add_request(false, duration);
            error!("❌ Registration error - {} - {}ms", e, duration.as_millis());
            return Err(e.into());
        }
    }

    Ok(user_data)
}

#[derive(Debug, Clone)]
struct AuthTestData {
    access_token: String,
    #[allow(dead_code)]
    refresh_token: String,
    #[allow(dead_code)]
    user_id: String,
}

async fn test_login_flow(
    client: &Client,
    base_url: &str,
    user_data: &UserTestData,
    stats: &mut TestStats,
) -> Result<AuthTestData> {
    let login_payload = json!({
        "email": user_data.email,
        "password": user_data.password
    });

    let start = Instant::now();
    let response = client
        .post(format!("{}/auth/login", base_url))
        .json(&login_payload)
        .send()
        .await;
    let duration = start.elapsed();

    match response {
        Ok(resp) if resp.status().is_success() => {
            stats.add_request(true, duration);
            let body: Value = resp.json().await?;
            info!("✅ Login successful - {}ms", duration.as_millis());

            // Extract auth data
            let access_token = body["access_token"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let refresh_token = body["refresh_token"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let user_id = body["user"]["user_id"]
                .as_str()
                .unwrap_or_default()
                .to_string();

            Ok(AuthTestData {
                access_token,
                refresh_token,
                user_id,
            })
        }
        Ok(resp) => {
            stats.add_request(false, duration);
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                "⚠️ Login failed - Status: {} - {}ms",
                status,
                duration.as_millis()
            );
            warn!("   Response: {}", body);
            Err(anyhow::anyhow!("Login failed with status: {}", status))
        }
        Err(e) => {
            stats.add_request(false, duration);
            error!("❌ Login error - {} - {}ms", e, duration.as_millis());
            Err(e.into())
        }
    }
}

async fn test_protected_endpoints(
    client: &Client,
    base_url: &str,
    auth_data: &AuthTestData,
    stats: &mut TestStats,
) -> Result<()> {
    let endpoints = vec![("GET", "/auth/me"), ("POST", "/auth/logout")];

    for (method, endpoint) in endpoints {
        let start = Instant::now();

        let request = match method {
            "GET" => client.get(format!("{base_url}{endpoint}")),
            "POST" => client.post(format!("{base_url}{endpoint}")),
            "PUT" => client.put(format!("{base_url}{endpoint}")),
            _ => continue,
        };

        let response = request
            .header(
                "Authorization",
                format!("Bearer {}", auth_data.access_token),
            )
            .send()
            .await;

        let duration = start.elapsed();

        match response {
            Ok(resp) if resp.status().is_success() => {
                stats.add_request(true, duration);
                let _body: Value = resp.json().await?;
                info!("✅ {} {} - {}ms", method, endpoint, duration.as_millis());
            }
            Ok(resp) => {
                stats.add_request(false, duration);
                let status = resp.status();
                let _body = resp.text().await.unwrap_or_default();
                warn!(
                    "⚠️ {} {} failed - Status: {} - {}ms",
                    method,
                    endpoint,
                    status,
                    duration.as_millis()
                );
            }
            Err(e) => {
                stats.add_request(false, duration);
                error!(
                    "❌ {} {} error - {} - {}ms",
                    method,
                    endpoint,
                    e,
                    duration.as_millis()
                );
            }
        }
    }

    Ok(())
}

async fn test_password_reset_flow(
    client: &Client,
    base_url: &str,
    user_data: &UserTestData,
    stats: &mut TestStats,
) -> Result<()> {
    // Step 1: Request password reset
    let reset_request = json!({
        "email": user_data.email
    });

    let start = Instant::now();
    let response = client
        .post(format!("{}/auth/forgot-password", base_url))
        .json(&reset_request)
        .send()
        .await;
    let duration = start.elapsed();

    match response {
        Ok(resp) if resp.status().is_success() => {
            stats.add_request(true, duration);
            info!("✅ Password reset request - {}ms", duration.as_millis());
        }
        Ok(resp) => {
            stats.add_request(false, duration);
            warn!(
                "⚠️ Password reset request failed - Status: {} - {}ms",
                resp.status(),
                duration.as_millis()
            );
        }
        Err(e) => {
            stats.add_request(false, duration);
            error!(
                "❌ Password reset request error - {} - {}ms",
                e,
                duration.as_millis()
            );
        }
    }

    // Note: We can't test the actual reset without email integration
    // This tests the endpoint availability and basic validation

    Ok(())
}

async fn test_error_scenarios(
    client: &Client,
    base_url: &str,
    stats: &mut TestStats,
) -> Result<()> {
    let error_tests = vec![
        (
            "Invalid login",
            json!({"email": "invalid@test.com", "password": "wrong"}),
            "/auth/login",
        ),
        (
            "Invalid registration",
            json!({"email": "invalid-email", "password": "123"}),
            "/auth/register",
        ),
        ("Unauthorized access", json!({}), "/auth/me"),
    ];

    for (test_name, payload, endpoint) in error_tests {
        let start = Instant::now();

        let response = if endpoint == "/auth/me" {
            client.get(format!("{base_url}{endpoint}")).send().await
        } else {
            client
                .post(format!("{base_url}{endpoint}"))
                .json(&payload)
                .send()
                .await
        };

        let duration = start.elapsed();

        match response {
            Ok(resp) if resp.status().is_client_error() => {
                stats.add_request(true, duration); // Expected error
                info!(
                    "✅ {} - Expected error {} - {}ms",
                    test_name,
                    resp.status(),
                    duration.as_millis()
                );
            }
            Ok(resp) => {
                stats.add_request(false, duration);
                warn!(
                    "⚠️ {} - Unexpected status {} - {}ms",
                    test_name,
                    resp.status(),
                    duration.as_millis()
                );
            }
            Err(e) => {
                stats.add_request(false, duration);
                error!(
                    "❌ {} - Connection error {} - {}ms",
                    test_name,
                    e,
                    duration.as_millis()
                );
            }
        }
    }

    Ok(())
}

async fn test_performance_load(
    client: &Client,
    base_url: &str,
    stats: &mut TestStats,
) -> Result<()> {
    info!("Running performance load test (100 requests)...");

    let mut handles = vec![];
    let client = client.clone();
    let base_url = base_url.to_string();

    // Create 100 concurrent health check requests
    for i in 0..100 {
        let client = client.clone();
        let base_url = base_url.clone();

        let handle = tokio::spawn(async move {
            let start = Instant::now();
            let response = client.get(format!("{}/health", base_url)).send().await;
            let duration = start.elapsed();

            match response {
                Ok(resp) if resp.status().is_success() => (true, duration, i),
                _ => (false, duration, i),
            }
        });

        handles.push(handle);
    }

    // Collect results
    let mut successful = 0;
    let mut total_time = Duration::new(0, 0);

    for handle in handles {
        let (success, duration, _) = handle.await?;
        stats.add_request(success, duration);
        total_time += duration;
        if success {
            successful += 1;
        }
    }

    info!("📊 Load test results:");
    info!("   Successful requests: {}/100", successful);
    info!(
        "   Average response time: {:.2}ms",
        total_time.as_millis() as f64 / 100.0
    );
    info!(
        "   Success rate: {:.1}%",
        (successful as f64 / 100.0) * 100.0
    );

    Ok(())
}
