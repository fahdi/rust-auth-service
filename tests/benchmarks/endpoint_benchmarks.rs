//! # Endpoint Performance Benchmarks
//!
//! Comprehensive performance benchmarks for all authentication service endpoints.
//! Tests specific response time and throughput targets from Issue #43.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::helpers::*;
use crate::integration::test_framework::*;

/// Performance targets from Issue #43
pub struct PerformanceTargets {
    pub auth_p95_ms: u64,           // <100ms P95
    pub registration_p95_ms: u64,   // <200ms P95
    pub password_reset_p95_ms: u64, // <150ms P95
    pub profile_p95_ms: u64,        // <50ms P95
    pub health_p95_ms: u64,         // <10ms P95
    pub login_rps: f64,             // >1000 RPS
    pub registration_rps: f64,      // >500 RPS
    pub protected_rps: f64,         // >2000 RPS
    pub health_rps: f64,            // >10000 RPS
}

impl Default for PerformanceTargets {
    fn default() -> Self {
        Self {
            auth_p95_ms: 100,
            registration_p95_ms: 200,
            password_reset_p95_ms: 150,
            profile_p95_ms: 50,
            health_p95_ms: 10,
            login_rps: 1000.0,
            registration_rps: 500.0,
            protected_rps: 2000.0,
            health_rps: 10000.0,
        }
    }
}

/// Detailed performance metrics collection
#[derive(Debug, Clone)]
pub struct EndpointMetrics {
    pub endpoint: String,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub response_times: Vec<Duration>,
    pub error_codes: HashMap<u16, usize>,
    pub test_duration: Duration,
}

impl EndpointMetrics {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            response_times: Vec::new(),
            error_codes: HashMap::new(),
            test_duration: Duration::from_secs(0),
        }
    }

    pub fn add_result(&mut self, success: bool, response_time: Duration, status_code: Option<u16>) {
        self.total_requests += 1;
        self.response_times.push(response_time);
        
        if success {
            self.successful_requests += 1;
        } else {
            self.failed_requests += 1;
            if let Some(code) = status_code {
                *self.error_codes.entry(code).or_insert(0) += 1;
            }
        }
    }

    pub fn calculate_percentiles(&self) -> (Duration, Duration, Duration) {
        if self.response_times.is_empty() {
            return (Duration::from_secs(0), Duration::from_secs(0), Duration::from_secs(0));
        }

        let mut sorted_times = self.response_times.clone();
        sorted_times.sort();

        let p95_idx = (sorted_times.len() as f64 * 0.95) as usize;
        let p99_idx = (sorted_times.len() as f64 * 0.99) as usize;
        let avg = sorted_times.iter().sum::<Duration>() / sorted_times.len() as u32;

        (avg, sorted_times[p95_idx.min(sorted_times.len() - 1)], sorted_times[p99_idx.min(sorted_times.len() - 1)])
    }

    pub fn requests_per_second(&self) -> f64 {
        if self.test_duration.as_secs_f64() == 0.0 {
            return 0.0;
        }
        self.successful_requests as f64 / self.test_duration.as_secs_f64()
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.successful_requests as f64 / self.total_requests as f64
    }

    pub fn print_detailed_metrics(&self) {
        let (avg, p95, p99) = self.calculate_percentiles();
        
        println!("📊 {} Performance Metrics:", self.endpoint);
        println!("  Total Requests: {}", self.total_requests);
        println!("  Successful: {} ({:.1}%)", self.successful_requests, self.success_rate() * 100.0);
        println!("  Failed: {}", self.failed_requests);
        println!("  Average Response Time: {:.2}ms", avg.as_millis());
        println!("  P95 Response Time: {:.2}ms", p95.as_millis());
        println!("  P99 Response Time: {:.2}ms", p99.as_millis());
        println!("  Requests per Second: {:.2}", self.requests_per_second());
        println!("  Test Duration: {:.2}s", self.test_duration.as_secs_f64());
        
        if !self.error_codes.is_empty() {
            println!("  Error Codes:");
            for (code, count) in &self.error_codes {
                println!("    {}: {}", code, count);
            }
        }
    }
}

/// Test authentication endpoint performance (login)
#[tokio::test]
async fn test_authentication_endpoint_performance() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping performance test.");
        return Ok(());
    }

    info!("🔑 Testing authentication endpoint performance");
    
    const TEST_USERS: usize = 100;
    const REQUESTS_PER_USER: usize = 10;
    const TOTAL_REQUESTS: usize = TEST_USERS * REQUESTS_PER_USER;
    
    // Create test users first
    println!("📝 Creating {} test users...", TEST_USERS);
    let mut test_users = Vec::new();
    for i in 0..TEST_USERS {
        let user = TestUser::new(&format!("auth_perf_test_{}", i));
        let _ = framework.client.register(&user).await?;
        test_users.push(user);
    }
    
    let mut metrics = EndpointMetrics::new("POST /auth/login");
    let start_time = Instant::now();
    let mut handles = Vec::new();

    // Launch concurrent authentication requests
    for i in 0..TOTAL_REQUESTS {
        let client = framework.client.clone();
        let user = test_users[i % TEST_USERS].clone();
        
        let handle = tokio::spawn(async move {
            let request_start = Instant::now();
            let result = client.login(&user).await;
            let elapsed = request_start.elapsed();
            
            match result {
                Ok(_) => (true, elapsed, Some(200u16)),
                Err(_) => (false, elapsed, Some(401u16)),
            }
        });
        
        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        if let Ok((success, response_time, status_code)) = handle.await {
            metrics.add_result(success, response_time, status_code);
        }
    }

    metrics.test_duration = start_time.elapsed();
    metrics.print_detailed_metrics();

    // Validate performance targets
    let targets = PerformanceTargets::default();
    let (_, p95, _) = metrics.calculate_percentiles();
    
    assert!(
        p95.as_millis() <= targets.auth_p95_ms as u128,
        "Authentication P95 response time should be ≤{}ms, got {}ms",
        targets.auth_p95_ms,
        p95.as_millis()
    );
    
    assert!(
        metrics.requests_per_second() >= targets.login_rps,
        "Authentication RPS should be ≥{}, got {:.2}",
        targets.login_rps,
        metrics.requests_per_second()
    );
    
    assert!(
        metrics.success_rate() >= 0.99,
        "Authentication success rate should be ≥99%, got {:.2}%",
        metrics.success_rate() * 100.0
    );

    println!("✅ Authentication endpoint performance targets met");
    Ok(())
}

/// Test registration endpoint performance
#[tokio::test]
async fn test_registration_endpoint_performance() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping performance test.");
        return Ok(());
    }

    info!("📝 Testing registration endpoint performance");
    
    const TOTAL_REGISTRATIONS: usize = 500;
    let mut metrics = EndpointMetrics::new("POST /auth/register");
    let start_time = Instant::now();
    let mut handles = Vec::new();

    // Launch concurrent registration requests
    for i in 0..TOTAL_REGISTRATIONS {
        let client = framework.client.clone();
        
        let handle = tokio::spawn(async move {
            let user = TestUser::new(&format!("reg_perf_test_{}", i));
            let request_start = Instant::now();
            let result = client.register(&user).await;
            let elapsed = request_start.elapsed();
            
            match result {
                Ok(_) => (true, elapsed, Some(201u16)),
                Err(_) => (false, elapsed, Some(400u16)),
            }
        });
        
        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        if let Ok((success, response_time, status_code)) = handle.await {
            metrics.add_result(success, response_time, status_code);
        }
    }

    metrics.test_duration = start_time.elapsed();
    metrics.print_detailed_metrics();

    // Validate performance targets
    let targets = PerformanceTargets::default();
    let (_, p95, _) = metrics.calculate_percentiles();
    
    assert!(
        p95.as_millis() <= targets.registration_p95_ms as u128,
        "Registration P95 response time should be ≤{}ms, got {}ms",
        targets.registration_p95_ms,
        p95.as_millis()
    );
    
    assert!(
        metrics.requests_per_second() >= targets.registration_rps,
        "Registration RPS should be ≥{}, got {:.2}",
        targets.registration_rps,
        metrics.requests_per_second()
    );
    
    assert!(
        metrics.success_rate() >= 0.95,
        "Registration success rate should be ≥95%, got {:.2}%",
        metrics.success_rate() * 100.0
    );

    println!("✅ Registration endpoint performance targets met");
    Ok(())
}

/// Test protected endpoint performance (profile access)
#[tokio::test]
async fn test_protected_endpoint_performance() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping performance test.");
        return Ok(());
    }

    info!("🔒 Testing protected endpoint performance");
    
    const TEST_USERS: usize = 50;
    const REQUESTS_PER_USER: usize = 40; // Total: 2000 requests
    
    // Create test users and get their tokens
    println!("📝 Creating {} test users and obtaining tokens...", TEST_USERS);
    let mut user_tokens = Vec::new();
    for i in 0..TEST_USERS {
        let user = TestUser::new(&format!("protected_perf_test_{}", i));
        let (tokens, _) = framework.client.register(&user).await?;
        user_tokens.push(tokens.access_token);
    }
    
    let mut metrics = EndpointMetrics::new("GET /auth/me");
    let start_time = Instant::now();
    let mut handles = Vec::new();

    // Launch concurrent protected endpoint requests
    for i in 0..(TEST_USERS * REQUESTS_PER_USER) {
        let client = framework.client.clone();
        let token = user_tokens[i % TEST_USERS].clone();
        
        let handle = tokio::spawn(async move {
            let request_start = Instant::now();
            let result = client.get_profile(&token).await;
            let elapsed = request_start.elapsed();
            
            match result {
                Ok(_) => (true, elapsed, Some(200u16)),
                Err(_) => (false, elapsed, Some(401u16)),
            }
        });
        
        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        if let Ok((success, response_time, status_code)) = handle.await {
            metrics.add_result(success, response_time, status_code);
        }
    }

    metrics.test_duration = start_time.elapsed();
    metrics.print_detailed_metrics();

    // Validate performance targets
    let targets = PerformanceTargets::default();
    let (_, p95, _) = metrics.calculate_percentiles();
    
    assert!(
        p95.as_millis() <= targets.profile_p95_ms as u128,
        "Protected endpoint P95 response time should be ≤{}ms, got {}ms",
        targets.profile_p95_ms,
        p95.as_millis()
    );
    
    assert!(
        metrics.requests_per_second() >= targets.protected_rps,
        "Protected endpoint RPS should be ≥{}, got {:.2}",
        targets.protected_rps,
        metrics.requests_per_second()
    );
    
    assert!(
        metrics.success_rate() >= 0.99,
        "Protected endpoint success rate should be ≥99%, got {:.2}%",
        metrics.success_rate() * 100.0
    );

    println!("✅ Protected endpoint performance targets met");
    Ok(())
}

/// Test health check endpoint performance
#[tokio::test]
async fn test_health_endpoint_performance() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping performance test.");
        return Ok(());
    }

    info!("❤️ Testing health endpoint performance");
    
    const TOTAL_REQUESTS: usize = 10000;
    const CONCURRENCY_LIMIT: usize = 100;
    
    let mut metrics = EndpointMetrics::new("GET /health");
    let start_time = Instant::now();
    let semaphore = Arc::new(Semaphore::new(CONCURRENCY_LIMIT));
    let mut handles = Vec::new();

    // Launch concurrent health check requests
    for _ in 0..TOTAL_REQUESTS {
        let client = framework.client.clone();
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        
        let handle = tokio::spawn(async move {
            let _permit = permit;
            let request_start = Instant::now();
            let result = client.health_check().await;
            let elapsed = request_start.elapsed();
            
            match result {
                Ok(_) => (true, elapsed, Some(200u16)),
                Err(_) => (false, elapsed, Some(500u16)),
            }
        });
        
        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        if let Ok((success, response_time, status_code)) = handle.await {
            metrics.add_result(success, response_time, status_code);
        }
    }

    metrics.test_duration = start_time.elapsed();
    metrics.print_detailed_metrics();

    // Validate performance targets
    let targets = PerformanceTargets::default();
    let (_, p95, _) = metrics.calculate_percentiles();
    
    assert!(
        p95.as_millis() <= targets.health_p95_ms as u128,
        "Health endpoint P95 response time should be ≤{}ms, got {}ms",
        targets.health_p95_ms,
        p95.as_millis()
    );
    
    assert!(
        metrics.requests_per_second() >= targets.health_rps,
        "Health endpoint RPS should be ≥{}, got {:.2}",
        targets.health_rps,
        metrics.requests_per_second()
    );
    
    assert!(
        metrics.success_rate() >= 0.999,
        "Health endpoint success rate should be ≥99.9%, got {:.2}%",
        metrics.success_rate() * 100.0
    );

    println!("✅ Health endpoint performance targets met");
    Ok(())
}

/// Test password reset endpoint performance
#[tokio::test]
async fn test_password_reset_performance() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping performance test.");
        return Ok(());
    }

    info!("🔑 Testing password reset endpoint performance");
    
    const TEST_USERS: usize = 150;
    
    // Create test users first
    println!("📝 Creating {} test users...", TEST_USERS);
    let mut test_users = Vec::new();
    for i in 0..TEST_USERS {
        let user = TestUser::new(&format!("reset_perf_test_{}", i));
        let _ = framework.client.register(&user).await?;
        test_users.push(user);
    }
    
    let mut metrics = EndpointMetrics::new("POST /auth/forgot-password");
    let start_time = Instant::now();
    let mut handles = Vec::new();

    // Launch concurrent password reset requests
    for user in test_users {
        let client = framework.client.clone();
        
        let handle = tokio::spawn(async move {
            let request_start = Instant::now();
            let result = client.forgot_password(&user.email).await;
            let elapsed = request_start.elapsed();
            
            match result {
                Ok(_) => (true, elapsed, Some(200u16)),
                Err(_) => (false, elapsed, Some(400u16)),
            }
        });
        
        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        if let Ok((success, response_time, status_code)) = handle.await {
            metrics.add_result(success, response_time, status_code);
        }
    }

    metrics.test_duration = start_time.elapsed();
    metrics.print_detailed_metrics();

    // Validate performance targets
    let targets = PerformanceTargets::default();
    let (_, p95, _) = metrics.calculate_percentiles();
    
    assert!(
        p95.as_millis() <= targets.password_reset_p95_ms as u128,
        "Password reset P95 response time should be ≤{}ms, got {}ms",
        targets.password_reset_p95_ms,
        p95.as_millis()
    );
    
    assert!(
        metrics.success_rate() >= 0.95,
        "Password reset success rate should be ≥95%, got {:.2}%",
        metrics.success_rate() * 100.0
    );

    println!("✅ Password reset endpoint performance targets met");
    Ok(())
}

/// Comprehensive endpoint performance suite
#[tokio::test]
async fn test_comprehensive_endpoint_performance() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping comprehensive performance test.");
        return Ok(());
    }

    println!("🎯 Running comprehensive endpoint performance test suite");
    
    // Run all endpoint tests
    test_health_endpoint_performance().await?;
    test_registration_endpoint_performance().await?;
    test_authentication_endpoint_performance().await?;
    test_protected_endpoint_performance().await?;
    test_password_reset_performance().await?;
    
    println!("✅ All endpoint performance targets validated successfully");
    println!("🏆 Comprehensive performance test suite completed");
    
    Ok(())
}

/// Performance regression baseline test
#[tokio::test]
async fn test_performance_regression_baseline() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping regression baseline test.");
        return Ok(());
    }

    info!("📊 Establishing performance regression baseline");
    
    let mut baseline_metrics = HashMap::new();
    
    // Single request baseline for each endpoint
    let test_user = TestUser::new("baseline_test_user");
    let (tokens, _) = framework.client.register(&test_user).await?;
    
    // Health check baseline
    let start = Instant::now();
    let _ = framework.client.health_check().await?;
    baseline_metrics.insert("health_check", start.elapsed());
    
    // Authentication baseline
    let start = Instant::now();
    let _ = framework.client.login(&test_user).await?;
    baseline_metrics.insert("authentication", start.elapsed());
    
    // Profile access baseline
    let start = Instant::now();
    let _ = framework.client.get_profile(&tokens.access_token).await?;
    baseline_metrics.insert("profile_access", start.elapsed());
    
    // Password reset baseline
    let start = Instant::now();
    let _ = framework.client.forgot_password(&test_user.email).await?;
    baseline_metrics.insert("password_reset", start.elapsed());
    
    println!("📊 Performance Regression Baselines:");
    for (endpoint, duration) in &baseline_metrics {
        println!("  {}: {:.2}ms", endpoint, duration.as_millis());
    }
    
    // Store baselines (in real implementation, this would go to a database or file)
    // For testing purposes, we'll just validate reasonable baseline values
    assert!(baseline_metrics["health_check"].as_millis() < 100, "Health check baseline should be <100ms");
    assert!(baseline_metrics["authentication"].as_millis() < 500, "Authentication baseline should be <500ms");
    assert!(baseline_metrics["profile_access"].as_millis() < 200, "Profile access baseline should be <200ms");
    assert!(baseline_metrics["password_reset"].as_millis() < 1000, "Password reset baseline should be <1000ms");
    
    println!("✅ Performance regression baselines established");
    Ok(())
}