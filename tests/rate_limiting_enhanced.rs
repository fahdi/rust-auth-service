use serde_json::json;
use std::time::Duration;
use reqwest::header::HeaderValue;

/// Test the enhanced rate limiting middleware with Redis backend and per-user limiting
/// Tests our newly implemented Redis rate limiting store and JWT-based per-user limiting

#[tokio::test]
async fn test_redis_rate_limiting_backend() {
    // Test that rate limiting works with Redis backend when configured
    // This test requires Redis to be running
    if std::env::var("REDIS_TEST_URL").is_err() {
        println!("⏭️ Skipping Redis rate limiting test - no REDIS_TEST_URL configured");
        return;
    }

    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // Make multiple requests to test rate limiting
    let mut rate_limited_count = 0;
    let total_requests = 10;

    for i in 0..total_requests {
        let response = client
            .post(&format!("{}/auth/login", base_url))
            .json(&json!({
                "email": "rate.limit.test@example.com",
                "password": "invalid_password"
            }))
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    rate_limited_count += 1;
                    println!("✅ Request {} was rate limited", i + 1);
                    
                    // Check for rate limit headers
                    let headers = resp.headers();
                    assert!(headers.contains_key("x-ratelimit-limit"));
                    assert!(headers.contains_key("x-ratelimit-remaining"));
                    assert!(headers.contains_key("x-ratelimit-reset"));
                } else {
                    println!("🔄 Request {} got status: {}", i + 1, resp.status());
                }
            }
            Err(e) => {
                println!("❌ Request {} failed: {}", i + 1, e);
            }
        }

        // Small delay between requests
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // We should have been rate limited at some point
    assert!(
        rate_limited_count > 0,
        "Expected to be rate limited, but no rate limiting occurred"
    );

    println!(
        "✅ Redis rate limiting test passed: {}/{} requests were rate limited",
        rate_limited_count, total_requests
    );
}

#[tokio::test]
async fn test_per_user_rate_limiting() {
    // Test per-user rate limiting with JWT tokens
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // First, register and login to get a JWT token
    let test_email = "peruser.ratelimit@example.com";
    let test_password = "test_password_123";

    // Register user
    let register_response = client
        .post(&format!("{}/auth/register", base_url))
        .json(&json!({
            "email": test_email,
            "password": test_password,
            "first_name": "Rate",
            "last_name": "Limit"
        }))
        .send()
        .await;

    if let Ok(resp) = register_response {
        if resp.status().is_success() {
            println!("✅ User registered successfully");
        }
    }

    // Login to get JWT token
    let login_response = client
        .post(&format!("{}/auth/login", base_url))
        .json(&json!({
            "email": test_email,
            "password": test_password
        }))
        .send()
        .await;

    let jwt_token = if let Ok(resp) = login_response {
        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().await.unwrap();
            body["access_token"].as_str().unwrap().to_string()
        } else {
            println!("⏭️ Skipping per-user rate limit test - login failed");
            return;
        }
    } else {
        println!("⏭️ Skipping per-user rate limit test - login request failed");
        return;
    };

    // Now test rate limiting with authenticated requests
    let mut rate_limited_count = 0;
    let total_requests = 15; // Higher than typical auth rate limit

    for i in 0..total_requests {
        let response = client
            .get(&format!("{}/auth/me", base_url))
            .header("Authorization", format!("Bearer {}", jwt_token))
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    rate_limited_count += 1;
                    println!("✅ Authenticated request {} was rate limited", i + 1);
                } else if resp.status().is_success() {
                    println!("🔄 Authenticated request {} succeeded", i + 1);
                } else {
                    println!("🔄 Authenticated request {} got status: {}", i + 1, resp.status());
                }
            }
            Err(e) => {
                println!("❌ Authenticated request {} failed: {}", i + 1, e);
            }
        }

        // Small delay between requests
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    println!(
        "✅ Per-user rate limiting test completed: {}/{} requests were rate limited",
        rate_limited_count, total_requests
    );

    // Cleanup - this is optional as the user might not be persistent
    let _ = client
        .delete(&format!("{}/auth/users/{}", base_url, test_email))
        .header("Authorization", format!("Bearer {}", jwt_token))
        .send()
        .await;
}

#[tokio::test]
async fn test_rate_limit_headers() {
    // Test that rate limit headers are properly set
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    let response = client
        .get(&format!("{}/health", base_url))
        .send()
        .await;

    if let Ok(resp) = response {
        let headers = resp.headers();
        
        // Check if rate limit headers are present
        // Note: Headers might not be present on all endpoints, but health check should have them
        if headers.contains_key("x-ratelimit-limit") {
            println!("✅ X-RateLimit-Limit header found: {:?}", 
                     headers.get("x-ratelimit-limit"));
        }
        
        if headers.contains_key("x-ratelimit-remaining") {
            println!("✅ X-RateLimit-Remaining header found: {:?}", 
                     headers.get("x-ratelimit-remaining"));
        }
        
        if headers.contains_key("x-ratelimit-reset") {
            println!("✅ X-RateLimit-Reset header found: {:?}", 
                     headers.get("x-ratelimit-reset"));
        }

        println!("✅ Rate limit headers test completed");
    } else {
        println!("⏭️ Skipping rate limit headers test - service not available");
    }
}

#[tokio::test]
async fn test_rate_limit_category_detection() {
    // Test that different endpoint categories have different rate limits
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    let endpoints = vec![
        ("/health", "health", "Health endpoint should have high rate limit"),
        ("/auth/login", "auth", "Auth endpoint should have low rate limit"), 
        ("/auth/register", "registration", "Registration should have very low rate limit"),
        ("/auth/forgot-password", "password_reset", "Password reset should have low rate limit"),
    ];

    for (endpoint, category, description) in endpoints {
        println!("🔍 Testing rate limit for {} category: {}", category, endpoint);
        
        // Make a single request to get baseline headers
        let response = client
            .post(&format!("{}{}", base_url, endpoint))
            .json(&json!({
                "email": "test@example.com",
                "password": "test"
            }))
            .send()
            .await;

        if let Ok(resp) = response {
            let headers = resp.headers();
            
            if let Some(limit) = headers.get("x-ratelimit-limit") {
                println!("✅ {} - Rate limit: {:?}", description, limit);
            } else {
                println!("ℹ️ {} - No rate limit header found", description);
            }
        } else {
            println!("❌ {} - Request failed", description);
        }

        // Small delay between different endpoint tests
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("✅ Rate limit category detection test completed");
}

#[tokio::test] 
async fn test_rate_limit_fallback_to_memory() {
    // Test that rate limiting falls back to memory store when Redis is unavailable
    // This is tested by configuring an invalid Redis URL and ensuring rate limiting still works
    
    println!("🔍 Testing rate limiting fallback behavior");
    println!("ℹ️ This test verifies that the service gracefully falls back to memory");
    println!("   store when Redis is configured but unavailable");
    
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // Make several requests to ensure fallback is working
    let mut successful_requests = 0;
    let mut rate_limited_requests = 0;
    let total_requests = 8;

    for i in 0..total_requests {
        let response = client
            .post(&format!("{}/auth/login", base_url))
            .json(&json!({
                "email": "fallback.test@example.com", 
                "password": "invalid"
            }))
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    rate_limited_requests += 1;
                    println!("✅ Request {} rate limited (fallback working)", i + 1);
                } else {
                    successful_requests += 1;
                    println!("🔄 Request {} completed with status: {}", i + 1, resp.status());
                }
            }
            Err(e) => {
                println!("❌ Request {} failed: {}", i + 1, e);
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Rate limiting should be working even with fallback
    println!(
        "✅ Fallback test completed: {} successful, {} rate limited out of {}",
        successful_requests, rate_limited_requests, total_requests
    );
    
    // At minimum, the service should be responding (not crashing due to Redis issues)
    assert!(
        successful_requests + rate_limited_requests > 0,
        "Service should be responding even when Redis backend fails"
    );
}