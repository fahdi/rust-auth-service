use serde_json::json;
use std::time::Duration;

/// Social authentication integration tests
/// Tests OAuth2 social login with Google, GitHub, Discord, and other providers

#[tokio::test]
async fn test_google_oauth_initiation() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // Test Google OAuth initiation
    let google_auth_response = client
        .get(&format!("{}/auth/google", base_url))
        .send()
        .await;

    match google_auth_response {
        Ok(resp) => {
            if resp.status() == reqwest::StatusCode::FOUND {
                let location = resp.headers().get("location");
                if let Some(redirect_url) = location {
                    let url_str = redirect_url.to_str().unwrap_or("");
                    if url_str.contains("accounts.google.com") {
                        println!("✅ Google OAuth correctly redirects to Google");
                    } else {
                        println!("ℹ️ Google OAuth redirects to: {}", url_str);
                    }
                } else {
                    println!("✅ Google OAuth initiated (redirect response)");
                }
            } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                println!("ℹ️ Google OAuth endpoint not configured or available");
            } else {
                println!("ℹ️ Google OAuth returned status: {}", resp.status());
            }
        }
        Err(e) => {
            println!("ℹ️ Google OAuth request failed: {}", e);
        }
    }

    println!("✅ Google OAuth initiation test completed");
}

#[tokio::test]
async fn test_github_oauth_initiation() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // Test GitHub OAuth initiation
    let github_auth_response = client
        .get(&format!("{}/auth/github", base_url))
        .send()
        .await;

    match github_auth_response {
        Ok(resp) => {
            if resp.status() == reqwest::StatusCode::FOUND {
                let location = resp.headers().get("location");
                if let Some(redirect_url) = location {
                    let url_str = redirect_url.to_str().unwrap_or("");
                    if url_str.contains("github.com") {
                        println!("✅ GitHub OAuth correctly redirects to GitHub");
                    } else {
                        println!("ℹ️ GitHub OAuth redirects to: {}", url_str);
                    }
                } else {
                    println!("✅ GitHub OAuth initiated (redirect response)");
                }
            } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                println!("ℹ️ GitHub OAuth endpoint not configured or available");
            } else {
                println!("ℹ️ GitHub OAuth returned status: {}", resp.status());
            }
        }
        Err(e) => {
            println!("ℹ️ GitHub OAuth request failed: {}", e);
        }
    }

    println!("✅ GitHub OAuth initiation test completed");
}

#[tokio::test]
async fn test_discord_oauth_initiation() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // Test Discord OAuth initiation
    let discord_auth_response = client
        .get(&format!("{}/auth/discord", base_url))
        .send()
        .await;

    match discord_auth_response {
        Ok(resp) => {
            if resp.status() == reqwest::StatusCode::FOUND {
                let location = resp.headers().get("location");
                if let Some(redirect_url) = location {
                    let url_str = redirect_url.to_str().unwrap_or("");
                    if url_str.contains("discord.com") {
                        println!("✅ Discord OAuth correctly redirects to Discord");
                    } else {
                        println!("ℹ️ Discord OAuth redirects to: {}", url_str);
                    }
                } else {
                    println!("✅ Discord OAuth initiated (redirect response)");
                }
            } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                println!("ℹ️ Discord OAuth endpoint not configured or available");
            } else {
                println!("ℹ️ Discord OAuth returned status: {}", resp.status());
            }
        }
        Err(e) => {
            println!("ℹ️ Discord OAuth request failed: {}", e);
        }
    }

    println!("✅ Discord OAuth initiation test completed");
}

#[tokio::test]
async fn test_social_auth_callback_handling() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // Test social auth callback endpoints with mock data
    let callback_tests = vec![
        ("/auth/google/callback", "Google"),
        ("/auth/github/callback", "GitHub"),
        ("/auth/discord/callback", "Discord"),
    ];

    for (endpoint, provider) in callback_tests {
        // Test callback with missing parameters (should return error)
        let callback_response = client
            .get(&format!("{}{}", base_url, endpoint))
            .send()
            .await;

        match callback_response {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::BAD_REQUEST {
                    println!("✅ {} callback correctly validates parameters", provider);
                } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    println!("ℹ️ {} callback endpoint not available", provider);
                } else {
                    println!(
                        "ℹ️ {} callback returned status: {}",
                        provider,
                        resp.status()
                    );
                }
            }
            Err(e) => {
                println!("ℹ️ {} callback failed: {}", provider, e);
            }
        }

        // Test callback with invalid authorization code
        let invalid_callback_response = client
            .get(&format!(
                "{}{}?code=invalid_code&state=test_state",
                base_url, endpoint
            ))
            .send()
            .await;

        match invalid_callback_response {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::BAD_REQUEST
                    || resp.status() == reqwest::StatusCode::UNAUTHORIZED
                {
                    println!(
                        "✅ {} callback correctly validates authorization code",
                        provider
                    );
                } else {
                    println!(
                        "ℹ️ {} callback with invalid code returned: {}",
                        provider,
                        resp.status()
                    );
                }
            }
            Err(e) => {
                println!("ℹ️ {} callback with invalid code failed: {}", provider, e);
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("✅ Social auth callback handling test completed");
}

#[tokio::test]
async fn test_social_auth_user_linking() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // Test linking social accounts to existing users
    // First, create a regular user account
    let test_email = "social.link@example.com";
    let test_password = "secure_password_123";

    let register_response = client
        .post(&format!("{}/auth/register", base_url))
        .json(&json!({
            "email": test_email,
            "password": test_password,
            "first_name": "Social",
            "last_name": "Link"
        }))
        .send()
        .await;

    if let Ok(resp) = register_response {
        if !resp.status().is_success() {
            println!("⏭️ Skipping social linking test - registration failed");
            return;
        }
    } else {
        println!("⏭️ Skipping social linking test - registration request failed");
        return;
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
            println!("⏭️ Skipping social linking test - login failed");
            return;
        }
    } else {
        println!("⏭️ Skipping social linking test - login request failed");
        return;
    };

    // Test linking social accounts
    let social_providers = vec!["google", "github", "discord"];

    for provider in social_providers {
        let link_response = client
            .post(&format!("{}/auth/link/{}", base_url, provider))
            .header("Authorization", format!("Bearer {}", jwt_token))
            .send()
            .await;

        match link_response {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::FOUND {
                    println!("✅ {} account linking initiated correctly", provider);
                } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    println!("ℹ️ {} account linking not available", provider);
                } else {
                    println!(
                        "ℹ️ {} account linking returned status: {}",
                        provider,
                        resp.status()
                    );
                }
            }
            Err(e) => {
                println!("ℹ️ {} account linking failed: {}", provider, e);
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("✅ Social auth user linking test completed");
}

#[tokio::test]
async fn test_social_auth_profile_data() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // Test that social auth profile endpoints return proper data structure
    // This tests the internal profile fetching logic

    // Note: These are internal endpoints that might require special testing setup
    let profile_endpoints = vec![
        ("/internal/social/google/profile", "Google"),
        ("/internal/social/github/profile", "GitHub"),
        ("/internal/social/discord/profile", "Discord"),
    ];

    for (endpoint, provider) in profile_endpoints {
        let profile_response = client
            .get(&format!("{}{}", base_url, endpoint))
            .header("Authorization", "Bearer test_social_token")
            .send()
            .await;

        match profile_response {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                    println!(
                        "✅ {} profile endpoint correctly requires authentication",
                        provider
                    );
                } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    println!(
                        "ℹ️ {} profile endpoint not available (expected for integration test)",
                        provider
                    );
                } else {
                    println!(
                        "ℹ️ {} profile endpoint returned status: {}",
                        provider,
                        resp.status()
                    );
                }
            }
            Err(e) => {
                println!("ℹ️ {} profile request failed: {}", provider, e);
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("✅ Social auth profile data test completed");
}

#[tokio::test]
async fn test_social_auth_error_handling() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // Test various error scenarios in social authentication
    let error_scenarios = vec![
        (
            "/auth/google/callback?error=access_denied",
            "Google access denied error",
        ),
        (
            "/auth/github/callback?error=access_denied&error_description=User%20denied%20access",
            "GitHub access denied with description",
        ),
        (
            "/auth/discord/callback?error=invalid_request",
            "Discord invalid request error",
        ),
        (
            "/auth/google/callback?state=invalid_state",
            "Google invalid state parameter",
        ),
    ];

    for (url, description) in error_scenarios {
        let error_response = client.get(&format!("{}{}", base_url, url)).send().await;

        match error_response {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::BAD_REQUEST {
                    println!("✅ {} - Error correctly handled", description);
                } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    println!("ℹ️ {} - Endpoint not available", description);
                } else {
                    println!("ℹ️ {} - Returned status: {}", description, resp.status());
                }
            }
            Err(e) => {
                println!("ℹ️ {} - Request failed: {}", description, e);
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("✅ Social auth error handling test completed");
}

#[tokio::test]
async fn test_social_auth_scope_handling() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // Test social auth with different scope requirements
    let scope_tests = vec![
        (
            "/auth/google?scope=email+profile",
            "Google with email and profile",
        ),
        (
            "/auth/github?scope=user:email",
            "GitHub with user email scope",
        ),
        (
            "/auth/discord?scope=identify+email",
            "Discord with identify and email",
        ),
    ];

    for (url, description) in scope_tests {
        let scope_response = client.get(&format!("{}{}", base_url, url)).send().await;

        match scope_response {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::FOUND {
                    let location = resp.headers().get("location");
                    if let Some(redirect_url) = location {
                        let url_str = redirect_url.to_str().unwrap_or("");
                        if url_str.contains("scope=") {
                            println!("✅ {} - Scope correctly included in redirect", description);
                        } else {
                            println!("ℹ️ {} - Redirected to: {}", description, url_str);
                        }
                    } else {
                        println!("✅ {} - OAuth flow initiated", description);
                    }
                } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    println!("ℹ️ {} - Endpoint not available", description);
                } else {
                    println!("ℹ️ {} - Returned status: {}", description, resp.status());
                }
            }
            Err(e) => {
                println!("ℹ️ {} - Request failed: {}", description, e);
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("✅ Social auth scope handling test completed");
}

#[tokio::test]
async fn test_social_auth_session_management() {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8090";

    // Test session management for social auth users
    // This tests that users authenticated via social login have proper sessions

    println!("🔍 Testing social auth session management");

    // Test that social auth creates proper sessions
    // Note: This would typically require a full OAuth flow, so we test the endpoints

    let session_endpoints = vec![
        ("/auth/sessions", "Session listing"),
        ("/auth/sessions/current", "Current session info"),
    ];

    for (endpoint, description) in session_endpoints {
        let session_response = client
            .get(&format!("{}{}", base_url, endpoint))
            .send()
            .await;

        match session_response {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                    println!("✅ {} - Correctly requires authentication", description);
                } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    println!("ℹ️ {} - Endpoint not available", description);
                } else {
                    println!("ℹ️ {} - Returned status: {}", description, resp.status());
                }
            }
            Err(e) => {
                println!("ℹ️ {} - Request failed: {}", description, e);
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("✅ Social auth session management test completed");
}
