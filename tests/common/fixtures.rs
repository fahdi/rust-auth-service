use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

use rust_auth_service::models::user::{User, LoginAttempt};

/// Test data fixtures for consistent testing across database adapters
pub struct TestFixtures;

impl TestFixtures {
    /// Create a complete test user with all fields populated
    pub fn complete_user() -> User {
        let now = Utc::now();
        User {
            id: None,
            email: "complete.user@example.com".to_string(),
            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
            full_name: "Complete Test User".to_string(),
            role: "user".to_string(),
            is_active: true,
            email_verified: true,
            email_verification_token: Some("verify_token_123".to_string()),
            email_verification_expires: Some(now + chrono::Duration::hours(24)),
            password_reset_token: Some("reset_token_456".to_string()),
            password_reset_expires: Some(now + chrono::Duration::hours(1)),
            failed_login_attempts: 2,
            locked_until: Some(now + chrono::Duration::minutes(30)),
            last_login: Some(now - chrono::Duration::hours(2)),
            created_at: now - chrono::Duration::days(30),
            updated_at: now,
        }
    }

    /// Create a minimal test user with only required fields
    pub fn minimal_user() -> User {
        let now = Utc::now();
        User {
            id: None,
            email: "minimal.user@example.com".to_string(),
            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
            full_name: "Minimal User".to_string(),
            role: "user".to_string(),
            is_active: true,
            email_verified: false,
            email_verification_token: None,
            email_verification_expires: None,
            password_reset_token: None,
            password_reset_expires: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_login: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create an admin user
    pub fn admin_user() -> User {
        let now = Utc::now();
        User {
            id: None,
            email: "admin@example.com".to_string(),
            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
            full_name: "Admin User".to_string(),
            role: "admin".to_string(),
            is_active: true,
            email_verified: true,
            email_verification_token: None,
            email_verification_expires: None,
            password_reset_token: None,
            password_reset_expires: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_login: Some(now - chrono::Duration::minutes(15)),
            created_at: now - chrono::Duration::days(365),
            updated_at: now,
        }
    }

    /// Create a locked user account
    pub fn locked_user() -> User {
        let now = Utc::now();
        User {
            id: None,
            email: "locked.user@example.com".to_string(),
            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
            full_name: "Locked User".to_string(),
            role: "user".to_string(),
            is_active: true,
            email_verified: true,
            email_verification_token: None,
            email_verification_expires: None,
            password_reset_token: None,
            password_reset_expires: None,
            failed_login_attempts: 5,
            locked_until: Some(now + chrono::Duration::hours(1)),
            last_login: Some(now - chrono::Duration::days(1)),
            created_at: now - chrono::Duration::days(7),
            updated_at: now,
        }
    }

    /// Create an inactive user
    pub fn inactive_user() -> User {
        let now = Utc::now();
        User {
            id: None,
            email: "inactive.user@example.com".to_string(),
            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
            full_name: "Inactive User".to_string(),
            role: "user".to_string(),
            is_active: false,
            email_verified: false,
            email_verification_token: None,
            email_verification_expires: None,
            password_reset_token: None,
            password_reset_expires: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_login: None,
            created_at: now - chrono::Duration::days(180),
            updated_at: now - chrono::Duration::days(90),
        }
    }

    /// Create user with pending email verification
    pub fn unverified_user() -> User {
        let now = Utc::now();
        User {
            id: None,
            email: "unverified.user@example.com".to_string(),
            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
            full_name: "Unverified User".to_string(),
            role: "user".to_string(),
            is_active: true,
            email_verified: false,
            email_verification_token: Some("pending_verify_token".to_string()),
            email_verification_expires: Some(now + chrono::Duration::hours(24)),
            password_reset_token: None,
            password_reset_expires: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_login: None,
            created_at: now - chrono::Duration::hours(2),
            updated_at: now - chrono::Duration::hours(2),
        }
    }

    /// Create user with pending password reset
    pub fn password_reset_user() -> User {
        let now = Utc::now();
        User {
            id: None,
            email: "reset.user@example.com".to_string(),
            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
            full_name: "Password Reset User".to_string(),
            role: "user".to_string(),
            is_active: true,
            email_verified: true,
            email_verification_token: None,
            email_verification_expires: None,
            password_reset_token: Some("pending_reset_token".to_string()),
            password_reset_expires: Some(now + chrono::Duration::hours(1)),
            failed_login_attempts: 0,
            locked_until: None,
            last_login: Some(now - chrono::Duration::days(5)),
            created_at: now - chrono::Duration::days(60),
            updated_at: now - chrono::Duration::minutes(30),
        }
    }

    /// Create successful login attempt
    pub fn successful_login_attempt(email: &str) -> LoginAttempt {
        LoginAttempt {
            id: None,
            email: email.to_string(),
            ip_address: "192.168.1.100".to_string(),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
            success: true,
            failure_reason: None,
            timestamp: Utc::now(),
        }
    }

    /// Create failed login attempt
    pub fn failed_login_attempt(email: &str, reason: &str) -> LoginAttempt {
        LoginAttempt {
            id: None,
            email: email.to_string(),
            ip_address: "10.0.0.50".to_string(),
            user_agent: Some("curl/7.68.0".to_string()),
            success: false,
            failure_reason: Some(reason.to_string()),
            timestamp: Utc::now(),
        }
    }

    /// Create login attempt from mobile device
    pub fn mobile_login_attempt(email: &str, success: bool) -> LoginAttempt {
        LoginAttempt {
            id: None,
            email: email.to_string(),
            ip_address: "172.16.0.25".to_string(),
            user_agent: Some("MyApp/1.0 (iOS 14.0; iPhone)".to_string()),
            success,
            failure_reason: if success { None } else { Some("Invalid credentials".to_string()) },
            timestamp: Utc::now(),
        }
    }

    /// Create multiple test users for bulk operations
    pub fn bulk_users(count: usize) -> Vec<User> {
        (0..count)
            .map(|i| {
                let now = Utc::now();
                User {
                    id: None,
                    email: format!("bulk.user.{}@example.com", i),
                    password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                    full_name: format!("Bulk User {}", i),
                    role: if i % 10 == 0 { "admin".to_string() } else { "user".to_string() },
                    is_active: i % 20 != 0, // Every 20th user is inactive
                    email_verified: i % 3 != 0, // Every 3rd user is unverified
                    email_verification_token: None,
                    email_verification_expires: None,
                    password_reset_token: None,
                    password_reset_expires: None,
                    failed_login_attempts: i as u32 % 6, // 0-5 failed attempts
                    locked_until: if i % 50 == 0 { Some(now + chrono::Duration::hours(1)) } else { None },
                    last_login: if i % 5 == 0 { None } else { Some(now - chrono::Duration::hours(i as i64 % 48)) },
                    created_at: now - chrono::Duration::days(i as i64 % 365),
                    updated_at: now - chrono::Duration::hours(i as i64 % 24),
                }
            })
            .collect()
    }

    /// Generate random test user with unique identifiers
    pub fn random_user() -> User {
        let uuid = Uuid::new_v4();
        let now = Utc::now();
        
        User {
            id: None,
            email: format!("random.{}@example.com", uuid),
            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
            full_name: format!("Random User {}", &uuid.to_string()[0..8]),
            role: "user".to_string(),
            is_active: true,
            email_verified: false,
            email_verification_token: None,
            email_verification_expires: None,
            password_reset_token: None,
            password_reset_expires: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_login: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create edge case users for testing
    pub fn edge_case_users() -> Vec<User> {
        let now = Utc::now();
        vec![
            // Very long name
            User {
                id: None,
                email: "long.name@example.com".to_string(),
                password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                full_name: "A".repeat(255),
                role: "user".to_string(),
                is_active: true,
                email_verified: false,
                email_verification_token: None,
                email_verification_expires: None,
                password_reset_token: None,
                password_reset_expires: None,
                failed_login_attempts: 0,
                locked_until: None,
                last_login: None,
                created_at: now,
                updated_at: now,
            },
            // Special characters in name
            User {
                id: None,
                email: "special.chars@example.com".to_string(),
                password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                full_name: "José María Ñoño-González O'Connor".to_string(),
                role: "user".to_string(),
                is_active: true,
                email_verified: false,
                email_verification_token: None,
                email_verification_expires: None,
                password_reset_token: None,
                password_reset_expires: None,
                failed_login_attempts: 0,
                locked_until: None,
                last_login: None,
                created_at: now,
                updated_at: now,
            },
            // Unicode email
            User {
                id: None,
                email: "unicode.тест@example.com".to_string(),
                password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(),
                full_name: "Unicode Test User".to_string(),
                role: "user".to_string(),
                is_active: true,
                email_verified: false,
                email_verification_token: None,
                email_verification_expires: None,
                password_reset_token: None,
                password_reset_expires: None,
                failed_login_attempts: 0,
                locked_until: None,
                last_login: None,
                created_at: now,
                updated_at: now,
            },
        ]
    }
}