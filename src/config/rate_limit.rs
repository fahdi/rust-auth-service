use serde::{Deserialize, Serialize};

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Default rate limits per endpoint category
    pub limits: RateLimitRules,
    /// Rate limiting storage backend (redis, memory)
    pub backend: String,
    /// Redis URL for distributed rate limiting
    pub redis_url: Option<String>,
    /// Memory cache size for in-memory backend
    pub memory_cache_size: usize,
    /// Window duration in seconds
    pub window_duration: u64,
}

/// Rate limiting rules for different endpoint categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRules {
    /// Authentication endpoints (login, verify, etc.)
    pub auth: RateLimitRule,
    /// Registration endpoint
    pub registration: RateLimitRule,
    /// Password reset endpoints
    pub password_reset: RateLimitRule,
    /// General API endpoints
    pub general: RateLimitRule,
    /// Health check endpoints
    pub health: RateLimitRule,
}

/// Individual rate limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// Maximum requests allowed
    pub max_requests: u32,
    /// Time window in seconds
    pub window_seconds: u64,
    /// Whether to apply per IP
    pub per_ip: bool,
    /// Whether to apply per user (when authenticated)
    pub per_user: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            limits: RateLimitRules::default(),
            backend: "memory".to_string(),
            redis_url: None,
            memory_cache_size: 10000,
            window_duration: 60, // 1 minute
        }
    }
}

impl Default for RateLimitRules {
    fn default() -> Self {
        Self {
            auth: RateLimitRule {
                max_requests: 5,
                window_seconds: 60,
                per_ip: true,
                per_user: false,
            },
            registration: RateLimitRule {
                max_requests: 3,
                window_seconds: 3600, // 1 hour
                per_ip: true,
                per_user: false,
            },
            password_reset: RateLimitRule {
                max_requests: 3,
                window_seconds: 3600, // 1 hour
                per_ip: true,
                per_user: false,
            },
            general: RateLimitRule {
                max_requests: 100,
                window_seconds: 60,
                per_ip: true,
                per_user: false,
            },
            health: RateLimitRule {
                max_requests: 1000,
                window_seconds: 60,
                per_ip: true,
                per_user: false,
            },
        }
    }
}

/// Rate limit check result
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Current count of requests
    pub current_requests: u32,
    /// Maximum allowed requests
    pub max_requests: u32,
    /// Seconds until the window resets
    pub reset_time: u64,
    /// Time until retry is allowed (if blocked)
    pub retry_after: Option<u64>,
}

/// Rate limit key generation
pub fn generate_rate_limit_key(
    category: &str,
    identifier: &str,
    window_start: u64,
) -> String {
    format!("rate_limit:{}:{}:{}", category, identifier, window_start)
}

/// Endpoint category detection
pub fn detect_endpoint_category(path: &str) -> &'static str {
    match path {
        p if p.starts_with("/health") || p.starts_with("/ready") || p.starts_with("/live") => "health",
        "/auth/register" => "registration",
        "/auth/forgot-password" | "/auth/reset-password" => "password_reset",
        p if p.starts_with("/auth/") => "auth",
        _ => "general",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_category_detection() {
        assert_eq!(detect_endpoint_category("/health"), "health");
        assert_eq!(detect_endpoint_category("/auth/register"), "registration");
        assert_eq!(detect_endpoint_category("/auth/login"), "auth");
        assert_eq!(detect_endpoint_category("/auth/forgot-password"), "password_reset");
        assert_eq!(detect_endpoint_category("/api/users"), "general");
    }

    #[test]
    fn test_rate_limit_key_generation() {
        let key = generate_rate_limit_key("auth", "192.168.1.1", 1234567890);
        assert_eq!(key, "rate_limit:auth:192.168.1.1:1234567890");
    }

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert!(config.enabled);
        assert_eq!(config.limits.auth.max_requests, 5);
        assert_eq!(config.limits.registration.max_requests, 3);
        assert_eq!(config.limits.password_reset.window_seconds, 3600);
    }
}