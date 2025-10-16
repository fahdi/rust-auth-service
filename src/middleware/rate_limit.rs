use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, warn};

use crate::{
    config::rate_limit::{
        detect_endpoint_category, generate_rate_limit_key, RateLimitConfig, RateLimitRule,
        RateLimitStatus,
    },
    errors::AppError,
    AppState,
};
use redis::{aio::ConnectionManager, Client};
use base64::Engine;

/// In-memory rate limiting store
#[derive(Debug, Clone)]
pub struct MemoryRateLimitStore {
    store: Arc<Mutex<HashMap<String, (u32, u64)>>>, // (count, window_start)
    max_size: usize,
}

impl MemoryRateLimitStore {
    pub fn new(max_size: usize) -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
            max_size,
        }
    }

    pub fn check_and_increment(
        &self,
        key: &str,
        rule: &RateLimitRule,
        current_time: u64,
    ) -> RateLimitStatus {
        let mut store = self.store.lock().unwrap();

        // Calculate window start
        let window_start = (current_time / rule.window_seconds) * rule.window_seconds;
        let full_key = format!("{}:{}", key, window_start);

        // Clean up old entries if store is getting too large
        if store.len() > self.max_size {
            store.retain(|_k, (_, window)| current_time - *window < rule.window_seconds * 2);
        }

        let (current_count, _) = store.entry(full_key.clone()).or_insert((0, window_start));

        let new_count = *current_count + 1;
        let allowed = new_count <= rule.max_requests;

        if allowed {
            *current_count = new_count;
        }

        let reset_time = window_start + rule.window_seconds - current_time;
        let retry_after = if !allowed { Some(reset_time) } else { None };

        RateLimitStatus {
            allowed,
            current_requests: new_count,
            max_requests: rule.max_requests,
            reset_time,
            retry_after,
        }
    }
}

/// Redis-based rate limiting store
#[derive(Clone)]
pub struct RedisRateLimitStore {
    connection: ConnectionManager,
}

impl RedisRateLimitStore {
    pub async fn new(redis_url: &str) -> Result<Self, AppError> {
        let client = Client::open(redis_url).map_err(|_| AppError::Internal)?;
        let connection = ConnectionManager::new(client)
            .await
            .map_err(|_| AppError::Internal)?;
        Ok(Self { connection })
    }

    pub async fn check_and_increment(
        &self,
        key: &str,
        rule: &RateLimitRule,
        current_time: u64,
    ) -> Result<RateLimitStatus, AppError> {
        let mut conn = self.connection.clone();
        let window_start = (current_time / rule.window_seconds) * rule.window_seconds;
        let full_key = format!("{}:{}", key, window_start);

        // Use Redis MULTI/EXEC for atomic operations
        let (current_count,): (u32,) = redis::pipe()
            .atomic()
            .incr(&full_key, 1)
            .expire(&full_key, rule.window_seconds as i64)
            .ignore()
            .query_async(&mut conn)
            .await
            .map_err(|_| AppError::Internal)?;

        let allowed = current_count <= rule.max_requests;
        let reset_time = window_start + rule.window_seconds - current_time;
        let retry_after = if !allowed { Some(reset_time) } else { None };

        Ok(RateLimitStatus {
            allowed,
            current_requests: current_count,
            max_requests: rule.max_requests,
            reset_time,
            retry_after,
        })
    }
}

/// Rate limiting store trait for abstraction
pub trait RateLimitStore: Send + Sync {
    async fn check_and_increment(
        &self,
        key: &str,
        rule: &RateLimitRule,
        current_time: u64,
    ) -> Result<RateLimitStatus, AppError>;
}

impl RateLimitStore for MemoryRateLimitStore {
    async fn check_and_increment(
        &self,
        key: &str,
        rule: &RateLimitRule,
        current_time: u64,
    ) -> Result<RateLimitStatus, AppError> {
        Ok(self.check_and_increment(key, rule, current_time))
    }
}

impl RateLimitStore for RedisRateLimitStore {
    async fn check_and_increment(
        &self,
        key: &str,
        rule: &RateLimitRule,
        current_time: u64,
    ) -> Result<RateLimitStatus, AppError> {
        self.check_and_increment(key, rule, current_time).await
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Check if rate limiting is enabled
    if !state.config.rate_limit.enabled {
        return Ok(next.run(request).await);
    }

    let path = request.uri().path();
    let method = request.method().as_str();
    let client_ip = get_client_ip(&request, addr.ip().to_string());

    debug!(
        "Rate limiting check for {} {} from IP: {}",
        method, path, client_ip
    );

    // Detect endpoint category
    let category = detect_endpoint_category(path);
    let rule = get_rule_for_category(&state.config.rate_limit, category);

    // Generate rate limit key
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Internal)?
        .as_secs();

    // Extract user ID from Authorization header if present and per_user is enabled
    let user_id = if rule.per_user {
        extract_user_id_from_request(&request)
    } else {
        None
    };

    let identifier = match (rule.per_ip, rule.per_user, user_id) {
        (_, true, Some(uid)) => format!("user:{}", uid), // Per-user takes precedence when authenticated
        (true, _, _) => format!("ip:{}", client_ip),     // Per-IP when no user or per_user disabled
        _ => "global".to_string(),                       // Global rate limiting
    };

    let key = generate_rate_limit_key(category, &identifier, current_time);

    // Check rate limit using configured backend
    let status = match state.config.rate_limit.backend.as_str() {
        "redis" => {
            if let Some(redis_url) = &state.config.rate_limit.redis_url {
                match RedisRateLimitStore::new(redis_url).await {
                    Ok(redis_store) => redis_store.check_and_increment(&key, rule, current_time).await?,
                    Err(_) => {
                        warn!("Failed to connect to Redis, falling back to memory store");
                        let memory_store = MemoryRateLimitStore::new(state.config.rate_limit.memory_cache_size);
                        memory_store.check_and_increment(&key, rule, current_time)
                    }
                }
            } else {
                warn!("Redis backend configured but no Redis URL provided, using memory store");
                let memory_store = MemoryRateLimitStore::new(state.config.rate_limit.memory_cache_size);
                memory_store.check_and_increment(&key, rule, current_time)
            }
        }
        _ => {
            let memory_store = MemoryRateLimitStore::new(state.config.rate_limit.memory_cache_size);
            memory_store.check_and_increment(&key, rule, current_time)
        }
    };

    // Add rate limit headers to response
    let mut response = if status.allowed {
        debug!(
            "Rate limit check passed for {} {}: {}/{} requests",
            method, path, status.current_requests, status.max_requests
        );
        next.run(request).await
    } else {
        warn!(
            "Rate limit exceeded for {} {} from IP {}: {}/{} requests",
            method, path, client_ip, status.current_requests, status.max_requests
        );

        let mut response = Response::new("Rate limit exceeded".into());
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        response
    };

    // Add rate limit headers
    let headers = response.headers_mut();

    if let Ok(limit_header) = HeaderValue::from_str(&status.max_requests.to_string()) {
        headers.insert("X-RateLimit-Limit", limit_header);
    }

    if let Ok(remaining_header) = HeaderValue::from_str(
        &(status.max_requests.saturating_sub(status.current_requests)).to_string(),
    ) {
        headers.insert("X-RateLimit-Remaining", remaining_header);
    }

    if let Ok(reset_header) = HeaderValue::from_str(&(current_time + status.reset_time).to_string())
    {
        headers.insert("X-RateLimit-Reset", reset_header);
    }

    if let Some(retry_after) = status.retry_after {
        if let Ok(retry_header) = HeaderValue::from_str(&retry_after.to_string()) {
            headers.insert("Retry-After", retry_header);
        }
    }

    if !status.allowed {
        return Err(AppError::RateLimited);
    }

    Ok(response)
}

/// Extract client IP from request headers or connection info
fn get_client_ip(request: &Request, fallback_ip: String) -> String {
    // Check X-Forwarded-For header (proxy/load balancer)
    if let Some(forwarded_for) = request.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            if let Some(ip) = forwarded_str.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    // Check X-Real-IP header (nginx proxy)
    if let Some(real_ip) = request.headers().get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }

    // Fallback to connection IP
    fallback_ip
}

/// Extract user ID from JWT token in Authorization header
fn extract_user_id_from_request(request: &Request) -> Option<String> {
    // Get Authorization header
    let auth_header = request.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;
    
    // Check if it's a Bearer token
    if !auth_str.starts_with("Bearer ") {
        return None;
    }
    
    let token = auth_str.strip_prefix("Bearer ")?;
    
    // Parse JWT token without verification (just for rate limiting identification)
    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    
    // Decode the payload (second part)
    let payload = parts[1];
    
    // Add padding if needed for base64 decoding
    let padded_payload = match payload.len() % 4 {
        0 => payload.to_string(),
        n => format!("{}{}", payload, "=".repeat(4 - n)),
    };
    
    // Decode base64 payload
    if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&padded_payload) {
        if let Ok(json_str) = String::from_utf8(decoded) {
            if let Ok(claims) = serde_json::from_str::<serde_json::Value>(&json_str) {
                // Extract user ID from claims (typically in 'sub' field)
                if let Some(user_id) = claims.get("sub").and_then(|v| v.as_str()) {
                    return Some(user_id.to_string());
                }
                // Fallback to 'user_id' field if 'sub' not found
                if let Some(user_id) = claims.get("user_id").and_then(|v| v.as_str()) {
                    return Some(user_id.to_string());
                }
            }
        }
    }
    
    None
}

/// Get rate limit rule for a specific category
fn get_rule_for_category<'a>(config: &'a RateLimitConfig, category: &str) -> &'a RateLimitRule {
    match category {
        "auth" => &config.limits.auth,
        "registration" => &config.limits.registration,
        "password_reset" => &config.limits.password_reset,
        "health" => &config.limits.health,
        _ => &config.limits.general,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, Uri};
    use std::str::FromStr;

    fn create_test_request(path: &str) -> Request {
        Request::builder()
            .method(Method::GET)
            .uri(Uri::from_str(path).unwrap())
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[test]
    fn test_get_client_ip_from_headers() {
        let mut request = create_test_request("/test");

        // Test X-Forwarded-For header
        request.headers_mut().insert(
            "X-Forwarded-For",
            HeaderValue::from_str("192.168.1.100, 10.0.0.1").unwrap(),
        );

        let ip = get_client_ip(&request, "127.0.0.1".to_string());
        assert_eq!(ip, "192.168.1.100");
    }

    #[test]
    fn test_get_client_ip_fallback() {
        let request = create_test_request("/test");
        let ip = get_client_ip(&request, "127.0.0.1".to_string());
        assert_eq!(ip, "127.0.0.1");
    }

    #[test]
    fn test_memory_rate_limit_store() {
        let store = MemoryRateLimitStore::new(100);
        let rule = RateLimitRule {
            max_requests: 5,
            window_seconds: 60,
            per_ip: true,
            per_user: false,
        };

        let current_time = 1234567890;

        // First request should be allowed
        let status = store.check_and_increment("test_key", &rule, current_time);
        assert!(status.allowed);
        assert_eq!(status.current_requests, 1);

        // Fifth request should still be allowed
        for _ in 2..=5 {
            let status = store.check_and_increment("test_key", &rule, current_time);
            assert!(status.allowed);
        }

        // Sixth request should be blocked
        let status = store.check_and_increment("test_key", &rule, current_time);
        assert!(!status.allowed);
        assert_eq!(status.current_requests, 6);
        assert!(status.retry_after.is_some());
    }

    #[test]
    fn test_get_rule_for_category() {
        let config = RateLimitConfig::default();

        assert_eq!(get_rule_for_category(&config, "auth").max_requests, 5);
        assert_eq!(
            get_rule_for_category(&config, "registration").max_requests,
            3
        );
        assert_eq!(get_rule_for_category(&config, "health").max_requests, 1000);
        assert_eq!(get_rule_for_category(&config, "unknown").max_requests, 100);
        // general
    }

    #[test]
    fn test_extract_user_id_from_request() {
        // Create a test JWT token (without signature verification)
        // Payload: {"sub": "user123", "exp": 1234567890}
        let payload = r#"{"sub":"user123","exp":1234567890}"#;
        let encoded_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        let fake_token = format!("header.{}.signature", encoded_payload);
        
        let mut request = create_test_request("/test");
        request.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", fake_token)).unwrap(),
        );

        let user_id = extract_user_id_from_request(&request);
        assert_eq!(user_id, Some("user123".to_string()));
    }

    #[test]
    fn test_extract_user_id_no_token() {
        let request = create_test_request("/test");
        let user_id = extract_user_id_from_request(&request);
        assert_eq!(user_id, None);
    }
}
