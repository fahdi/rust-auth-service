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
            store.retain(|_k, (_, window)| {
                current_time - *window < rule.window_seconds * 2
            });
        }
        
        let (current_count, _) = store
            .entry(full_key.clone())
            .or_insert((0, window_start));
        
        let new_count = *current_count + 1;
        let allowed = new_count <= rule.max_requests;
        
        if allowed {
            *current_count = new_count;
        }
        
        let reset_time = window_start + rule.window_seconds - current_time;
        let retry_after = if !allowed {
            Some(reset_time)
        } else {
            None
        };
        
        RateLimitStatus {
            allowed,
            current_requests: new_count,
            max_requests: rule.max_requests,
            reset_time,
            retry_after,
        }
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
    
    debug!("Rate limiting check for {} {} from IP: {}", method, path, client_ip);
    
    // Detect endpoint category
    let category = detect_endpoint_category(path);
    let rule = get_rule_for_category(&state.config.rate_limit, category);
    
    // Generate rate limit key
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Internal)?
        .as_secs();
    
    let identifier = if rule.per_ip {
        client_ip.clone()
    } else {
        "global".to_string() // For global rate limiting
    };
    
    let key = generate_rate_limit_key(category, &identifier, current_time);
    
    // Check rate limit using memory store for now
    // TODO: Add Redis support for distributed rate limiting
    let store = MemoryRateLimitStore::new(state.config.rate_limit.memory_cache_size);
    let status = store.check_and_increment(&key, rule, current_time);
    
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
    
    if let Ok(remaining_header) = HeaderValue::from_str(&(status.max_requests.saturating_sub(status.current_requests)).to_string()) {
        headers.insert("X-RateLimit-Remaining", remaining_header);
    }
    
    if let Ok(reset_header) = HeaderValue::from_str(&(current_time + status.reset_time).to_string()) {
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
        assert_eq!(get_rule_for_category(&config, "registration").max_requests, 3);
        assert_eq!(get_rule_for_category(&config, "health").max_requests, 1000);
        assert_eq!(get_rule_for_category(&config, "unknown").max_requests, 100); // general
    }
}