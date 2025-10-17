use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::debug;

use crate::{metrics, AppState};
use crate::observability::{RequestContext, log_request};

/// Middleware to collect HTTP request metrics
///
/// This middleware automatically records HTTP request metrics including:
/// - Request count by method, endpoint, and status code
/// - Request duration by method and endpoint
///
/// The metrics are sent to Prometheus for monitoring and alerting.
pub async fn metrics_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Skip metrics collection if disabled
    if !state.config.monitoring.metrics {
        return next.run(request).await;
    }

    let start_time = Instant::now();
    let method = request.method().to_string();
    let path = request.uri().path().to_string();

    // Normalize endpoint path for better grouping in metrics
    let endpoint = normalize_endpoint_path(&path);

    // Extract client IP and user agent for logging
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Create request context for structured logging
    let request_id = uuid::Uuid::new_v4().to_string();
    let request_context = RequestContext::new(
        request_id.clone(),
        client_ip,
        method.clone(),
        endpoint.clone(),
    )
    .with_user_agent(user_agent.unwrap_or_default());

    debug!(
        request_id = %request_id,
        "Recording metrics for {} {}",
        method,
        endpoint
    );

    // Process the request
    let response = next.run(request).await;

    // Calculate request duration and sizes
    let duration = start_time.elapsed();
    let status = response.status().as_u16();

    // Record comprehensive metrics
    // 1. Old metrics system
    metrics::record_http_request(&method, &endpoint, status, duration.as_secs_f64());

    // 2. New observability metrics
    state.metrics.record_http_request(
        &method,
        &endpoint,
        status,
        duration,
        None, // request_size - would need to be captured before processing
        None, // response_size - would need body inspection
    );

    // 3. Structured logging
    log_request(&request_context, status, None);

    debug!(
        "HTTP request completed: {} {} -> {} in {:.3}ms",
        method,
        endpoint,
        status,
        duration.as_millis()
    );

    response
}

/// Normalize endpoint paths for better metric grouping
///
/// This function replaces dynamic path segments with placeholders
/// to avoid creating too many unique metric series.
fn normalize_endpoint_path(path: &str) -> String {
    // Handle common API patterns
    match path {
        // Health check endpoints
        p if p == "/health" || p == "/ready" || p == "/live" => p.to_string(),

        // Metrics endpoints
        p if p == "/metrics" || p == "/stats" => p.to_string(),

        // Authentication endpoints
        p if p.starts_with("/auth/") => match p {
            "/auth/register" => "/auth/register".to_string(),
            "/auth/login" => "/auth/login".to_string(),
            "/auth/verify" => "/auth/verify".to_string(),
            "/auth/forgot-password" => "/auth/forgot-password".to_string(),
            "/auth/reset-password" => "/auth/reset-password".to_string(),
            "/auth/refresh" => "/auth/refresh".to_string(),
            "/auth/me" => "/auth/me".to_string(),
            "/auth/profile" => "/auth/profile".to_string(),
            "/auth/logout" => "/auth/logout".to_string(),
            _ => "/auth/unknown".to_string(),
        },

        // API endpoints with IDs - replace IDs with placeholder
        p if p.starts_with("/api/") => {
            // Replace UUIDs and numeric IDs with placeholders
            let normalized = p
                .split('/')
                .map(|segment| {
                    if is_uuid(segment) {
                        "{uuid}"
                    } else if is_numeric_id(segment) {
                        "{id}"
                    } else {
                        segment
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            normalized
        }

        // Default: return path as-is for other endpoints
        _ => path.to_string(),
    }
}

/// Check if a string looks like a UUID
fn is_uuid(s: &str) -> bool {
    // Basic UUID pattern check (8-4-4-4-12 hexadecimal digits)
    s.len() == 36
        && s.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Check if a string looks like a numeric ID
fn is_numeric_id(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty() && s.len() <= 20
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_endpoint_path() {
        // Health endpoints
        assert_eq!(normalize_endpoint_path("/health"), "/health");
        assert_eq!(normalize_endpoint_path("/ready"), "/ready");

        // Auth endpoints
        assert_eq!(normalize_endpoint_path("/auth/login"), "/auth/login");
        assert_eq!(normalize_endpoint_path("/auth/register"), "/auth/register");
        assert_eq!(
            normalize_endpoint_path("/auth/unknown-endpoint"),
            "/auth/unknown"
        );

        // API endpoints with IDs
        assert_eq!(normalize_endpoint_path("/api/users/123"), "/api/users/{id}");
        assert_eq!(
            normalize_endpoint_path("/api/users/550e8400-e29b-41d4-a716-446655440000"),
            "/api/users/{uuid}"
        );
        assert_eq!(
            normalize_endpoint_path("/api/users/123/posts/456"),
            "/api/users/{id}/posts/{id}"
        );

        // Other endpoints
        assert_eq!(
            normalize_endpoint_path("/custom/endpoint"),
            "/custom/endpoint"
        );
    }

    #[test]
    fn test_is_uuid() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430c8"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("123"));
        assert!(!is_uuid("550e8400-e29b-41d4-a716"));
    }

    #[test]
    fn test_is_numeric_id() {
        assert!(is_numeric_id("123"));
        assert!(is_numeric_id("1"));
        assert!(is_numeric_id("999999999"));
        assert!(!is_numeric_id("abc"));
        assert!(!is_numeric_id("12abc"));
        assert!(!is_numeric_id(""));
        assert!(!is_numeric_id("123456789012345678901")); // Too long
    }
}
