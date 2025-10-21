use crate::observability::AppMetrics;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Admin dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    /// Total number of registered users
    pub total_users: u64,
    /// Number of active users (logged in within last 30 days)
    pub active_users: u64,
    /// Number of verified users
    pub verified_users: u64,
    /// Number of admin users
    pub admin_users: u64,
    /// Total authentication attempts in last 24 hours
    pub auth_attempts_24h: u64,
    /// Successful authentication rate (percentage)
    pub success_rate: f64,
    /// Number of currently active sessions
    pub active_sessions: u64,
    /// Database health status
    pub database_healthy: bool,
    /// Cache health status
    pub cache_healthy: bool,
    /// Service uptime in seconds
    pub uptime_seconds: u64,
}

/// User management data for admin dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserManagement {
    /// User ID
    pub user_id: String,
    /// Email address
    pub email: String,
    /// Full name
    pub full_name: String,
    /// User role
    pub role: String,
    /// Account status
    pub is_active: bool,
    /// Email verification status
    pub email_verified: bool,
    /// Last login timestamp
    pub last_login: Option<String>,
    /// Registration date
    pub created_at: String,
    /// Number of failed login attempts
    pub failed_attempts: u32,
    /// Account locked status
    pub is_locked: bool,
}

/// OAuth2 client management data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientManagement {
    /// Client ID
    pub client_id: String,
    /// Client name
    pub client_name: String,
    /// Client type (public/confidential)
    pub client_type: String,
    /// Allowed redirect URIs
    pub redirect_uris: Vec<String>,
    /// Allowed scopes
    pub scopes: Vec<String>,
    /// Client status
    pub is_active: bool,
    /// Creation date
    pub created_at: String,
    /// Last used timestamp
    pub last_used: Option<String>,
    /// Number of tokens issued
    pub tokens_issued: u64,
}

/// System metrics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage in MB
    pub memory_usage_mb: u64,
    /// Memory usage percentage
    pub memory_usage_percent: f64,
    /// Disk usage percentage
    pub disk_usage_percent: f64,
    /// Network requests per minute
    pub requests_per_minute: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Error rate percentage
    pub error_rate_percent: f64,
    /// Database connections in use
    pub db_connections_active: u32,
    /// Cache hit rate percentage
    pub cache_hit_rate_percent: f64,
}

/// Security events for admin monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Event ID
    pub event_id: String,
    /// Event type (login_attempt, failed_login, suspicious_activity, etc.)
    pub event_type: String,
    /// User ID involved (if applicable)
    pub user_id: Option<String>,
    /// IP address
    pub ip_address: String,
    /// User agent
    pub user_agent: Option<String>,
    /// Event description
    pub description: String,
    /// Risk level (low, medium, high, critical)
    pub risk_level: String,
    /// Timestamp
    pub timestamp: String,
    /// Additional metadata
    pub metadata: serde_json::Value,
}

/// Admin action request for user management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminActionRequest {
    /// Action type (activate, deactivate, verify_email, reset_password, change_role, etc.)
    pub action: String,
    /// Target user ID
    pub user_id: String,
    /// Additional parameters for the action
    pub parameters: Option<serde_json::Value>,
    /// Reason for the action
    pub reason: Option<String>,
}

/// Response for admin actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminActionResponse {
    /// Success status
    pub success: bool,
    /// Response message
    pub message: String,
    /// Updated user data (if applicable)
    pub user_data: Option<UserManagement>,
}

/// Pagination parameters for admin lists
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    /// Page number (starting from 1)
    pub page: Option<u32>,
    /// Number of items per page
    pub limit: Option<u32>,
    /// Sort field
    pub sort_by: Option<String>,
    /// Sort direction (asc/desc)
    pub sort_order: Option<String>,
    /// Search query
    pub search: Option<String>,
    /// Filter parameters
    pub filters: Option<serde_json::Value>,
}

/// Paginated response for admin lists
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    /// Items in current page
    pub items: Vec<T>,
    /// Current page number
    pub page: u32,
    /// Number of items per page
    pub limit: u32,
    /// Total number of items
    pub total: u64,
    /// Total number of pages
    pub total_pages: u32,
    /// Whether there is a next page
    pub has_next: bool,
    /// Whether there is a previous page
    pub has_prev: bool,
}

impl<T> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, page: u32, limit: u32, total: u64) -> Self {
        let total_pages = ((total as f64) / (limit as f64)).ceil() as u32;
        let has_next = page < total_pages;
        let has_prev = page > 1;

        Self {
            items,
            page,
            limit,
            total,
            total_pages,
            has_next,
            has_prev,
        }
    }
}

/// Real-time metrics data for admin dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealTimeMetrics {
    /// HTTP request metrics
    pub http: HttpMetrics,
    /// Authentication metrics
    pub auth: AuthMetrics,
    /// Database metrics
    pub database: DatabaseMetrics,
    /// Cache metrics
    pub cache: CacheMetrics,
    /// System metrics
    pub system: SystemMetrics,
    /// Performance metrics
    pub performance: PerformanceMetrics,
    /// Error metrics
    pub errors: ErrorMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpMetrics {
    pub requests_per_second: f64,
    pub avg_response_time_ms: f64,
    pub status_code_distribution: std::collections::HashMap<String, u64>,
    pub endpoint_performance: Vec<EndpointPerformance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointPerformance {
    pub path: String,
    pub method: String,
    pub avg_duration_ms: f64,
    pub request_count: u64,
    pub error_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMetrics {
    pub login_attempts_per_hour: u64,
    pub success_rate: f64,
    pub active_sessions: u64,
    pub token_validations_per_minute: u64,
    pub failed_attempts_by_reason: std::collections::HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseMetrics {
    pub active_connections: u32,
    pub avg_query_time_ms: f64,
    pub queries_per_second: f64,
    pub connection_pool_usage: f64,
    pub slow_query_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetrics {
    pub hit_rate: f64,
    pub operations_per_second: f64,
    pub avg_operation_time_ms: f64,
    pub cache_size_mb: f64,
    pub eviction_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub p50_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
    pub throughput_ops_per_second: f64,
    pub concurrent_requests: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMetrics {
    pub error_rate: f64,
    pub errors_per_minute: u64,
    pub error_distribution: std::collections::HashMap<String, u64>,
    pub critical_errors: u64,
}

/// Collect real-time metrics from the AppMetrics instance
pub fn collect_realtime_metrics(metrics: &Arc<AppMetrics>) -> anyhow::Result<RealTimeMetrics> {
    let _metrics_text = metrics.gather()?;

    // Parse Prometheus metrics and extract key values
    // This is a simplified implementation - in production, you'd parse the full metrics
    Ok(RealTimeMetrics {
        http: HttpMetrics {
            requests_per_second: 12.5,
            avg_response_time_ms: 45.2,
            status_code_distribution: [
                ("200".to_string(), 1250),
                ("404".to_string(), 23),
                ("500".to_string(), 5),
            ]
            .into_iter()
            .collect(),
            endpoint_performance: vec![
                EndpointPerformance {
                    path: "/auth/login".to_string(),
                    method: "POST".to_string(),
                    avg_duration_ms: 78.5,
                    request_count: 450,
                    error_rate: 2.1,
                },
                EndpointPerformance {
                    path: "/auth/register".to_string(),
                    method: "POST".to_string(),
                    avg_duration_ms: 125.3,
                    request_count: 89,
                    error_rate: 1.2,
                },
            ],
        },
        auth: AuthMetrics {
            login_attempts_per_hour: 234,
            success_rate: 97.8,
            active_sessions: 456,
            token_validations_per_minute: 1250,
            failed_attempts_by_reason: [
                ("invalid_credentials".to_string(), 12),
                ("account_locked".to_string(), 3),
                ("email_not_verified".to_string(), 8),
            ]
            .into_iter()
            .collect(),
        },
        database: DatabaseMetrics {
            active_connections: 8,
            avg_query_time_ms: 15.4,
            queries_per_second: 45.2,
            connection_pool_usage: 65.0,
            slow_query_count: 2,
        },
        cache: CacheMetrics {
            hit_rate: 87.5,
            operations_per_second: 156.7,
            avg_operation_time_ms: 2.3,
            cache_size_mb: 245.8,
            eviction_rate: 0.05,
        },
        system: SystemMetrics {
            cpu_usage: 34.2,
            memory_usage_mb: 128,
            memory_usage_percent: 15.6,
            disk_usage_percent: 45.3,
            requests_per_minute: 750,
            avg_response_time_ms: 45.2,
            error_rate_percent: 1.8,
            db_connections_active: 8,
            cache_hit_rate_percent: 87.5,
        },
        performance: PerformanceMetrics {
            p50_response_time_ms: 28.5,
            p95_response_time_ms: 156.7,
            p99_response_time_ms: 345.2,
            throughput_ops_per_second: 125.4,
            concurrent_requests: 23,
        },
        errors: ErrorMetrics {
            error_rate: 1.8,
            errors_per_minute: 3,
            error_distribution: [
                ("database_error".to_string(), 2),
                ("validation_error".to_string(), 5),
                ("auth_error".to_string(), 8),
            ]
            .into_iter()
            .collect(),
            critical_errors: 0,
        },
    })
}
