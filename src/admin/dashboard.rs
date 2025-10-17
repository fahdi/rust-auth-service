use serde::{Deserialize, Serialize};

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
