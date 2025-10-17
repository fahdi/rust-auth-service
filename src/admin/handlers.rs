use axum::{
    extract::{Path, Query, State},
    response::{Html, Json},
    Extension,
};
use serde_json::json;
use tracing::{debug, info};

use crate::{
    admin::{
        AdminActionRequest, AdminActionResponse, ClientManagement, DashboardStats,
        PaginatedResponse, PaginationParams, SecurityEvent, SystemMetrics, UserManagement,
    },
    errors::{AppError, AppResult},
    utils::jwt::JwtClaims,
    AppState,
};

/// Admin dashboard HTML page
#[utoipa::path(
    get,
    path = "/admin",
    tag = "admin"
)]
pub async fn admin_dashboard() -> Html<&'static str> {
    Html(include_str!("../../templates/admin_dashboard.html"))
}

/// Get dashboard statistics
#[utoipa::path(
    get,
    path = "/admin/api/stats",
    tag = "admin"
)]
pub async fn get_dashboard_stats(
    State(_state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
) -> AppResult<Json<DashboardStats>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    debug!("Fetching dashboard statistics for admin: {}", claims.email);

    // TODO: Replace with actual database queries
    let stats = DashboardStats {
        total_users: 1250,
        active_users: 890,
        verified_users: 1100,
        admin_users: 5,
        auth_attempts_24h: 3450,
        success_rate: 94.5,
        active_sessions: 234,
        database_healthy: true,
        cache_healthy: true,
        uptime_seconds: 86400,
    };

    info!("Dashboard statistics retrieved successfully");
    Ok(Json(stats))
}

/// Get system metrics
#[utoipa::path(
    get,
    path = "/admin/api/metrics",
    tag = "admin"
)]
pub async fn get_system_metrics(
    State(_state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
) -> AppResult<Json<SystemMetrics>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    debug!("Fetching system metrics for admin: {}", claims.email);

    // TODO: Replace with actual system monitoring
    let metrics = SystemMetrics {
        cpu_usage: 25.6,
        memory_usage_mb: 128,
        memory_usage_percent: 45.2,
        disk_usage_percent: 67.8,
        requests_per_minute: 1200,
        avg_response_time_ms: 85.3,
        error_rate_percent: 0.8,
        db_connections_active: 12,
        cache_hit_rate_percent: 89.5,
    };

    Ok(Json(metrics))
}

/// List users with pagination
#[utoipa::path(
    get,
    path = "/admin/api/users",
    tag = "admin"
)]
pub async fn list_users(
    State(_state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<UserManagement>>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20);

    debug!("Listing users - page: {}, limit: {}", page, limit);

    // TODO: Replace with actual database queries
    let users = vec![
        UserManagement {
            user_id: "user_001".to_string(),
            email: "john.doe@example.com".to_string(),
            full_name: "John Doe".to_string(),
            role: "user".to_string(),
            is_active: true,
            email_verified: true,
            last_login: Some("2025-10-17T10:30:00Z".to_string()),
            created_at: "2025-09-15T08:20:00Z".to_string(),
            failed_attempts: 0,
            is_locked: false,
        },
        UserManagement {
            user_id: "user_002".to_string(),
            email: "jane.smith@example.com".to_string(),
            full_name: "Jane Smith".to_string(),
            role: "user".to_string(),
            is_active: true,
            email_verified: false,
            last_login: None,
            created_at: "2025-10-16T14:45:00Z".to_string(),
            failed_attempts: 2,
            is_locked: false,
        },
    ];

    let response = PaginatedResponse::new(users, page, limit, 150);
    Ok(Json(response))
}

/// Get user details by ID
#[utoipa::path(
    get,
    path = "/admin/api/users/{user_id}",
    tag = "admin"
)]
pub async fn get_user_details(
    State(_state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<String>,
) -> AppResult<Json<UserManagement>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    debug!("Getting user details for: {}", user_id);

    // TODO: Replace with actual database query
    let user = UserManagement {
        user_id: user_id.clone(),
        email: "user@example.com".to_string(),
        full_name: "User Name".to_string(),
        role: "user".to_string(),
        is_active: true,
        email_verified: true,
        last_login: Some("2025-10-17T10:30:00Z".to_string()),
        created_at: "2025-09-15T08:20:00Z".to_string(),
        failed_attempts: 0,
        is_locked: false,
    };

    Ok(Json(user))
}

/// Perform admin action on user
#[utoipa::path(
    post,
    path = "/admin/api/users/{user_id}/action",
    tag = "admin"
)]
pub async fn admin_user_action(
    State(_state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<String>,
    Json(action_request): Json<AdminActionRequest>,
) -> AppResult<Json<AdminActionResponse>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    info!(
        "Admin {} performing action '{}' on user {}",
        claims.email, action_request.action, user_id
    );

    // TODO: Implement actual admin actions
    let response = match action_request.action.as_str() {
        "activate" => AdminActionResponse {
            success: true,
            message: "User activated successfully".to_string(),
            user_data: None,
        },
        "deactivate" => AdminActionResponse {
            success: true,
            message: "User deactivated successfully".to_string(),
            user_data: None,
        },
        "verify_email" => AdminActionResponse {
            success: true,
            message: "Email verified successfully".to_string(),
            user_data: None,
        },
        "unlock_account" => AdminActionResponse {
            success: true,
            message: "Account unlocked successfully".to_string(),
            user_data: None,
        },
        "reset_password" => AdminActionResponse {
            success: true,
            message: "Password reset email sent".to_string(),
            user_data: None,
        },
        _ => AdminActionResponse {
            success: false,
            message: "Unknown action".to_string(),
            user_data: None,
        },
    };

    Ok(Json(response))
}

/// List OAuth2 clients
#[utoipa::path(
    get,
    path = "/admin/api/clients",
    tag = "admin"
)]
pub async fn list_oauth2_clients(
    State(_state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ClientManagement>>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20);

    debug!("Listing OAuth2 clients - page: {}, limit: {}", page, limit);

    // TODO: Replace with actual database queries
    let clients = vec![
        ClientManagement {
            client_id: "client_001".to_string(),
            client_name: "Web Application".to_string(),
            client_type: "confidential".to_string(),
            redirect_uris: vec!["https://app.example.com/callback".to_string()],
            scopes: vec!["read".to_string(), "write".to_string()],
            is_active: true,
            created_at: "2025-09-01T12:00:00Z".to_string(),
            last_used: Some("2025-10-17T09:15:00Z".to_string()),
            tokens_issued: 1250,
        },
        ClientManagement {
            client_id: "client_002".to_string(),
            client_name: "Mobile App".to_string(),
            client_type: "public".to_string(),
            redirect_uris: vec!["com.example.app://callback".to_string()],
            scopes: vec!["read".to_string()],
            is_active: true,
            created_at: "2025-09-15T16:30:00Z".to_string(),
            last_used: Some("2025-10-16T18:45:00Z".to_string()),
            tokens_issued: 890,
        },
    ];

    let response = PaginatedResponse::new(clients, page, limit, 25);
    Ok(Json(response))
}

/// List security events
#[utoipa::path(
    get,
    path = "/admin/api/security/events",
    tag = "admin"
)]
pub async fn list_security_events(
    State(_state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<SecurityEvent>>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(50);

    debug!("Listing security events - page: {}, limit: {}", page, limit);

    // TODO: Replace with actual security event logs
    let events = vec![
        SecurityEvent {
            event_id: "evt_001".to_string(),
            event_type: "failed_login".to_string(),
            user_id: Some("user_002".to_string()),
            ip_address: "192.168.1.100".to_string(),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string()),
            description: "Failed login attempt with invalid password".to_string(),
            risk_level: "medium".to_string(),
            timestamp: "2025-10-17T10:15:00Z".to_string(),
            metadata: json!({"attempts": 3, "account_locked": false}),
        },
        SecurityEvent {
            event_id: "evt_002".to_string(),
            event_type: "suspicious_activity".to_string(),
            user_id: None,
            ip_address: "10.0.0.45".to_string(),
            user_agent: Some("curl/7.68.0".to_string()),
            description: "Multiple rapid requests from unusual IP".to_string(),
            risk_level: "high".to_string(),
            timestamp: "2025-10-17T09:45:00Z".to_string(),
            metadata: json!({"requests_per_minute": 500, "blocked": true}),
        },
    ];

    let response = PaginatedResponse::new(events, page, limit, 1000);
    Ok(Json(response))
}

/// Export user data (CSV format)
#[utoipa::path(
    get,
    path = "/admin/api/users/export",
    tag = "admin"
)]
pub async fn export_users(
    State(_state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
) -> AppResult<String> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    info!("Admin {} exporting user data", claims.email);

    // TODO: Generate actual CSV from database
    let csv_data = "user_id,email,full_name,role,is_active,email_verified,created_at\n\
        user_001,john.doe@example.com,John Doe,user,true,true,2025-09-15T08:20:00Z\n\
        user_002,jane.smith@example.com,Jane Smith,user,true,false,2025-10-16T14:45:00Z\n";

    Ok(csv_data.to_string())
}

/// Search users by email or name
#[utoipa::path(
    get,
    path = "/admin/api/users/search",
    tag = "admin"
)]
pub async fn search_users(
    State(_state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<UserManagement>>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    let search_query = params.search.unwrap_or_default();
    debug!("Searching users with query: {}", search_query);

    // TODO: Implement actual search functionality
    let users = vec![];
    let response = PaginatedResponse::new(users, 1, 20, 0);
    
    Ok(Json(response))
}