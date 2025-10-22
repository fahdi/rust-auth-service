use axum::{
    extract::{Path, Query, State},
    response::{Html, Json},
    Extension,
};
use serde_json::json;
use tracing::{debug, info, warn};

use crate::{
    admin::{
        collect_realtime_metrics, AdminActionRequest, AdminActionResponse, ClientManagement,
        DashboardStats, PaginatedResponse, PaginationParams, RealTimeMetrics, SecurityEvent,
        SystemMetrics, UserManagement,
    },
    errors::{AppError, AppResult},
    utils::jwt::JwtClaims,
    AppState,
};

/// Admin dashboard HTML page
pub async fn admin_dashboard() -> Html<&'static str> {
    Html(include_str!("../../templates/admin_dashboard.html"))
}

/// Get dashboard statistics
pub async fn get_dashboard_stats(
    State(state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
) -> AppResult<Json<DashboardStats>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    debug!("Fetching dashboard statistics for admin: {}", claims.email);

    // Get total users count
    let total_users = match state.database.count_users().await {
        Ok(count) => count,
        Err(e) => {
            warn!("Failed to get total users count: {}", e);
            0
        }
    };

    // Get verified users count
    let verified_users = match state.database.count_verified_users().await {
        Ok(count) => count,
        Err(e) => {
            warn!("Failed to get verified users count: {}", e);
            0
        }
    };

    // Get active users (simplified - users who have logged in recently)
    let active_users = match state.database.count_active_users().await {
        Ok(count) => count,
        Err(e) => {
            warn!("Failed to get active users count: {}", e);
            0
        }
    };

    // Get admin users count
    let admin_users = match state.database.count_admin_users().await {
        Ok(count) => count,
        Err(e) => {
            warn!("Failed to get admin users count: {}", e);
            0
        }
    };

    // Check database health
    let database_healthy = state.database.health_check().await.is_ok();

    // Check cache health (simplified - cache service doesn't have health_check method)
    let cache_healthy = true; // Could be implemented with a simple Redis ping

    // Calculate success rate (simplified implementation)
    let success_rate = if total_users > 0 {
        (verified_users as f64 / total_users as f64) * 100.0
    } else {
        0.0
    };

    let stats = DashboardStats {
        total_users,
        active_users,
        verified_users,
        admin_users,
        auth_attempts_24h: 0, // Would need session/metrics tracking
        success_rate,
        active_sessions: 0, // Would need session tracking
        database_healthy,
        cache_healthy,
        uptime_seconds: 0, // Would need startup time tracking
    };

    info!("Dashboard statistics retrieved successfully");
    Ok(Json(stats))
}

/// Get system metrics
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
pub async fn list_users(
    State(state): State<AppState>,
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

    // Get total count for pagination
    let total_count = match state.database.count_users().await {
        Ok(count) => count,
        Err(e) => {
            warn!("Failed to get total users count: {}", e);
            return Err(AppError::Internal);
        }
    };

    // Get paginated users
    let db_users = match state.database.list_users(page, limit).await {
        Ok(users) => users,
        Err(e) => {
            warn!("Failed to list users: {}", e);
            return Err(AppError::Internal);
        }
    };

    // Convert to UserManagement format
    let users: Vec<UserManagement> = db_users
        .into_iter()
        .map(|user| {
            let is_locked = user.is_locked();
            UserManagement {
                user_id: user.user_id,
                email: user.email,
                full_name: format!("{} {}", user.first_name, user.last_name),
                role: user.role.to_string(),
                is_active: user.is_active,
                email_verified: user.email_verified,
                last_login: user.last_login.map(|dt| dt.to_rfc3339()),
                created_at: user.created_at.to_rfc3339(),
                failed_attempts: user.login_attempts,
                is_locked,
            }
        })
        .collect();

    let response = PaginatedResponse::new(users, page, limit, total_count);
    Ok(Json(response))
}

/// Get user details by ID
pub async fn get_user_details(
    State(state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<String>,
) -> AppResult<Json<UserManagement>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    debug!("Getting user details for: {}", user_id);

    let db_user = match state.database.get_user_for_admin(&user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(AppError::NotFound),
        Err(e) => {
            warn!("Failed to get user details: {}", e);
            return Err(AppError::Internal);
        }
    };

    let is_locked = db_user.is_locked();
    let user = UserManagement {
        user_id: db_user.user_id,
        email: db_user.email,
        full_name: format!("{} {}", db_user.first_name, db_user.last_name),
        role: db_user.role.to_string(),
        is_active: db_user.is_active,
        email_verified: db_user.email_verified,
        last_login: db_user.last_login.map(|dt| dt.to_rfc3339()),
        created_at: db_user.created_at.to_rfc3339(),
        failed_attempts: db_user.login_attempts,
        is_locked,
    };

    Ok(Json(user))
}

/// Perform admin action on user
pub async fn admin_user_action(
    State(state): State<AppState>,
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

    let response = match action_request.action.as_str() {
        "activate" => match state.database.set_user_lock_status(&user_id, false).await {
            Ok(_) => AdminActionResponse {
                success: true,
                message: "User activated successfully".to_string(),
                user_data: None,
            },
            Err(e) => {
                warn!("Failed to activate user {}: {}", user_id, e);
                AdminActionResponse {
                    success: false,
                    message: "Failed to activate user".to_string(),
                    user_data: None,
                }
            }
        },
        "deactivate" => match state.database.deactivate_user(&user_id).await {
            Ok(_) => AdminActionResponse {
                success: true,
                message: "User deactivated successfully".to_string(),
                user_data: None,
            },
            Err(e) => {
                warn!("Failed to deactivate user {}: {}", user_id, e);
                AdminActionResponse {
                    success: false,
                    message: "Failed to deactivate user".to_string(),
                    user_data: None,
                }
            }
        },
        "verify_email" => match state.database.admin_verify_email(&user_id).await {
            Ok(_) => AdminActionResponse {
                success: true,
                message: "Email verified successfully".to_string(),
                user_data: None,
            },
            Err(e) => {
                warn!("Failed to verify email for user {}: {}", user_id, e);
                AdminActionResponse {
                    success: false,
                    message: "Failed to verify email".to_string(),
                    user_data: None,
                }
            }
        },
        "unlock_account" => match state.database.set_user_lock_status(&user_id, false).await {
            Ok(_) => AdminActionResponse {
                success: true,
                message: "Account unlocked successfully".to_string(),
                user_data: None,
            },
            Err(e) => {
                warn!("Failed to unlock account for user {}: {}", user_id, e);
                AdminActionResponse {
                    success: false,
                    message: "Failed to unlock account".to_string(),
                    user_data: None,
                }
            }
        },
        "lock_account" => match state.database.set_user_lock_status(&user_id, true).await {
            Ok(_) => AdminActionResponse {
                success: true,
                message: "Account locked successfully".to_string(),
                user_data: None,
            },
            Err(e) => {
                warn!("Failed to lock account for user {}: {}", user_id, e);
                AdminActionResponse {
                    success: false,
                    message: "Failed to lock account".to_string(),
                    user_data: None,
                }
            }
        },
        "change_role" => {
            if let Some(new_role) = action_request
                .parameters
                .as_ref()
                .and_then(|p| p.get("role"))
                .and_then(|r| r.as_str())
            {
                match state.database.update_user_role(&user_id, new_role).await {
                    Ok(_) => AdminActionResponse {
                        success: true,
                        message: format!("User role changed to {} successfully", new_role),
                        user_data: None,
                    },
                    Err(e) => {
                        warn!("Failed to change role for user {}: {}", user_id, e);
                        AdminActionResponse {
                            success: false,
                            message: "Failed to change user role".to_string(),
                            user_data: None,
                        }
                    }
                }
            } else {
                AdminActionResponse {
                    success: false,
                    message: "Role parameter is required".to_string(),
                    user_data: None,
                }
            }
        }
        _ => AdminActionResponse {
            success: false,
            message: "Unknown action".to_string(),
            user_data: None,
        },
    };

    Ok(Json(response))
}

/// List OAuth2 clients
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
pub async fn search_users(
    State(state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<UserManagement>>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    let search_query = params.search.unwrap_or_default();
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(20);

    debug!(
        "Searching users with query: {} - page: {}, limit: {}",
        search_query, page, limit
    );

    if search_query.is_empty() {
        // If no search query, return empty results
        let response = PaginatedResponse::new(vec![], page, limit, 0);
        return Ok(Json(response));
    }

    // Search users in database
    let db_users = match state
        .database
        .search_users(&search_query, page, limit)
        .await
    {
        Ok(users) => users,
        Err(e) => {
            warn!("Failed to search users: {}", e);
            return Err(AppError::Internal);
        }
    };

    // Convert to UserManagement format
    let users: Vec<UserManagement> = db_users
        .into_iter()
        .map(|user| {
            let is_locked = user.is_locked();
            UserManagement {
                user_id: user.user_id,
                email: user.email,
                full_name: format!("{} {}", user.first_name, user.last_name),
                role: user.role.to_string(),
                is_active: user.is_active,
                email_verified: user.email_verified,
                last_login: user.last_login.map(|dt| dt.to_rfc3339()),
                created_at: user.created_at.to_rfc3339(),
                failed_attempts: user.login_attempts,
                is_locked,
            }
        })
        .collect();

    // For simplicity, use the count of returned results as total
    // In a real implementation, you'd want a separate count query
    let total = users.len() as u64;
    let response = PaginatedResponse::new(users, page, limit, total);

    Ok(Json(response))
}

/// Get real-time metrics for admin dashboard
pub async fn get_realtime_metrics(
    State(state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
) -> AppResult<Json<RealTimeMetrics>> {
    // Verify admin access
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }

    debug!("Fetching real-time metrics for admin: {}", claims.email);

    match collect_realtime_metrics(&state.metrics) {
        Ok(metrics) => {
            info!("Real-time metrics collected successfully");
            Ok(Json(metrics))
        }
        Err(e) => {
            tracing::error!("Failed to collect real-time metrics: {}", e);
            Err(AppError::Internal)
        }
    }
}
