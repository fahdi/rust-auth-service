use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Log structured error information with request context
#[allow(dead_code)]
fn log_error_with_context(
    error_type: &str,
    message: &str,
    details: Option<&str>,
    request_id: &str,
) {
    if let Some(details) = details {
        error!(
            error_type = error_type,
            error_details = details,
            request_id = request_id,
            "{}",
            message
        );
    } else {
        error!(
            error_type = error_type,
            request_id = request_id,
            "{}",
            message
        );
    }
}

/// Log structured warning with request context
#[allow(dead_code)]
fn log_warning_with_context(warning_type: &str, message: &str, request_id: &str) {
    warn!(
        warning_type = warning_type,
        request_id = request_id,
        "{}",
        message
    );
}

/// Application error types
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Many variants unused in current implementation
pub enum AppError {
    #[error("Validation error: {message}")]
    Validation { message: String },

    #[error("Authentication failed")]
    Unauthorized,

    #[error("Insufficient permissions")]
    Forbidden,

    #[error("Resource not found")]
    NotFound,

    #[error("Resource already exists")]
    Conflict,

    #[error("Account is locked")]
    Locked,

    #[error("Rate limit exceeded")]
    #[allow(dead_code)]
    RateLimited,

    #[error("Internal server error")]
    Internal,

    #[error("Database error: {0}")]
    Database(String),

    #[error("Database connection error")]
    DatabaseConnection,

    #[error("Database timeout")]
    DatabaseTimeout,

    #[error("JWT error: {0}")]
    #[allow(dead_code)]
    Jwt(String),

    #[error("JWT token expired")]
    JwtExpired,

    #[error("JWT token invalid")]
    JwtInvalid,

    #[error("Cache error: {0}")]
    #[allow(dead_code)]
    Cache(String),

    #[error("Cache unavailable")]
    CacheUnavailable,

    #[error("Email service error: {0}")]
    #[allow(dead_code)]
    Email(String),

    #[error("Email delivery failed")]
    EmailDeliveryFailed,

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Service temporarily unavailable")]
    ServiceUnavailable,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message, error_code) = match &self {
            AppError::Validation { message } => {
                (StatusCode::BAD_REQUEST, message.clone(), "VALIDATION_ERROR")
            }
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Authentication required".to_string(),
                "UNAUTHORIZED",
            ),
            AppError::Forbidden => (
                StatusCode::FORBIDDEN,
                "Insufficient permissions".to_string(),
                "FORBIDDEN",
            ),
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                "Resource not found".to_string(),
                "NOT_FOUND",
            ),
            AppError::Conflict => (
                StatusCode::CONFLICT,
                "Resource already exists".to_string(),
                "CONFLICT",
            ),
            AppError::Locked => (
                StatusCode::LOCKED,
                "Account is locked".to_string(),
                "ACCOUNT_LOCKED",
            ),
            AppError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded".to_string(),
                "RATE_LIMITED",
            ),
            AppError::Internal => {
                error!(error_type = "internal", "Internal server error occurred");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    "INTERNAL_ERROR",
                )
            }
            AppError::Database(msg) => {
                error!(error = %msg, error_type = "database", "Database operation failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    "DATABASE_ERROR",
                )
            }
            AppError::Jwt(msg) => {
                error!(error = %msg, error_type = "jwt", "JWT validation failed");
                (
                    StatusCode::UNAUTHORIZED,
                    "Invalid token".to_string(),
                    "INVALID_TOKEN",
                )
            }
            AppError::Cache(msg) => {
                error!(error = %msg, error_type = "cache", "Cache operation failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    "CACHE_ERROR",
                )
            }
            AppError::Email(msg) => {
                error!(error = %msg, "Email service error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    "EMAIL_ERROR",
                )
            }
            AppError::DatabaseConnection => {
                error!("Database connection failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable".to_string(),
                    "DATABASE_CONNECTION_ERROR",
                )
            }
            AppError::DatabaseTimeout => {
                warn!("Database operation timed out");
                (
                    StatusCode::REQUEST_TIMEOUT,
                    "Request timed out".to_string(),
                    "DATABASE_TIMEOUT",
                )
            }
            AppError::JwtExpired => {
                info!("JWT token expired");
                (
                    StatusCode::UNAUTHORIZED,
                    "Token has expired".to_string(),
                    "TOKEN_EXPIRED",
                )
            }
            AppError::JwtInvalid => {
                warn!("Invalid JWT token provided");
                (
                    StatusCode::UNAUTHORIZED,
                    "Invalid token".to_string(),
                    "TOKEN_INVALID",
                )
            }
            AppError::CacheUnavailable => {
                warn!("Cache service unavailable, using fallback");
                (
                    StatusCode::OK, // Don't fail the request if cache is down
                    "Request processed with degraded performance".to_string(),
                    "CACHE_UNAVAILABLE",
                )
            }
            AppError::EmailDeliveryFailed => {
                error!("Email delivery failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Email service temporarily unavailable".to_string(),
                    "EMAIL_DELIVERY_FAILED",
                )
            }
            AppError::Configuration(msg) => {
                error!(config_error = %msg, "Configuration error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    "CONFIGURATION_ERROR",
                )
            }
            AppError::ServiceUnavailable => {
                warn!("Service temporarily unavailable");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable".to_string(),
                    "SERVICE_UNAVAILABLE",
                )
            }
        };

        // Generate a unique request ID for tracing
        let request_id = Uuid::new_v4().to_string();

        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": error_message,
                "request_id": request_id,
            },
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }));

        (status, body).into_response()
    }
}

impl From<crate::models::user::UserError> for AppError {
    fn from(err: crate::models::user::UserError) -> Self {
        match err {
            crate::models::user::UserError::NotFound => AppError::NotFound,
            crate::models::user::UserError::EmailAlreadyExists => AppError::Conflict,
            crate::models::user::UserError::InvalidCredentials => AppError::Unauthorized,
            crate::models::user::UserError::AccountLocked => AppError::Locked,
            crate::models::user::UserError::EmailNotVerified => AppError::Forbidden,
            crate::models::user::UserError::InvalidVerificationToken => AppError::Unauthorized,
            crate::models::user::UserError::VerificationTokenExpired => AppError::Unauthorized,
            crate::models::user::UserError::InvalidPasswordResetToken => AppError::Unauthorized,
            crate::models::user::UserError::PasswordResetTokenExpired => AppError::Unauthorized,
            crate::models::user::UserError::Database(msg) => AppError::Database(msg),
            crate::models::user::UserError::Validation(msg) => {
                AppError::Validation { message: msg }
            }
        }
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(err: validator::ValidationErrors) -> Self {
        let message = err
            .field_errors()
            .iter()
            .map(|(field, errors)| {
                let error_messages: Vec<String> = errors
                    .iter()
                    .filter_map(|error| error.message.as_ref().map(|m| m.to_string()))
                    .collect();
                format!("{}: {}", field, error_messages.join(", "))
            })
            .collect::<Vec<String>>()
            .join("; ");

        AppError::Validation { message }
    }
}

/// Result type alias for application errors
pub type AppResult<T> = Result<T, AppError>;

/// Error response for API endpoints
#[derive(serde::Serialize)]
#[allow(dead_code)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
    pub timestamp: String,
}

#[derive(serde::Serialize)]
#[allow(dead_code)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

#[allow(dead_code)]
impl ErrorResponse {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            error: ErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}
