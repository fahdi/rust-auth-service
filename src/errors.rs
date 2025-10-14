use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::error;

/// Application error types
#[derive(Debug, thiserror::Error)]
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
    RateLimited,

    #[error("Internal server error")]
    Internal,

    #[error("Database error: {0}")]
    Database(String),

    #[error("JWT error: {0}")]
    Jwt(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Email service error: {0}")]
    Email(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message, error_code) = match &self {
            AppError::Validation { message } => {
                (StatusCode::BAD_REQUEST, message.clone(), "VALIDATION_ERROR")
            }
            AppError::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "Authentication required".to_string(), "UNAUTHORIZED")
            }
            AppError::Forbidden => {
                (StatusCode::FORBIDDEN, "Insufficient permissions".to_string(), "FORBIDDEN")
            }
            AppError::NotFound => {
                (StatusCode::NOT_FOUND, "Resource not found".to_string(), "NOT_FOUND")
            }
            AppError::Conflict => {
                (StatusCode::CONFLICT, "Resource already exists".to_string(), "CONFLICT")
            }
            AppError::Locked => {
                (StatusCode::LOCKED, "Account is locked".to_string(), "ACCOUNT_LOCKED")
            }
            AppError::RateLimited => {
                (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string(), "RATE_LIMITED")
            }
            AppError::Internal => {
                error!("Internal server error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string(), "INTERNAL_ERROR")
            }
            AppError::Database(msg) => {
                error!("Database error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string(), "DATABASE_ERROR")
            }
            AppError::Jwt(msg) => {
                error!("JWT error: {}", msg);
                (StatusCode::UNAUTHORIZED, "Invalid token".to_string(), "INVALID_TOKEN")
            }
            AppError::Cache(msg) => {
                error!("Cache error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string(), "CACHE_ERROR")
            }
            AppError::Email(msg) => {
                error!("Email service error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string(), "EMAIL_ERROR")
            }
        };

        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": error_message,
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
            crate::models::user::UserError::Validation(msg) => AppError::Validation { message: msg },
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
pub struct ErrorResponse {
    pub error: ErrorDetail,
    pub timestamp: String,
}

#[derive(serde::Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

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