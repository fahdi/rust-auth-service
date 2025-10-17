use axum::{
    extract::{Path, State},
    response::Json,
    Extension,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::AppError;
use crate::models::user::User;
use crate::utils::response::ApiResponse;
use super::super::AppState;
use crate::mfa::MfaType;

/// MFA setup request
#[derive(Debug, Deserialize)]
pub struct MfaSetupRequest {
    pub mfa_type: MfaType,
    pub name: String,
    pub config: Option<Value>, // For SMS phone number, etc.
}

/// MFA verification request
#[derive(Debug, Deserialize)]
pub struct MfaVerificationRequest {
    pub method_id: String,
    pub code: String,
}

/// MFA challenge request
#[derive(Debug, Deserialize)]
pub struct MfaChallengeRequest {
    pub method_id: Option<String>, // If None, use primary method
}

/// MFA setup response
#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    pub method_id: String,
    pub mfa_type: MfaType,
    pub setup_data: Value,
    pub backup_codes: Option<Vec<String>>,
}

/// MFA challenge response
#[derive(Debug, Serialize)]
pub struct MfaChallengeResponse {
    pub challenge_id: String,
    pub mfa_type: MfaType,
    pub challenge_data: Value,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// MFA status response
#[derive(Debug, Serialize)]
pub struct MfaStatusResponse {
    pub mfa_enabled: bool,
    pub methods: Vec<MfaMethodInfo>,
    pub backup_codes_remaining: Option<u32>,
}

/// MFA method info
#[derive(Debug, Serialize)]
pub struct MfaMethodInfo {
    pub method_id: String,
    pub mfa_type: MfaType,
    pub name: String,
    pub is_primary: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
}

/// Get user's MFA status
pub async fn get_mfa_status(
    State(_app_state): State<AppState>,
    Extension(_user): Extension<User>,
) -> Result<Json<ApiResponse<MfaStatusResponse>>, AppError> {
    // TODO: Get MFA manager from app state once integrated
    // For now, return a mock response
    let response = MfaStatusResponse {
        mfa_enabled: false,
        methods: vec![],
        backup_codes_remaining: None,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Setup a new MFA method
pub async fn setup_mfa_method(
    State(_app_state): State<AppState>,
    Extension(user): Extension<User>,
    Json(request): Json<MfaSetupRequest>,
) -> Result<Json<ApiResponse<MfaSetupResponse>>, AppError> {
    // TODO: Get MFA manager from app state once integrated
    // For now, return a mock response based on MFA type
    let method_id = uuid::Uuid::new_v4().to_string();

    let (setup_data, backup_codes) = match request.mfa_type {
        MfaType::Totp => {
            let secret = "JBSWY3DPEHPK3PXP"; // Mock secret
            let qr_code = format!(
                "otpauth://totp/AuthService:{}?secret={}&issuer=AuthService",
                user.email, secret
            );
            (
                serde_json::json!({
                    "secret": secret,
                    "qr_code": qr_code,
                    "manual_entry_key": secret,
                }),
                Some(vec![
                    "12345678".to_string(),
                    "87654321".to_string(),
                    "11223344".to_string(),
                    "55667788".to_string(),
                    "99887766".to_string(),
                    "44332211".to_string(),
                    "66778899".to_string(),
                    "33445566".to_string(),
                ]),
            )
        }
        MfaType::Sms => {
            let phone_number = request
                .config
                .as_ref()
                .and_then(|c| c.get("phone_number"))
                .and_then(|p| p.as_str())
                .ok_or_else(|| AppError::Validation {
                    message: "Phone number required for SMS MFA".to_string(),
                })?;

            (
                serde_json::json!({
                    "phone_number": phone_number,
                    "message": "SMS MFA method configured. You will receive verification codes on this number.",
                }),
                None,
            )
        }
        MfaType::Email => (
            serde_json::json!({
                "email": user.email,
                "message": "Email MFA method configured. You will receive verification codes via email.",
            }),
            None,
        ),
        MfaType::BackupCodes => {
            let backup_codes = vec![
                "12345678".to_string(),
                "87654321".to_string(),
                "11223344".to_string(),
                "55667788".to_string(),
                "99887766".to_string(),
                "44332211".to_string(),
                "66778899".to_string(),
                "33445566".to_string(),
            ];
            (
                serde_json::json!({
                    "message": "Backup codes generated. Store these securely.",
                    "codes": backup_codes.clone(),
                }),
                Some(backup_codes),
            )
        }
        MfaType::WebAuthn => (
            serde_json::json!({
                "challenge": "mock_challenge_data",
                "options": {
                    "challenge": "mock_challenge",
                    "rp": {
                        "name": "AuthService",
                        "id": "localhost"
                    },
                    "user": {
                        "id": user.id,
                        "name": user.email,
                        "displayName": user.email
                    }
                }
            }),
            None,
        ),
        MfaType::Push => (
            serde_json::json!({
                "message": "Push notification MFA method configured.",
                "device_id": "mock_device_id",
            }),
            None,
        ),
    };

    let response = MfaSetupResponse {
        method_id,
        mfa_type: request.mfa_type,
        setup_data,
        backup_codes,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Verify MFA setup (complete setup process)
pub async fn verify_mfa_setup(
    State(_app_state): State<AppState>,
    Extension(_user): Extension<User>,
    Path(_method_id): Path<String>,
    Json(request): Json<MfaVerificationRequest>,
) -> Result<Json<ApiResponse<Value>>, AppError> {
    // TODO: Implement actual MFA verification
    // For now, accept any 6-digit code
    if request.code.len() == 6 && request.code.chars().all(|c| c.is_ascii_digit()) {
        Ok(Json(ApiResponse::success(serde_json::json!({
            "verified": true,
            "message": "MFA method successfully verified and enabled"
        }))))
    } else {
        Err(AppError::Unauthorized)
    }
}

/// Remove MFA method
pub async fn remove_mfa_method(
    State(_app_state): State<AppState>,
    Extension(_user): Extension<User>,
    Path(_method_id): Path<String>,
) -> Result<Json<ApiResponse<Value>>, AppError> {
    // TODO: Implement actual MFA method removal
    Ok(Json(ApiResponse::success(serde_json::json!({
        "removed": true,
        "message": "MFA method successfully removed"
    }))))
}

/// Create MFA challenge for authentication
pub async fn create_mfa_challenge(
    State(_app_state): State<AppState>,
    Extension(_user): Extension<User>,
    Json(_request): Json<MfaChallengeRequest>,
) -> Result<Json<ApiResponse<MfaChallengeResponse>>, AppError> {
    // TODO: Get actual MFA method and create real challenge
    let challenge_id = uuid::Uuid::new_v4().to_string();
    let mfa_type = MfaType::Totp; // Mock - should be determined from method_id

    let challenge_data = match mfa_type {
        MfaType::Totp => serde_json::json!({
            "message": "Enter the 6-digit code from your authenticator app"
        }),
        MfaType::Sms => serde_json::json!({
            "message": "A verification code has been sent to your phone",
            "phone_hint": "***-***-1234"
        }),
        MfaType::Email => serde_json::json!({
            "message": "A verification code has been sent to your email",
            "email_hint": "u***@example.com"
        }),
        MfaType::WebAuthn => serde_json::json!({
            "challenge": "mock_webauthn_challenge",
            "options": {
                "challenge": "challenge_data_here",
                "timeout": 60000,
                "rpId": "localhost"
            }
        }),
        _ => serde_json::json!({
            "message": "MFA challenge created"
        }),
    };

    let response = MfaChallengeResponse {
        challenge_id,
        mfa_type,
        challenge_data,
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Verify MFA challenge
pub async fn verify_mfa_challenge(
    State(_app_state): State<AppState>,
    Extension(_user): Extension<User>,
    Path(_challenge_id): Path<String>,
    Json(request): Json<MfaVerificationRequest>,
) -> Result<Json<ApiResponse<Value>>, AppError> {
    // TODO: Implement actual MFA challenge verification
    // For now, accept any 6-digit code
    if request.code.len() == 6 && request.code.chars().all(|c| c.is_ascii_digit()) {
        Ok(Json(ApiResponse::success(serde_json::json!({
            "verified": true,
            "message": "MFA challenge successfully verified",
            "mfa_token": "mfa_session_token_here" // Temporary token for completing auth
        }))))
    } else {
        Err(AppError::Unauthorized)
    }
}

/// List user's MFA methods
pub async fn list_mfa_methods(
    State(_app_state): State<AppState>,
    Extension(_user): Extension<User>,
) -> Result<Json<ApiResponse<Vec<MfaMethodInfo>>>, AppError> {
    // TODO: Get actual MFA methods from database
    let methods = vec![
        // Mock data
        MfaMethodInfo {
            method_id: "totp_1".to_string(),
            mfa_type: MfaType::Totp,
            name: "Google Authenticator".to_string(),
            is_primary: true,
            created_at: chrono::Utc::now() - chrono::Duration::days(30),
            last_used: Some(chrono::Utc::now() - chrono::Duration::hours(2)),
        },
    ];

    Ok(Json(ApiResponse::success(methods)))
}

/// Set primary MFA method
pub async fn set_primary_mfa_method(
    State(_app_state): State<AppState>,
    Extension(_user): Extension<User>,
    Path(_method_id): Path<String>,
) -> Result<Json<ApiResponse<Value>>, AppError> {
    // TODO: Implement setting primary MFA method
    Ok(Json(ApiResponse::success(serde_json::json!({
        "updated": true,
        "message": "Primary MFA method updated successfully"
    }))))
}

/// Generate new backup codes
pub async fn generate_backup_codes(
    State(_app_state): State<AppState>,
    Extension(_user): Extension<User>,
) -> Result<Json<ApiResponse<Value>>, AppError> {
    // TODO: Generate actual backup codes
    let backup_codes = vec![
        "12345678".to_string(),
        "87654321".to_string(),
        "11223344".to_string(),
        "55667788".to_string(),
        "99887766".to_string(),
        "44332211".to_string(),
        "66778899".to_string(),
        "33445566".to_string(),
    ];

    Ok(Json(ApiResponse::success(serde_json::json!({
        "backup_codes": backup_codes,
        "message": "New backup codes generated. Previous codes are now invalid."
    }))))
}

/// Disable MFA for user (requires current MFA verification)
pub async fn disable_mfa(
    State(_app_state): State<AppState>,
    Extension(_user): Extension<User>,
    Json(request): Json<MfaVerificationRequest>,
) -> Result<Json<ApiResponse<Value>>, AppError> {
    // TODO: Verify MFA code before disabling
    if request.code.len() == 6 && request.code.chars().all(|c| c.is_ascii_digit()) {
        Ok(Json(ApiResponse::success(serde_json::json!({
            "disabled": true,
            "message": "MFA has been disabled for your account"
        }))))
    } else {
        Err(AppError::Unauthorized)
    }
}
