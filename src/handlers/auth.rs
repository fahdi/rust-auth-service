use axum::{
    extract::State,
    response::Json,
    Extension,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{error, info, warn, debug};
use validator::Validate;
use uuid::Uuid;
use chrono::{Utc, Duration};

use crate::{
    errors::{AppError, AppResult},
    models::user::{
        AuthResponse, CreateUserRequest, EmailVerificationRequest,
        PasswordChangeRequest, PasswordResetRequest, UpdateUserRequest,
        User, UserError, UserResponse, UserRole, UserMetadata,
    },
    utils::{
        jwt::{JwtClaims, generate_token, verify_token},
        password::{hash_password, verify_password},
        validation::validate_password_strength,
    },
    AppState,
};

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

// Registration endpoint
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> AppResult<Json<AuthResponse>> {
    debug!("Registration attempt for email: {}", payload.email);
    
    // Validate input
    payload.validate()
        .map_err(|e| AppError::Validation(format!("Validation error: {:?}", e)))?;

    // Additional password strength validation
    if let Err(e) = validate_password_strength(&payload.password) {
        return Err(AppError::Validation(e));
    }

    // Check if user already exists
    match state.database.find_user_by_email(&payload.email).await {
        Ok(Some(_)) => {
            warn!("Registration attempt with existing email: {}", payload.email);
            return Err(AppError::Conflict("User already exists".to_string()));
        }
        Ok(None) => {
            debug!("Email {} is available for registration", payload.email);
        }
        Err(e) => {
            error!("Database error during registration check: {:?}", e);
            return Err(AppError::Database(e.to_string()));
        }
    }

    // Hash password
    let password_hash = hash_password(&payload.password)
        .map_err(|e| {
            error!("Password hashing failed: {:?}", e);
            AppError::Internal
        })?;

    // Create user
    let mut user = User::new(payload, password_hash);
    
    // Generate email verification token
    let verification_token = Uuid::new_v4().to_string();
    user.set_email_verification_token(verification_token.clone(), 24);

    // Save user to database
    match state.database.create_user(&user).await {
        Ok(created_user) => {
            info!("User registered successfully: {}", created_user.email);
            
            // TODO: Send verification email
            // state.email_service.send_verification_email(&created_user, &verification_token).await;
            
            // Generate JWT token
            let access_token = generate_token(
                &created_user.user_id,
                &created_user.email,
                &created_user.role.to_string(),
                state.config.auth.access_token_expiry_hours,
                &state.config.auth.jwt_secret,
            ).map_err(|e| {
                error!("JWT token creation failed: {:?}", e);
                AppError::Internal
            })?;

            let refresh_token = generate_token(
                &created_user.user_id,
                &created_user.email,
                &created_user.role.to_string(),
                state.config.auth.refresh_token_expiry_hours,
                &state.config.auth.jwt_secret,
            ).map_err(|e| {
                error!("Refresh token creation failed: {:?}", e);
                AppError::Internal
            })?;
            
            Ok(Json(AuthResponse {
                user: created_user.to_response(),
                access_token,
                refresh_token,
                expires_in: state.config.auth.access_token_expiry_hours * 3600,
            }))
        }
        Err(e) => {
            error!("Failed to create user: {:?}", e);
            Err(AppError::Database(e.to_string()))
        }
    }
}

// Login endpoint
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<AuthResponse>> {
    debug!("Login attempt for email: {}", payload.email);
    
    // Validate input
    payload.validate()
        .map_err(|e| AppError::Validation(format!("Validation error: {:?}", e)))?;

    // Get user by email
    let mut user = match state.database.find_user_by_email(&payload.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!("Login attempt with non-existent email: {}", payload.email);
            return Err(AppError::Unauthorized("Invalid email or password".to_string()));
        }
        Err(e) => {
            error!("Database error during login: {:?}", e);
            return Err(AppError::Database(e.to_string()));
        }
    };

    // Check if account is locked
    if user.is_locked() {
        warn!("Login attempt on locked account: {}", user.email);
        return Err(AppError::Unauthorized("Account is temporarily locked".to_string()));
    }

    // Check if account is active
    if !user.is_active {
        warn!("Login attempt on inactive account: {}", user.email);
        return Err(AppError::Unauthorized("Account is disabled".to_string()));
    }

    // Verify password
    let password_valid = verify_password(&payload.password, &user.password_hash)
        .map_err(|e| {
            error!("Password verification error: {:?}", e);
            AppError::Internal
        })?;

    if !password_valid {
        // Record failed login attempt
        user.record_failed_login(state.config.auth.max_login_attempts, state.config.auth.lockout_duration_hours);
        
        if let Err(e) = state.database.update_user(&user).await {
            error!("Failed to update user after failed login: {:?}", e);
        }
        
        warn!("Invalid password for user: {}", user.email);
        return Err(AppError::Unauthorized("Invalid email or password".to_string()));
    }

    // Check if email is verified (if required)
    if state.config.auth.require_email_verification && !user.email_verified {
        warn!("Login attempt with unverified email: {}", user.email);
        return Err(AppError::Unauthorized("Email verification required".to_string()));
    }

    // Record successful login
    user.record_login();
    
    if let Err(e) = state.database.update_user(&user).await {
        error!("Failed to update user after successful login: {:?}", e);
        // Don't fail the login for this
    }

    // Generate JWT tokens
    let access_token = generate_token(
        &user.user_id,
        &user.email,
        &user.role.to_string(),
        state.config.auth.access_token_expiry_hours,
        &state.config.auth.jwt_secret,
    ).map_err(|e| {
        error!("Failed to generate access token: {:?}", e);
        AppError::Internal
    })?;

    let refresh_token = generate_token(
        &user.user_id,
        &user.email,
        &user.role.to_string(),
        state.config.auth.refresh_token_expiry_hours,
        &state.config.auth.jwt_secret,
    ).map_err(|e| {
        error!("Failed to generate refresh token: {:?}", e);
        AppError::Internal
    })?;

    info!("User logged in successfully: {}", user.email);

    Ok(Json(AuthResponse {
        user: user.to_response(),
        access_token,
        refresh_token,
        expires_in: state.config.auth.access_token_expiry_hours * 3600,
    }))
}

// Email verification endpoint
pub async fn verify_email(
    State(state): State<AppState>,
    Json(payload): Json<EmailVerificationRequest>,
) -> Result<Json<Value>, StatusCode> {
    // Find user by verification token (this would need a database method)
    // For now, we'll need to add this method to the database trait
    // TODO: Implement get_user_by_verification_token in database trait
    
    Ok(Json(json!({
        "message": "Email verification endpoint - implementation pending database method"
    })))
}

// Password reset request endpoint
pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<PasswordResetRequest>,
) -> Result<Json<Value>, StatusCode> {
    // Validate input
    if let Err(validation_errors) = payload.validate() {
        error!("Password reset validation failed: {:?}", validation_errors);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Get user by email
    let mut user = match state.database.get_user_by_email(&payload.email).await {
        Ok(user) => user,
        Err(UserError::NotFound) => {
            // Don't reveal whether email exists or not
            info!("Password reset requested for non-existent email: {}", payload.email);
            return Ok(Json(json!({
                "message": "If the email exists, a password reset link has been sent"
            })));
        }
        Err(e) => {
            error!("Database error during password reset: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Generate password reset token
    let reset_token = uuid::Uuid::new_v4().to_string();
    user.set_password_reset_token(reset_token.clone(), 2); // 2 hours validity

    // Update user in database
    if let Err(e) = state.database.update_user(&user).await {
        error!("Failed to update user with reset token: {:?}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // TODO: Send password reset email
    // state.email_service.send_password_reset_email(&user, &reset_token).await;

    info!("Password reset requested for: {}", user.email);

    Ok(Json(json!({
        "message": "If the email exists, a password reset link has been sent"
    })))
}

// Password reset endpoint
pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<PasswordChangeRequest>,
) -> Result<Json<Value>, StatusCode> {
    // Validate input
    if let Err(validation_errors) = payload.validate() {
        error!("Password change validation failed: {:?}", validation_errors);
        return Err(StatusCode::BAD_REQUEST);
    }

    // TODO: Find user by reset token (need database method)
    // For now, we'll need to add this method to the database trait
    
    Ok(Json(json!({
        "message": "Password reset endpoint - implementation pending database method"
    })))
}

// Refresh token endpoint
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // Validate refresh token
    let claims = match crate::utils::jwt::verify_token(&payload.refresh_token, &state.config.auth.jwt_secret) {
        Ok(claims) => claims,
        Err(e) => {
            warn!("Invalid refresh token: {:?}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Get user by user_id from token
    let user = match state.database.get_user_by_id(&claims.sub).await {
        Ok(user) => user,
        Err(UserError::NotFound) => {
            warn!("Refresh token for non-existent user: {}", claims.sub);
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            error!("Database error during token refresh: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Check if user is still active
    if !user.is_active {
        warn!("Token refresh for inactive user: {}", user.email);
        return Err(StatusCode::FORBIDDEN);
    }

    // Generate new tokens
    let access_token = match crate::utils::jwt::generate_token(
        &user.user_id,
        &user.email,
        &user.role.to_string(),
        state.config.auth.access_token_expiry_hours,
        &state.config.auth.jwt_secret,
    ) {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to generate new access token: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let new_refresh_token = match crate::utils::jwt::generate_token(
        &user.user_id,
        &user.email,
        &user.role.to_string(),
        state.config.auth.refresh_token_expiry_hours,
        &state.config.auth.jwt_secret,
    ) {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to generate new refresh token: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    info!("Token refreshed for user: {}", user.email);

    Ok(Json(AuthResponse {
        user: user.to_response(),
        access_token,
        refresh_token: new_refresh_token,
        expires_in: state.config.auth.access_token_expiry_hours * 3600,
    }))
}

// Get current user profile
pub async fn get_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<UserResponse>, StatusCode> {
    // Get user by ID from JWT claims
    let user = match state.database.get_user_by_id(&claims.sub).await {
        Ok(user) => user,
        Err(UserError::NotFound) => {
            warn!("Profile request for non-existent user: {}", claims.sub);
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            error!("Database error during profile fetch: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Ok(Json(user.to_response()))
}

// Update user profile
pub async fn update_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    // Validate input
    if let Err(validation_errors) = payload.validate() {
        error!("Profile update validation failed: {:?}", validation_errors);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Get current user
    let mut user = match state.database.get_user_by_id(&claims.sub).await {
        Ok(user) => user,
        Err(UserError::NotFound) => {
            warn!("Profile update for non-existent user: {}", claims.sub);
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            error!("Database error during profile update: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Check if email is being changed and if it already exists
    if let Some(ref new_email) = payload.email {
        if new_email != &user.email {
            match state.database.get_user_by_email(new_email).await {
                Ok(_) => {
                    warn!("Profile update with existing email: {}", new_email);
                    return Err(StatusCode::CONFLICT);
                }
                Err(UserError::NotFound) => {
                    // Good, email is available
                }
                Err(e) => {
                    error!("Database error checking email availability: {:?}", e);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }
    }

    // Update user
    user.update(payload);

    // Save to database
    match state.database.update_user(&user).await {
        Ok(updated_user) => {
            info!("Profile updated for user: {}", updated_user.email);
            Ok(Json(updated_user.to_response()))
        }
        Err(e) => {
            error!("Failed to update user profile: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Logout endpoint
pub async fn logout(
    State(_state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<Value>, StatusCode> {
    // TODO: Add token to blacklist
    // For now, just log the logout
    info!("User logged out: {}", claims.sub);

    Ok(Json(json!({
        "message": "Logged out successfully"
    })))
}