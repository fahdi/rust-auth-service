use axum::{extract::State, http::StatusCode, response::Json, Extension};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use validator::Validate;

use crate::{
    errors::{AppError, AppResult},
    models::user::{
        AuthResponse, CreateUserRequest, EmailVerificationRequest, PasswordChangeRequest,
        PasswordResetRequest, UpdateUserRequest, User, UserResponse,
    },
    utils::{
        jwt::{generate_token, verify_token, JwtClaims},
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
    payload.validate()?;

    // Additional password strength validation
    if let Err(e) = validate_password_strength(&payload.password) {
        return Err(AppError::Validation { message: e });
    }

    // Check if user already exists
    match state.database.find_user_by_email(&payload.email).await {
        Ok(Some(_)) => {
            warn!(
                "Registration attempt with existing email: {}",
                payload.email
            );
            return Err(AppError::Conflict);
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
    let password_hash = hash_password(&payload.password).map_err(|e| {
        error!("Password hashing failed: {:?}", e);
        AppError::Internal
    })?;

    // Create user
    let mut user = User::new(payload, password_hash);

    // Generate email verification token
    let verification_token = Uuid::new_v4().to_string();
    user.set_email_verification_token(verification_token.clone(), 24);

    // Save user to database
    match state.database.create_user(user).await {
        Ok(created_user) => {
            info!("User registered successfully: {}", created_user.email);

            // TODO: Send verification email
            // state.email_service.send_verification_email(&created_user, &verification_token).await;

            // Generate JWT token
            let access_token = generate_token(
                &created_user.user_id,
                &created_user.email,
                &created_user.role.to_string(),
                (state.config.auth.jwt.expiration_days * 24) as i64,
                &state.config.auth.jwt.secret,
            )
            .map_err(|e| {
                error!("JWT token creation failed: {:?}", e);
                AppError::Internal
            })?;

            let refresh_token = generate_token(
                &created_user.user_id,
                &created_user.email,
                &created_user.role.to_string(),
                (state.config.auth.jwt.expiration_days * 24 * 7) as i64, // 7x longer
                &state.config.auth.jwt.secret,
            )
            .map_err(|e| {
                error!("Refresh token creation failed: {:?}", e);
                AppError::Internal
            })?;

            Ok(Json(AuthResponse {
                user: created_user.to_response(),
                access_token,
                refresh_token,
                expires_in: (state.config.auth.jwt.expiration_days * 24 * 3600) as i64,
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
    payload.validate()?;

    // Get user by email
    let mut user = match state.database.find_user_by_email(&payload.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!("Login attempt with non-existent email: {}", payload.email);
            return Err(AppError::Unauthorized);
        }
        Err(e) => {
            error!("Database error during login: {:?}", e);
            return Err(AppError::Database(e.to_string()));
        }
    };

    // Check if account is locked
    if user.is_locked() {
        warn!("Login attempt on locked account: {}", user.email);
        return Err(AppError::Locked);
    }

    // Check if account is active
    if !user.is_active {
        warn!("Login attempt on inactive account: {}", user.email);
        return Err(AppError::Unauthorized);
    }

    // Verify password
    let password_valid = verify_password(&payload.password, &user.password_hash).map_err(|e| {
        error!("Password verification error: {:?}", e);
        AppError::Internal
    })?;

    if !password_valid {
        // Record failed login attempt
        user.record_failed_login(5, 24); // TODO: make configurable

        if let Err(e) = state.database.update_user(&user).await {
            error!("Failed to update user after failed login: {:?}", e);
        }

        warn!("Invalid password for user: {}", user.email);
        return Err(AppError::Unauthorized);
    }

    // Check if email is verified (if required)
    if state.config.auth.verification.required && !user.email_verified {
        warn!("Login attempt with unverified email: {}", user.email);
        return Err(AppError::Unauthorized);
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
        (state.config.auth.jwt.expiration_days * 24) as i64,
        &state.config.auth.jwt.secret,
    )
    .map_err(|e| {
        error!("Failed to generate access token: {:?}", e);
        AppError::Internal
    })?;

    let refresh_token = generate_token(
        &user.user_id,
        &user.email,
        &user.role.to_string(),
        (state.config.auth.jwt.expiration_days * 24 * 7) as i64,
        &state.config.auth.jwt.secret,
    )
    .map_err(|e| {
        error!("Failed to generate refresh token: {:?}", e);
        AppError::Internal
    })?;

    info!("User logged in successfully: {}", user.email);

    Ok(Json(AuthResponse {
        user: user.to_response(),
        access_token,
        refresh_token,
        expires_in: (state.config.auth.jwt.expiration_days * 24 * 3600) as i64,
    }))
}

// Email verification endpoint
pub async fn verify_email(
    State(state): State<AppState>,
    Json(payload): Json<EmailVerificationRequest>,
) -> Result<Json<Value>, StatusCode> {
    // Validate input
    if let Err(validation_errors) = payload.validate() {
        error!(
            "Email verification validation failed: {:?}",
            validation_errors
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Find user by verification token
    match state
        .database
        .get_user_by_verification_token(&payload.token)
        .await
    {
        Ok(Some(user)) => {
            // Check if token is still valid (not expired)
            if let Some(expires) = user.email_verification_expires {
                let now = chrono::Utc::now();
                if now > expires {
                    warn!("Email verification token expired for user: {}", user.email);
                    return Err(StatusCode::BAD_REQUEST);
                }
            }

            // Verify the user's email
            if let Err(e) = state.database.verify_user_email(&user.user_id).await {
                error!("Failed to verify user email: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }

            info!("Email verified successfully for user: {}", user.email);
            Ok(Json(json!({
                "message": "Email verified successfully",
                "user": {
                    "user_id": user.user_id,
                    "email": user.email,
                    "email_verified": true
                }
            })))
        }
        Ok(None) => {
            warn!("Invalid verification token provided");
            Err(StatusCode::BAD_REQUEST)
        }
        Err(e) => {
            error!("Database error during email verification: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
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
    let mut user = match state.database.find_user_by_email(&payload.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            // Don't reveal whether email exists or not
            info!(
                "Password reset requested for non-existent email: {}",
                payload.email
            );
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

    // Find user by reset token
    match state.database.get_user_by_reset_token(&payload.token).await {
        Ok(Some(user)) => {
            // Check if token is still valid (not expired)
            if let Some(expires) = user.password_reset_expires {
                let now = chrono::Utc::now();
                if now > expires {
                    warn!("Password reset token expired for user: {}", user.email);
                    return Err(StatusCode::BAD_REQUEST);
                }
            }

            // Hash the new password
            let password_hash = match hash_password(&payload.new_password) {
                Ok(hash) => hash,
                Err(e) => {
                    error!("Failed to hash password: {}", e);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            };

            // Update user password
            if let Err(e) = state
                .database
                .update_password(&user.user_id, &password_hash)
                .await
            {
                error!("Failed to update user password: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }

            // Clear the password reset token
            if let Err(e) = state
                .database
                .clear_password_reset_token(&user.user_id)
                .await
            {
                error!("Failed to clear password reset token: {}", e);
                // Don't return error here since password was already updated
                warn!("Password reset token could not be cleared: {}", e);
            }

            info!("Password reset successfully for user: {}", user.email);
            Ok(Json(json!({
                "message": "Password reset successful",
                "status": "success"
            })))
        }
        Ok(None) => {
            warn!("Invalid password reset token provided");
            Err(StatusCode::BAD_REQUEST)
        }
        Err(e) => {
            error!("Database error during password reset: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Refresh token endpoint
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // Validate refresh token
    let claims = match verify_token(&payload.refresh_token, &state.config.auth.jwt.secret) {
        Ok(claims) => claims,
        Err(e) => {
            warn!("Invalid refresh token: {:?}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Get user by user_id from token
    let user = match state.database.find_user_by_id(&claims.sub).await {
        Ok(Some(user)) => user,
        Ok(None) => {
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
    let access_token = match generate_token(
        &user.user_id,
        &user.email,
        &user.role.to_string(),
        (state.config.auth.jwt.expiration_days * 24) as i64,
        &state.config.auth.jwt.secret,
    ) {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to generate new access token: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let new_refresh_token = match generate_token(
        &user.user_id,
        &user.email,
        &user.role.to_string(),
        (state.config.auth.jwt.expiration_days * 24 * 7) as i64,
        &state.config.auth.jwt.secret,
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
        expires_in: (state.config.auth.jwt.expiration_days * 24 * 3600) as i64,
    }))
}

// Get current user profile
pub async fn get_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<UserResponse>, StatusCode> {
    let cache_key = format!("user_profile:{}", claims.sub);

    // Try to get user profile from cache first
    if let Ok(Some(cached_profile)) = state.cache.get(&cache_key).await {
        if let Ok(user_response) = serde_json::from_str::<UserResponse>(&cached_profile) {
            debug!("User profile cache hit for user: {}", claims.sub);
            return Ok(Json(user_response));
        }
    }

    debug!("User profile cache miss for user: {}", claims.sub);

    // Get user by ID from database
    let user = match state.database.find_user_by_id(&claims.sub).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!("Profile request for non-existent user: {}", claims.sub);
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            error!("Database error during profile fetch: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let user_response = user.to_response();

    // Cache the user profile for 5 minutes
    if let Ok(serialized) = serde_json::to_string(&user_response) {
        if let Err(e) = state
            .cache
            .set_with_ttl(&cache_key, &serialized, std::time::Duration::from_secs(300))
            .await
        {
            warn!("Failed to cache user profile: {}", e);
        } else {
            debug!("Cached user profile for user: {}", claims.sub);
        }
    }

    Ok(Json(user_response))
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
    let mut user = match state.database.find_user_by_id(&claims.sub).await {
        Ok(Some(user)) => user,
        Ok(None) => {
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
            match state.database.find_user_by_email(new_email).await {
                Ok(Some(_)) => {
                    warn!("Profile update with existing email: {}", new_email);
                    return Err(StatusCode::CONFLICT);
                }
                Ok(None) => {
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

            // Invalidate cache after successful update
            let cache_key = format!("user_profile:{}", claims.sub);
            if let Err(e) = state.cache.delete(&cache_key).await {
                warn!("Failed to invalidate user profile cache: {}", e);
            } else {
                debug!("Invalidated cache for user profile: {}", claims.sub);
            }

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
    State(state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<Value>, StatusCode> {
    // Add token to blacklist cache until it expires
    let blacklist_key = format!("blacklist:token:{}", claims.jti);
    let ttl = std::time::Duration::from_secs(
        (claims.exp as u64).saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ),
    );

    if let Err(e) = state
        .cache
        .set_with_ttl(&blacklist_key, "blacklisted", ttl)
        .await
    {
        warn!("Failed to blacklist token: {}", e);
    } else {
        debug!("Token blacklisted for user: {}", claims.sub);
    }

    // Invalidate user profile cache on logout
    let cache_key = format!("user_profile:{}", claims.sub);
    if let Err(e) = state.cache.delete(&cache_key).await {
        warn!("Failed to invalidate user profile cache on logout: {}", e);
    }

    info!("User logged out: {}", claims.sub);

    Ok(Json(json!({
        "message": "Logged out successfully"
    })))
}
