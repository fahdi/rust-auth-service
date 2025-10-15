use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use tracing::{error, warn};

use crate::AppState;

/// JWT authentication middleware
/// Extracts and validates JWT token from Authorization header
/// and adds claims to request extensions
pub async fn jwt_auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let auth_header = match auth_header {
        Some(header) => header,
        None => {
            warn!("Missing Authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Check if it starts with "Bearer "
    if !auth_header.starts_with("Bearer ") {
        warn!("Invalid Authorization header format");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extract token
    let token = auth_header.trim_start_matches("Bearer ");

    // Verify token
    let claims = match crate::utils::jwt::verify_token(token, &state.config.auth.jwt.secret) {
        Ok(claims) => claims,
        Err(e) => {
            warn!("Invalid JWT token: {:?}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // TODO: Check if token is blacklisted
    // if state.cache.is_token_blacklisted(token).await? {
    //     return Err(StatusCode::UNAUTHORIZED);
    // }

    // Verify user still exists and is active
    match state.database.find_user_by_id(&claims.sub).await {
        Ok(Some(user)) => {
            if !user.is_active {
                warn!("Token for inactive user: {}", user.email);
                return Err(StatusCode::FORBIDDEN);
            }
        }
        Ok(None) => {
            warn!("Token for non-existent user: {}", claims.sub);
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            error!("Database error during token validation: {:?}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Add claims to request extensions
    request.extensions_mut().insert(claims);

    // Continue to next middleware/handler
    Ok(next.run(request).await)
}

/// Optional JWT authentication middleware
/// Similar to jwt_auth_middleware but doesn't return error if no token is provided
/// Useful for endpoints that work with or without authentication
#[allow(dead_code)]
pub async fn optional_jwt_auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract Authorization header
    if let Some(auth_header) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
    {
        // Check if it starts with "Bearer "
        if auth_header.starts_with("Bearer ") {
            // Extract token
            let token = auth_header.trim_start_matches("Bearer ");

            // Verify token
            if let Ok(claims) = crate::utils::jwt::verify_token(token, &state.config.auth.jwt.secret) {
                // Verify user still exists and is active
                if let Ok(Some(user)) = state.database.find_user_by_id(&claims.sub).await {
                    if user.is_active {
                        // Add claims to request extensions
                        request.extensions_mut().insert(claims);
                    }
                }
            }
        }
    }

    // Continue to next middleware/handler regardless of authentication status
    next.run(request).await
}