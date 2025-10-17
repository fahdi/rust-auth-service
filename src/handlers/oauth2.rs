use axum::{
    extract::{Form, Query, State},
    http::StatusCode,
    response::{Html, Json, Redirect},
    Extension,
};
use serde::Deserialize;
use std::collections::HashMap;

use crate::{
    oauth2::{
        client::OAuth2ClientManager,
        client::{
            ClientQuery, ClientRegistrationRequest, ClientRegistrationResponse, ClientUpdateRequest,
        },
        AuthorizeRequest, DeviceAuthorizationRequest, DeviceAuthorizationResponse, OAuth2Error,
        OAuth2ErrorResponse, OAuth2Metadata, TokenRequest, TokenResponse,
    },
    utils::response::{ApiError, ApiResponse},
    AppState,
};

/// OAuth2 authorization endpoint
pub async fn authorize(
    State(app_state): State<AppState>,
    Query(params): Query<AuthorizeRequest>,
    Extension(user_id): Extension<Option<String>>,
) -> Result<Redirect, ApiError> {
    let oauth2_server = &app_state.oauth2_server;
    // Check if user is authenticated
    let user_id = user_id.ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "User must be authenticated for authorization".to_string(),
        )
    })?;

    // Handle authorization request
    let redirect_url = oauth2_server
        .handle_authorization_request(
            &params.response_type,
            &params.client_id,
            params.redirect_uri.as_deref(),
            params.scope.as_deref(),
            params.state.as_deref(),
            params.code_challenge.as_deref(),
            params.code_challenge_method.as_deref(),
            params.nonce.as_deref(),
            &user_id,
        )
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Redirect::to(&redirect_url))
}

/// OAuth2 authorization consent page
pub async fn authorize_consent(
    State(app_state): State<AppState>,
    Query(params): Query<AuthorizeRequest>,
    Extension(user_id): Extension<Option<String>>,
) -> Result<Html<String>, ApiError> {
    let oauth2_server = &app_state.oauth2_server;
    // Check if user is authenticated
    let _user_id = user_id.ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "User must be authenticated".to_string(),
        )
    })?;

    // Get client information
    let client = oauth2_server
        .get_client(&params.client_id)
        .await
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Invalid client_id".to_string()))?;

    // Parse requested scopes
    let requested_scopes = params.scope.as_deref().unwrap_or("read");
    let scopes: Vec<&str> = requested_scopes.split_whitespace().collect();

    // Generate consent page HTML
    let html = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorization Request</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                h1 {{ color: #333; margin-bottom: 20px; }}
                .app-info {{ background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }}
                .scopes {{ margin: 20px 0; }}
                .scope {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
                .buttons {{ margin-top: 30px; text-align: center; }}
                button {{ padding: 12px 24px; margin: 0 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
                .approve {{ background: #007bff; color: white; }}
                .deny {{ background: #6c757d; color: white; }}
                button:hover {{ opacity: 0.8; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Authorization Request</h1>
                <div class="app-info">
                    <h3>{}</h3>
                    <p>{}</p>
                </div>
                <p>This application is requesting access to your account with the following permissions:</p>
                <div class="scopes">
                    {}
                </div>
                <div class="buttons">
                    <form method="post" action="/oauth2/authorize" style="display: inline;">
                        <input type="hidden" name="response_type" value="{}">
                        <input type="hidden" name="client_id" value="{}">
                        <input type="hidden" name="redirect_uri" value="{}">
                        <input type="hidden" name="scope" value="{}">
                        <input type="hidden" name="state" value="{}">
                        <input type="hidden" name="code_challenge" value="{}">
                        <input type="hidden" name="code_challenge_method" value="{}">
                        <input type="hidden" name="nonce" value="{}">
                        <input type="hidden" name="action" value="approve">
                        <button type="submit" class="approve">Approve</button>
                    </form>
                    <form method="post" action="/oauth2/authorize" style="display: inline;">
                        <input type="hidden" name="action" value="deny">
                        <input type="hidden" name="state" value="{}">
                        <input type="hidden" name="redirect_uri" value="{}">
                        <button type="submit" class="deny">Deny</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
        "#,
        client.name,
        client.description.as_deref().unwrap_or(""),
        scopes
            .iter()
            .map(|scope| format!("<div class=\"scope\">{}</div>", describe_scope(scope)))
            .collect::<Vec<_>>()
            .join(""),
        params.response_type,
        params.client_id,
        params.redirect_uri.as_deref().unwrap_or(""),
        params.scope.as_deref().unwrap_or(""),
        params.state.as_deref().unwrap_or(""),
        params.code_challenge.as_deref().unwrap_or(""),
        params.code_challenge_method.as_deref().unwrap_or(""),
        params.nonce.as_deref().unwrap_or(""),
        params.state.as_deref().unwrap_or(""),
        params.redirect_uri.as_deref().unwrap_or(""),
    );

    Ok(Html(html))
}

/// Handle authorization consent form submission
#[derive(Deserialize)]
pub struct ConsentForm {
    pub action: String,
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

pub async fn authorize_consent_post(
    State(app_state): State<AppState>,
    Extension(user_id): Extension<Option<String>>,
    Form(form): Form<ConsentForm>,
) -> Result<Redirect, ApiError> {
    let oauth2_server = &app_state.oauth2_server;
    let user_id = user_id.ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "User must be authenticated".to_string(),
        )
    })?;

    if form.action == "deny" {
        // User denied authorization
        let redirect_uri = form.redirect_uri.as_deref().unwrap_or("");
        let mut error_url = format!(
            "{}?error=access_denied&error_description=User%20denied%20access",
            redirect_uri
        );
        if let Some(state) = &form.state {
            error_url.push_str(&format!("&state={}", urlencoding::encode(state)));
        }
        return Ok(Redirect::to(&error_url));
    }

    // User approved authorization
    let redirect_url = oauth2_server
        .handle_authorization_request(
            &form.response_type.as_deref().unwrap_or("code"),
            &form.client_id.as_deref().unwrap_or(""),
            form.redirect_uri.as_deref(),
            form.scope.as_deref(),
            form.state.as_deref(),
            form.code_challenge.as_deref(),
            form.code_challenge_method.as_deref(),
            form.nonce.as_deref(),
            &user_id,
        )
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Redirect::to(&redirect_url))
}

/// OAuth2 token endpoint
pub async fn token(
    State(app_state): State<AppState>,
    Form(params): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, Json<OAuth2ErrorResponse>> {
    let oauth2_server = &app_state.oauth2_server;
    match oauth2_server.handle_token_request(&params).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            let error_response = OAuth2ErrorResponse {
                error: OAuth2Error::InvalidRequest,
                error_description: Some(e.to_string()),
                error_uri: None,
                state: None,
            };
            Err(Json(error_response))
        }
    }
}

/// OAuth2 device authorization endpoint
pub async fn device_authorization(
    State(app_state): State<AppState>,
    Form(params): Form<DeviceAuthorizationRequest>,
) -> Result<Json<DeviceAuthorizationResponse>, Json<OAuth2ErrorResponse>> {
    let oauth2_server = &app_state.oauth2_server;
    match oauth2_server
        .handle_device_authorization(&params.client_id, params.scope.as_deref())
        .await
    {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            let error_response = OAuth2ErrorResponse {
                error: OAuth2Error::InvalidRequest,
                error_description: Some(e.to_string()),
                error_uri: None,
                state: None,
            };
            Err(Json(error_response))
        }
    }
}

/// Device verification page
pub async fn device_verify(
    State(app_state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Html<String>, ApiError> {
    let _oauth2_server = &app_state.oauth2_server;
    let user_code = params.get("user_code").cloned().unwrap_or_default();

    let html = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Device Verification</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                h1 {{ color: #333; margin-bottom: 20px; text-align: center; }}
                .code-input {{ width: 100%; padding: 15px; font-size: 18px; text-align: center; margin: 20px 0; border: 2px solid #ddd; border-radius: 4px; text-transform: uppercase; letter-spacing: 2px; }}
                button {{ width: 100%; padding: 15px; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }}
                button:hover {{ background: #0056b3; }}
                .help {{ color: #666; font-size: 14px; text-align: center; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Device Verification</h1>
                <p>Enter the code displayed on your device:</p>
                <form method="post" action="/oauth2/device/verify">
                    <input type="text" name="user_code" class="code-input" placeholder="XXXX-XXXX" value="{}" required maxlength="9">
                    <button type="submit">Verify</button>
                </form>
                <div class="help">
                    Enter the 8-character code shown on your device.
                </div>
            </div>
        </body>
        </html>
        "#,
        user_code
    );

    Ok(Html(html))
}

/// Handle device verification
#[derive(Deserialize)]
pub struct DeviceVerifyForm {
    pub user_code: String,
}

pub async fn device_verify_post(
    State(app_state): State<AppState>,
    Extension(user_id): Extension<Option<String>>,
    Form(form): Form<DeviceVerifyForm>,
) -> Result<Html<String>, ApiError> {
    let oauth2_server = &app_state.oauth2_server;
    let user_id = user_id.ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "User must be authenticated".to_string(),
        )
    })?;

    let success = oauth2_server
        .authorize_device_code(&form.user_code, &user_id)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e.to_string()))?;

    let html = if success {
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Device Authorized</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
                .success { color: #28a745; font-size: 48px; margin-bottom: 20px; }
                h1 { color: #333; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="success">✓</div>
                <h1>Device Authorized</h1>
                <p>Your device has been successfully authorized. You can now close this window.</p>
            </div>
        </body>
        </html>
        "#
    } else {
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorization Failed</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
                .error { color: #dc3545; font-size: 48px; margin-bottom: 20px; }
                h1 { color: #333; }
                a { color: #007bff; text-decoration: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error">✗</div>
                <h1>Authorization Failed</h1>
                <p>Invalid or expired device code. Please try again.</p>
                <a href="/oauth2/device">← Try Again</a>
            </div>
        </body>
        </html>
        "#
    };

    Ok(Html(html.to_string()))
}

/// OAuth2 token introspection endpoint (RFC 7662)
pub async fn introspect(
    State(app_state): State<AppState>,
    Form(params): Form<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, Json<OAuth2ErrorResponse>> {
    let oauth2_server = &app_state.oauth2_server;
    let token = params.get("token").ok_or_else(|| {
        Json(OAuth2ErrorResponse {
            error: OAuth2Error::InvalidRequest,
            error_description: Some("Missing token parameter".to_string()),
            error_uri: None,
            state: None,
        })
    })?;

    match oauth2_server.introspect_token(token).await {
        Ok(introspection) => Ok(Json(serde_json::to_value(introspection).unwrap())),
        Err(e) => Err(Json(OAuth2ErrorResponse {
            error: OAuth2Error::InvalidRequest,
            error_description: Some(e.to_string()),
            error_uri: None,
            state: None,
        })),
    }
}

/// OAuth2 token revocation endpoint (RFC 7009)
pub async fn revoke(
    State(app_state): State<AppState>,
    Form(params): Form<HashMap<String, String>>,
) -> Result<StatusCode, Json<OAuth2ErrorResponse>> {
    let oauth2_server = &app_state.oauth2_server;
    let token = params.get("token").ok_or_else(|| {
        Json(OAuth2ErrorResponse {
            error: OAuth2Error::InvalidRequest,
            error_description: Some("Missing token parameter".to_string()),
            error_uri: None,
            state: None,
        })
    })?;

    match oauth2_server.revoke_token(token).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => Err(Json(OAuth2ErrorResponse {
            error: OAuth2Error::InvalidRequest,
            error_description: Some(e.to_string()),
            error_uri: None,
            state: None,
        })),
    }
}

/// OAuth2 metadata endpoint (RFC 8414)
pub async fn metadata(State(app_state): State<AppState>) -> Json<OAuth2Metadata> {
    let oauth2_server = &app_state.oauth2_server;
    Json(oauth2_server.get_metadata())
}

/// JWKS endpoint for public keys
pub async fn jwks(State(app_state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let oauth2_server = &app_state.oauth2_server;
    let jwks = oauth2_server
        .get_jwks()
        .await
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(jwks))
}

// Client management endpoints

/// Register a new OAuth2 client
pub async fn register_client(
    State(client_manager): State<OAuth2ClientManager<impl crate::oauth2::OAuth2Service>>,
    Json(request): Json<ClientRegistrationRequest>,
) -> Result<Json<ClientRegistrationResponse>, ApiError> {
    let response = client_manager
        .register_client(request)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Json(response))
}

/// Get client information
pub async fn get_client(
    State(client_manager): State<OAuth2ClientManager<impl crate::oauth2::OAuth2Service>>,
    axum::extract::Path(client_id): axum::extract::Path<String>,
) -> Result<Json<ApiResponse<crate::oauth2::OAuth2Client>>, ApiError> {
    let client = client_manager
        .get_client(&client_id)
        .await
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Client not found".to_string()))?;

    Ok(Json(ApiResponse::success(client)))
}

/// Update client information
pub async fn update_client(
    State(client_manager): State<OAuth2ClientManager<impl crate::oauth2::OAuth2Service>>,
    axum::extract::Path(client_id): axum::extract::Path<String>,
    Json(request): Json<ClientUpdateRequest>,
) -> Result<Json<ApiResponse<crate::oauth2::OAuth2Client>>, ApiError> {
    let client = client_manager
        .update_client(&client_id, request)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Json(ApiResponse::success(client)))
}

/// Delete a client
pub async fn delete_client(
    State(client_manager): State<OAuth2ClientManager<impl crate::oauth2::OAuth2Service>>,
    axum::extract::Path(client_id): axum::extract::Path<String>,
) -> Result<Json<ApiResponse<bool>>, ApiError> {
    let deleted = client_manager
        .delete_client(&client_id)
        .await
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !deleted {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Client not found".to_string(),
        ));
    }

    Ok(Json(ApiResponse::success(true)))
}

/// List clients
pub async fn list_clients(
    State(client_manager): State<OAuth2ClientManager<impl crate::oauth2::OAuth2Service>>,
    Query(query): Query<ClientQuery>,
) -> Result<Json<ApiResponse<Vec<crate::oauth2::OAuth2Client>>>, ApiError> {
    let clients = client_manager
        .list_clients(query)
        .await
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(ApiResponse::success(clients)))
}

/// Helper function to describe OAuth2 scopes
fn describe_scope(scope: &str) -> String {
    match scope {
        "openid" => "Access your identity".to_string(),
        "profile" => "Access your profile information".to_string(),
        "email" => "Access your email address".to_string(),
        "read" => "Read access to your data".to_string(),
        "write" => "Write access to your data".to_string(),
        "admin" => "Administrative access".to_string(),
        "offline_access" => "Access your data while offline".to_string(),
        _ => format!("Access to {}", scope),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_describe_scope() {
        assert_eq!(describe_scope("openid"), "Access your identity");
        assert_eq!(describe_scope("email"), "Access your email address");
        assert_eq!(describe_scope("custom"), "Access to custom");
    }
}
