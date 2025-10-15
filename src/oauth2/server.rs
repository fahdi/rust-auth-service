use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use uuid::Uuid;

use super::*;
use super::tokens::TokenManager;
use crate::models::user::User;

/// OAuth2 server implementation
pub struct OAuth2Server {
    config: OAuth2Config,
    service: Arc<dyn OAuth2Service>,
    token_manager: TokenManager,
    metadata: OAuth2Metadata,
}

impl OAuth2Server {
    /// Create new OAuth2 server
    pub fn new(config: OAuth2Config, service: Arc<dyn OAuth2Service>, token_manager: TokenManager) -> Self {
        let mut metadata = OAuth2Metadata::default();
        metadata.issuer = config.issuer.clone();
        metadata.authorization_endpoint = format!("{}/oauth2/authorize", config.base_url);
        metadata.token_endpoint = format!("{}/oauth2/token", config.base_url);
        metadata.userinfo_endpoint = Some(format!("{}/oauth2/userinfo", config.base_url));
        metadata.jwks_uri = Some(format!("{}/.well-known/jwks.json", config.base_url));
        metadata.scopes_supported = config.supported_scopes.clone();

        Self {
            config,
            service,
            token_manager,
            metadata,
        }
    }

    /// Get OAuth2 metadata for .well-known/oauth-authorization-server
    pub fn metadata(&self) -> &OAuth2Metadata {
        &self.metadata
    }

    /// Handle authorization request (GET/POST /oauth2/authorize)
    pub async fn handle_authorize(
        &self,
        request: AuthorizeRequest,
        user: Option<User>,
    ) -> Result<AuthorizeResponse> {
        // Validate client
        let client = self.service.get_client(&request.client_id).await?
            .ok_or_else(|| anyhow!("Invalid client"))?;

        if !client.is_active {
            return Err(anyhow!("Client is inactive"));
        }

        // Validate redirect URI
        if let Some(redirect_uri) = &request.redirect_uri {
            if !client.redirect_uris.contains(redirect_uri) {
                return Err(anyhow!("Invalid redirect URI"));
            }
        }

        // Validate response type
        let response_types: Vec<&str> = request.response_type.split(' ').collect();
        for response_type in &response_types {
            match *response_type {
                "code" => {
                    if !client.allowed_grant_types.contains(&GrantType::AuthorizationCode) {
                        return Err(anyhow!("Authorization code flow not allowed for client"));
                    }
                }
                "token" => {
                    if !client.allowed_grant_types.contains(&GrantType::Implicit) {
                        return Err(anyhow!("Implicit flow not allowed for client"));
                    }
                }
                _ => return Err(anyhow!("Unsupported response type")),
            }
        }

        // Validate and parse scopes
        let requested_scopes = self.parse_scopes(request.scope.as_deref())?;
        let allowed_scopes = self.filter_allowed_scopes(&requested_scopes, &client.allowed_scopes);

        // PKCE validation for public clients
        if client.is_public && request.code_challenge.is_none() {
            if self.config.require_pkce {
                return Err(anyhow!("PKCE required for public clients"));
            }
        }

        if let Some(code_challenge) = &request.code_challenge {
            let method = request.code_challenge_method.as_deref().unwrap_or("plain");
            if !["plain", "S256"].contains(&method) {
                return Err(anyhow!("Unsupported code challenge method"));
            }
        }

        // Check if user is authenticated
        let user = match user {
            Some(user) => user,
            None => {
                // User needs to authenticate
                return Ok(AuthorizeResponse::LoginRequired {
                    login_url: format!("/auth/login?return_url={}", 
                        urlencoding::encode(&format!("/oauth2/authorize?{}", 
                            serde_urlencoded::to_string(&request)?
                        ))
                    ),
                });
            }
        };

        // Check if consent is required
        if self.requires_consent(&client, &allowed_scopes, &user).await? {
            return Ok(AuthorizeResponse::ConsentRequired {
                consent_url: format!("/oauth2/consent?client_id={}&scopes={}&state={}", 
                    client.client_id,
                    allowed_scopes.join(","),
                    request.state.as_deref().unwrap_or("")
                ),
                client: client.clone(),
                scopes: allowed_scopes,
            });
        }

        // Generate response based on response type
        if response_types.contains(&"code") {
            self.generate_authorization_code_response(request, client, user, allowed_scopes).await
        } else {
            self.generate_implicit_response(request, client, user, allowed_scopes).await
        }
    }

    /// Handle token request (POST /oauth2/token)
    pub async fn handle_token(&self, request: TokenRequest) -> Result<TokenResponse> {
        match request.grant_type.as_str() {
            "authorization_code" => self.handle_authorization_code_grant(request).await,
            "client_credentials" => self.handle_client_credentials_grant(request).await,
            "refresh_token" => self.handle_refresh_token_grant(request).await,
            "urn:ietf:params:oauth:grant-type:device_code" => self.handle_device_code_grant(request).await,
            _ => Err(anyhow!("Unsupported grant type")),
        }
    }

    /// Handle device authorization request (POST /oauth2/device_authorization)
    pub async fn handle_device_authorization(
        &self,
        request: DeviceAuthorizationRequest,
    ) -> Result<DeviceAuthorizationResponse> {
        if !self.config.enable_device_flow {
            return Err(anyhow!("Device flow not enabled"));
        }

        // Validate client
        let client = self.service.get_client(&request.client_id).await?
            .ok_or_else(|| anyhow!("Invalid client"))?;

        if !client.is_active {
            return Err(anyhow!("Client is inactive"));
        }

        // Validate scopes
        let requested_scopes = self.parse_scopes(request.scope.as_deref())?;
        let allowed_scopes = self.filter_allowed_scopes(&requested_scopes, &client.allowed_scopes);

        // Generate device and user codes
        let device_code = self.generate_device_code();
        let user_code = self.generate_user_code();
        let verification_uri = format!("{}/oauth2/device", self.config.base_url);
        let verification_uri_complete = format!("{}?user_code={}", verification_uri, user_code);

        // Create device authorization
        let auth = DeviceAuthorization {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            verification_uri: verification_uri.clone(),
            verification_uri_complete: verification_uri_complete.clone(),
            client_id: client.client_id,
            scopes: allowed_scopes,
            expires_at: Utc::now() + Duration::seconds(self.config.device_code_lifetime as i64),
            interval: self.config.device_code_interval,
            user_id: None,
            authorized: false,
        };

        self.service.create_device_authorization(auth).await?;

        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code,
            verification_uri,
            verification_uri_complete,
            expires_in: self.config.device_code_lifetime,
            interval: self.config.device_code_interval,
        })
    }

    /// Handle device verification (GET/POST /oauth2/device)
    pub async fn handle_device_verification(
        &self,
        user_code: String,
        user: User,
    ) -> Result<DeviceVerificationResponse> {
        // Get device authorization
        let mut auth = self.service.get_device_authorization_by_user_code(&user_code).await?
            .ok_or_else(|| anyhow!("Invalid user code"))?;

        if auth.expires_at < Utc::now() {
            return Err(anyhow!("User code expired"));
        }

        if auth.authorized {
            return Err(anyhow!("Device already authorized"));
        }

        // Get client information
        let client = self.service.get_client(&auth.client_id).await?
            .ok_or_else(|| anyhow!("Client not found"))?;

        Ok(DeviceVerificationResponse {
            client: client.clone(),
            scopes: auth.scopes.clone(),
            user_code,
        })
    }

    /// Authorize device (POST /oauth2/device/authorize)
    pub async fn authorize_device(&self, user_code: String, user: User) -> Result<()> {
        self.service.authorize_device(&user_code, &user.id.to_string()).await?;
        Ok(())
    }

    /// Handle token revocation (POST /oauth2/revoke)
    pub async fn handle_revocation(&self, token: String, token_type_hint: Option<String>) -> Result<()> {
        // Try revoking as access token first
        if self.service.revoke_access_token(&token).await? {
            return Ok(());
        }

        // Try revoking as refresh token
        if self.service.revoke_refresh_token(&token).await? {
            return Ok(());
        }

        // Token not found - RFC 7009 says to return success anyway
        Ok(())
    }

    /// Handle token introspection (POST /oauth2/introspect)
    pub async fn handle_introspection(&self, token: String) -> Result<TokenIntrospection> {
        self.service.introspect_token(&token).await
    }

    /// Get user info (GET /oauth2/userinfo)
    pub async fn handle_userinfo(&self, access_token: String) -> Result<UserInfo> {
        let token = self.service.get_access_token(&access_token).await?
            .ok_or_else(|| anyhow!("Invalid access token"))?;

        if token.revoked || token.expires_at < Utc::now() {
            return Err(anyhow!("Token expired or revoked"));
        }

        let user_id = token.user_id.ok_or_else(|| anyhow!("Token not associated with user"))?;

        // This would need to get user from user service
        // For now, return basic user info
        Ok(UserInfo {
            sub: user_id,
            email: None,
            email_verified: None,
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
        })
    }

    // Private helper methods

    async fn handle_authorization_code_grant(&self, request: TokenRequest) -> Result<TokenResponse> {
        let code = request.code.ok_or_else(|| anyhow!("Missing authorization code"))?;
        let redirect_uri = request.redirect_uri.ok_or_else(|| anyhow!("Missing redirect URI"))?;

        // Get and validate authorization code
        let auth_code = self.service.get_auth_code(&code).await?
            .ok_or_else(|| anyhow!("Invalid authorization code"))?;

        if auth_code.used {
            return Err(anyhow!("Authorization code already used"));
        }

        if auth_code.expires_at < Utc::now() {
            return Err(anyhow!("Authorization code expired"));
        }

        if auth_code.redirect_uri != redirect_uri {
            return Err(anyhow!("Redirect URI mismatch"));
        }

        // Authenticate client
        let client_id = request.client_id.unwrap_or(auth_code.client_id.clone());
        let client = self.service.get_client(&client_id).await?
            .ok_or_else(|| anyhow!("Invalid client"))?;

        // PKCE verification
        if let Some(code_challenge) = &auth_code.code_challenge {
            let code_verifier = request.code_verifier.ok_or_else(|| anyhow!("Missing PKCE code verifier"))?;
            
            let method = auth_code.code_challenge_method.as_deref().unwrap_or("plain");
            let computed_challenge = match method {
                "plain" => code_verifier.clone(),
                "S256" => {
                    let digest = Sha256::digest(code_verifier.as_bytes());
                    URL_SAFE_NO_PAD.encode(digest)
                }
                _ => return Err(anyhow!("Unsupported code challenge method")),
            };

            if computed_challenge != *code_challenge {
                return Err(anyhow!("PKCE verification failed"));
            }
        }

        // Mark code as used
        self.service.use_auth_code(&code).await?;

        // Generate tokens
        self.generate_tokens(&client, Some(auth_code.user_id), &auth_code.scopes).await
    }

    async fn handle_client_credentials_grant(&self, request: TokenRequest) -> Result<TokenResponse> {
        if !self.config.enable_client_credentials {
            return Err(anyhow!("Client credentials grant not enabled"));
        }

        let client_id = request.client_id.ok_or_else(|| anyhow!("Missing client ID"))?;
        let client = self.service.get_client(&client_id).await?
            .ok_or_else(|| anyhow!("Invalid client"))?;

        if !client.allowed_grant_types.contains(&GrantType::ClientCredentials) {
            return Err(anyhow!("Client credentials grant not allowed"));
        }

        // Authenticate client
        if let Some(client_secret) = &client.client_secret {
            let provided_secret = request.client_secret.ok_or_else(|| anyhow!("Missing client secret"))?;
            if provided_secret != *client_secret {
                return Err(anyhow!("Invalid client credentials"));
            }
        }

        // Parse requested scopes
        let requested_scopes = self.parse_scopes(request.scope.as_deref())?;
        let allowed_scopes = self.filter_allowed_scopes(&requested_scopes, &client.allowed_scopes);

        // Generate access token (no refresh token for client credentials)
        let access_token = self.generate_access_token(&client, None, &allowed_scopes).await?;

        Ok(TokenResponse {
            access_token: access_token.token,
            token_type: "Bearer".to_string(),
            expires_in: Some((access_token.expires_at - Utc::now()).num_seconds() as u64),
            refresh_token: None,
            scope: Some(allowed_scopes.join(" ")),
            id_token: None,
        })
    }

    async fn handle_refresh_token_grant(&self, request: TokenRequest) -> Result<TokenResponse> {
        if !self.config.enable_refresh_tokens {
            return Err(anyhow!("Refresh tokens not enabled"));
        }

        let refresh_token = request.refresh_token.ok_or_else(|| anyhow!("Missing refresh token"))?;

        // Get and validate refresh token
        let token_data = self.service.get_refresh_token(&refresh_token).await?
            .ok_or_else(|| anyhow!("Invalid refresh token"))?;

        if token_data.used {
            return Err(anyhow!("Refresh token already used"));
        }

        if let Some(expires_at) = token_data.expires_at {
            if expires_at < Utc::now() {
                return Err(anyhow!("Refresh token expired"));
            }
        }

        // Get client
        let client = self.service.get_client(&token_data.client_id).await?
            .ok_or_else(|| anyhow!("Client not found"))?;

        // Mark refresh token as used
        self.service.use_refresh_token(&refresh_token).await?;

        // Generate new tokens
        self.generate_tokens(&client, token_data.user_id, &token_data.scopes).await
    }

    async fn handle_device_code_grant(&self, request: TokenRequest) -> Result<TokenResponse> {
        if !self.config.enable_device_flow {
            return Err(anyhow!("Device flow not enabled"));
        }

        let device_code = request.code.ok_or_else(|| anyhow!("Missing device code"))?;

        // Get device authorization
        let auth = self.service.get_device_authorization_by_device_code(&device_code).await?
            .ok_or_else(|| anyhow!("Invalid device code"))?;

        if auth.expires_at < Utc::now() {
            return Err(anyhow!("Device code expired"));
        }

        if !auth.authorized {
            return Err(anyhow!("Device not yet authorized by user"));
        }

        let user_id = auth.user_id.ok_or_else(|| anyhow!("Device authorization missing user"))?;

        // Get client
        let client = self.service.get_client(&auth.client_id).await?
            .ok_or_else(|| anyhow!("Client not found"))?;

        // Generate tokens
        self.generate_tokens(&client, Some(user_id), &auth.scopes).await
    }

    async fn generate_authorization_code_response(
        &self,
        request: AuthorizeRequest,
        client: OAuth2Client,
        user: User,
        scopes: Vec<String>,
    ) -> Result<AuthorizeResponse> {
        let code = self.generate_authorization_code();
        let redirect_uri = request.redirect_uri.unwrap_or_else(|| client.redirect_uris[0].clone());

        let auth_code = AuthorizationCode {
            code: code.clone(),
            client_id: client.client_id,
            user_id: user.id.to_string(),
            redirect_uri: redirect_uri.clone(),
            scopes,
            expires_at: Utc::now() + Duration::seconds(self.config.authorization_code_lifetime as i64),
            code_challenge: request.code_challenge,
            code_challenge_method: request.code_challenge_method,
            nonce: request.nonce,
            state: request.state.clone(),
            used: false,
        };

        self.service.create_auth_code(auth_code).await?;

        let mut redirect_url = format!("{}?code={}", redirect_uri, code);
        if let Some(state) = request.state {
            redirect_url.push_str(&format!("&state={}", urlencoding::encode(&state)));
        }

        Ok(AuthorizeResponse::Redirect { url: redirect_url })
    }

    async fn generate_implicit_response(
        &self,
        request: AuthorizeRequest,
        client: OAuth2Client,
        user: User,
        scopes: Vec<String>,
    ) -> Result<AuthorizeResponse> {
        let redirect_uri = request.redirect_uri.unwrap_or_else(|| client.redirect_uris[0].clone());

        let access_token = self.generate_access_token(&client, Some(user.id.to_string()), &scopes).await?;

        let mut redirect_url = format!(
            "{}#access_token={}&token_type=Bearer&expires_in={}",
            redirect_uri,
            access_token.token,
            (access_token.expires_at - Utc::now()).num_seconds()
        );

        if !scopes.is_empty() {
            redirect_url.push_str(&format!("&scope={}", urlencoding::encode(&scopes.join(" "))));
        }

        if let Some(state) = request.state {
            redirect_url.push_str(&format!("&state={}", urlencoding::encode(&state)));
        }

        Ok(AuthorizeResponse::Redirect { url: redirect_url })
    }

    async fn generate_tokens(&self, client: &OAuth2Client, user_id: Option<String>, scopes: &[String]) -> Result<TokenResponse> {
        let access_token = self.generate_access_token(client, user_id.clone(), scopes).await?;
        
        let refresh_token = if self.config.enable_refresh_tokens && user_id.is_some() {
            Some(self.generate_refresh_token(client, user_id, scopes, &access_token.token).await?)
        } else {
            None
        };

        Ok(TokenResponse {
            access_token: access_token.token,
            token_type: "Bearer".to_string(),
            expires_in: Some((access_token.expires_at - Utc::now()).num_seconds() as u64),
            refresh_token: refresh_token.map(|t| t.token),
            scope: Some(scopes.join(" ")),
            id_token: None, // TODO: Implement OpenID Connect ID tokens
        })
    }

    async fn generate_access_token(&self, client: &OAuth2Client, user_id: Option<String>, scopes: &[String]) -> Result<AccessToken> {
        let token = self.generate_jwt_token(client, user_id.as_deref(), scopes)?;
        
        let access_token = AccessToken {
            token,
            token_type: "Bearer".to_string(),
            client_id: client.client_id.clone(),
            user_id,
            scopes: scopes.to_vec(),
            expires_at: Utc::now() + Duration::seconds(self.config.access_token_lifetime as i64),
            created_at: Utc::now(),
            revoked: false,
        };

        self.service.create_access_token(access_token.clone()).await?;
        Ok(access_token)
    }

    async fn generate_refresh_token(&self, client: &OAuth2Client, user_id: Option<String>, scopes: &[String], access_token: &str) -> Result<RefreshToken> {
        let token = self.generate_random_token(64);
        
        let refresh_token = RefreshToken {
            token,
            access_token: access_token.to_string(),
            client_id: client.client_id.clone(),
            user_id,
            scopes: scopes.to_vec(),
            expires_at: self.config.refresh_token_lifetime.map(|lifetime| 
                Utc::now() + Duration::seconds(lifetime as i64)
            ),
            created_at: Utc::now(),
            used: false,
        };

        self.service.create_refresh_token(refresh_token.clone()).await?;
        Ok(refresh_token)
    }

    fn generate_jwt_token(&self, client: &OAuth2Client, user_id: Option<&str>, scopes: &[String]) -> Result<String> {
        let user_id = user_id.unwrap_or(&client.client_id);
        let (token, _) = self.token_manager.generate_access_token(
            user_id,
            &client.client_id,
            scopes,
            Some(vec![client.client_id.clone()]),
            Some(Utc::now().timestamp()),
            None,
        )?;
        Ok(token)
    }

    fn parse_scopes(&self, scope: Option<&str>) -> Result<Vec<String>> {
        match scope {
            Some(scope_str) => Ok(scope_str.split_whitespace().map(String::from).collect()),
            None => Ok(self.config.default_scopes.clone()),
        }
    }

    fn filter_allowed_scopes(&self, requested: &[String], allowed: &[String]) -> Vec<String> {
        requested
            .iter()
            .filter(|scope| allowed.contains(scope) && self.config.supported_scopes.contains(scope))
            .cloned()
            .collect()
    }

    async fn requires_consent(&self, client: &OAuth2Client, scopes: &[String], user: &User) -> Result<bool> {
        // For now, always require consent for non-first-party apps
        // In a real implementation, you'd check if user has already consented to these scopes
        Ok(!client.client_id.starts_with("first_party_"))
    }

    fn generate_authorization_code(&self) -> String {
        self.generate_random_token(32)
    }

    fn generate_device_code(&self) -> String {
        self.generate_random_token(40)
    }

    fn generate_user_code(&self) -> String {
        // Generate human-readable code (8 characters, uppercase)
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect::<String>()
            .to_uppercase()
    }

    fn generate_random_token(&self, length: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }
}

/// Authorization response types
#[derive(Debug)]
pub enum AuthorizeResponse {
    Redirect { url: String },
    LoginRequired { login_url: String },
    ConsentRequired { 
        consent_url: String, 
        client: OAuth2Client, 
        scopes: Vec<String> 
    },
}

/// Device verification response
#[derive(Debug, Clone, Serialize)]
pub struct DeviceVerificationResponse {
    pub client: OAuth2Client,
    pub scopes: Vec<String>,
    pub user_code: String,
}

/// User info response (OpenID Connect)
#[derive(Debug, Clone, Serialize)]
pub struct UserInfo {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
}