use anyhow::{anyhow, Result};
use chrono::Utc;
use std::sync::Arc;

use super::scopes::utils::parse_scope_string;
use super::tokens::TokenManager;
use super::*;
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
    pub fn new(
        config: OAuth2Config,
        service: Arc<dyn OAuth2Service>,
        token_manager: TokenManager,
    ) -> Self {
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

    /// Create new OAuth2 server without service (temporary)
    pub fn new_without_service(config: OAuth2Config, token_manager: Arc<TokenManager>) -> Self {
        let mut metadata = OAuth2Metadata::default();
        metadata.issuer = config.issuer.clone();
        metadata.authorization_endpoint = format!("{}/oauth2/authorize", config.base_url);
        metadata.token_endpoint = format!("{}/oauth2/token", config.base_url);
        metadata.userinfo_endpoint = Some(format!("{}/oauth2/userinfo", config.base_url));
        metadata.jwks_uri = Some(format!("{}/.well-known/jwks.json", config.base_url));
        metadata.scopes_supported = config.supported_scopes.clone();

        // Create a stub service implementation
        let stub_service: Arc<dyn OAuth2Service> = Arc::new(StubOAuth2Service);

        Self {
            config,
            service: stub_service,
            token_manager: (*token_manager).clone(),
            metadata,
        }
    }

    /// Get OAuth2 metadata for .well-known/oauth-authorization-server
    pub fn metadata(&self) -> &OAuth2Metadata {
        &self.metadata
    }

    /// Get OAuth2 metadata (alias for handlers)
    pub fn get_metadata(&self) -> OAuth2Metadata {
        self.metadata.clone()
    }

    /// Get client by ID
    pub async fn get_client(&self, client_id: &str) -> Result<Option<OAuth2Client>> {
        self.service.get_client(client_id).await
    }

    /// Handle authorization request for handlers
    pub async fn handle_authorization_request(
        &self,
        _response_type: &str,
        client_id: &str,
        redirect_uri: Option<&str>,
        scope: Option<&str>,
        state: Option<&str>,
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
        nonce: Option<&str>,
        user_id: &str,
    ) -> Result<String> {
        use crate::oauth2::flows::validate_redirect_uri;

        // Get and validate client
        let client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid client_id"))?;

        if !client.is_active {
            return Err(anyhow::anyhow!("Client is not active"));
        }

        // Validate redirect URI
        let redirect_uri = redirect_uri.unwrap_or_else(|| client.redirect_uris.first().unwrap());
        if !client.redirect_uris.contains(&redirect_uri.to_string()) {
            return Err(anyhow::anyhow!("Invalid redirect_uri"));
        }

        // Validate redirect URI format
        validate_redirect_uri(redirect_uri)?;

        // Parse and validate scopes
        let _scope_manager = crate::oauth2::scopes::ScopeManager::new();
        let default_scopes = self.config.default_scopes.join(" ");
        let requested_scopes = scope.unwrap_or(&default_scopes);
        let scopes = parse_scope_string(requested_scopes);

        // Filter scopes to only include those allowed for the client
        let validated_scopes: Vec<String> = scopes
            .into_iter()
            .filter(|scope| client.allowed_scopes.contains(scope))
            .collect();

        // Validate PKCE for public clients
        if client.is_public || self.config.require_pkce {
            if code_challenge.is_none() {
                return Err(anyhow::anyhow!("PKCE required for this client"));
            }
        }

        // Generate authorization code
        let code = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(self.config.authorization_code_lifetime as i64);

        let auth_code = AuthorizationCode {
            code: code.clone(),
            client_id: client_id.to_string(),
            user_id: user_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scopes: validated_scopes,
            expires_at: expires_at.into(),
            code_challenge: code_challenge.map(|s| s.to_string()),
            code_challenge_method: code_challenge_method.map(|s| s.to_string()),
            nonce: nonce.map(|s| s.to_string()),
            state: state.map(|s| s.to_string()),
            used: false,
        };

        self.service.create_auth_code(auth_code).await?;

        // Return redirect URL with authorization code
        let mut url = format!("{}?code={}", redirect_uri, code);
        if let Some(state) = state {
            url.push_str(&format!("&state={}", urlencoding::encode(state)));
        }
        Ok(url)
    }

    /// Handle token request for handlers
    pub async fn handle_token_request(&self, request: &TokenRequest) -> Result<TokenResponse> {
        match request.grant_type.as_str() {
            "authorization_code" => {
                self.handle_authorization_code_grant(
                    request
                        .code
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing authorization code"))?,
                    request
                        .client_id
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing client_id"))?,
                    request.client_secret.as_deref(),
                    request
                        .redirect_uri
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing redirect_uri"))?,
                    request.code_verifier.as_deref(),
                )
                .await
            }
            "client_credentials" => {
                self.handle_client_credentials_grant(
                    request
                        .client_id
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing client_id"))?,
                    request.client_secret.as_deref(),
                    request.scope.as_deref(),
                )
                .await
            }
            "refresh_token" => {
                self.handle_refresh_token_grant(
                    request
                        .refresh_token
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing refresh token"))?,
                    request
                        .client_id
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing client_id"))?,
                    request.client_secret.as_deref(),
                    request.scope.as_deref(),
                )
                .await
            }
            _ => Err(anyhow::anyhow!(
                "Unsupported grant type: {}",
                request.grant_type
            )),
        }
    }

    /// Handle authorization code grant
    async fn handle_authorization_code_grant(
        &self,
        code: &str,
        client_id: &str,
        client_secret: Option<&str>,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse> {
        use crate::oauth2::pkce::{verify_pkce, PKCEVerificationResult};

        // Get and validate authorization code
        let auth_code = self
            .service
            .get_auth_code(code)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid authorization code"))?;

        if auth_code.used {
            return Err(anyhow::anyhow!("Authorization code already used"));
        }

        if auth_code.expires_at < Utc::now() {
            return Err(anyhow::anyhow!("Authorization code expired"));
        }

        if auth_code.client_id != client_id {
            return Err(anyhow::anyhow!("Client ID mismatch"));
        }

        if auth_code.redirect_uri != redirect_uri {
            return Err(anyhow::anyhow!("Redirect URI mismatch"));
        }

        // Get and validate client
        let client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid client"))?;

        // Authenticate client
        if !client.is_public {
            let provided_secret =
                client_secret.ok_or_else(|| anyhow::anyhow!("Client secret required"))?;
            let expected_secret = client
                .client_secret
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Client secret not configured"))?;

            if provided_secret != expected_secret {
                return Err(anyhow::anyhow!("Invalid client credentials"));
            }
        }

        // Verify PKCE if present
        let pkce_result = verify_pkce(
            code_verifier,
            auth_code.code_challenge.as_deref(),
            auth_code.code_challenge_method.as_deref(),
        );

        match pkce_result {
            PKCEVerificationResult::Valid => {}
            PKCEVerificationResult::Invalid => {
                return Err(anyhow::anyhow!("PKCE verification failed"))
            }
            PKCEVerificationResult::MethodMismatch => {
                return Err(anyhow::anyhow!("PKCE method mismatch"))
            }
            PKCEVerificationResult::MissingVerifier => {
                if auth_code.code_challenge.is_some() {
                    return Err(anyhow::anyhow!("PKCE verifier required"));
                }
            }
            PKCEVerificationResult::MissingChallenge => {
                if code_verifier.is_some() {
                    return Err(anyhow::anyhow!("PKCE not used in authorization"));
                }
            }
        }

        // Mark authorization code as used
        self.service.use_auth_code(code).await?;

        // Generate tokens
        let (access_token, access_token_record) = self.token_manager.generate_access_token(
            &auth_code.user_id,
            client_id,
            &auth_code.scopes,
            None,
            Some(chrono::Utc::now().timestamp()),
            None,
        )?;

        // Store access token
        self.service
            .create_access_token(access_token_record)
            .await?;

        let mut response = TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: Some(self.config.access_token_lifetime),
            refresh_token: None,
            scope: Some(auth_code.scopes.join(" ")),
            id_token: None,
        };

        // Generate refresh token if enabled
        if self.config.enable_refresh_tokens {
            let (refresh_token, refresh_token_record) = self.token_manager.generate_refresh_token(
                &response.access_token,
                &auth_code.user_id,
                client_id,
                &auth_code.scopes,
                None,
            )?;

            self.service
                .create_refresh_token(refresh_token_record)
                .await?;
            response.refresh_token = Some(refresh_token);
        }

        // Generate ID token if openid scope requested
        if auth_code.scopes.contains(&"openid".to_string()) {
            let id_token = self.token_manager.generate_id_token(
                &auth_code.user_id,
                client_id,
                chrono::Utc::now().timestamp(),
                auth_code.nonce.clone(),
                Some(&response.access_token),
                Some(code),
                None,
            )?;

            response.id_token = Some(id_token);
        }

        Ok(response)
    }

    /// Handle client credentials grant
    async fn handle_client_credentials_grant(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        scope: Option<&str>,
    ) -> Result<TokenResponse> {
        if !self.config.enable_client_credentials {
            return Err(anyhow::anyhow!("Client credentials grant not enabled"));
        }

        // Get and validate client
        let client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid client"))?;

        if !client
            .allowed_grant_types
            .contains(&GrantType::ClientCredentials)
        {
            return Err(anyhow::anyhow!(
                "Client credentials grant not allowed for this client"
            ));
        }

        // Authenticate client
        if !client.is_public {
            let provided_secret =
                client_secret.ok_or_else(|| anyhow::anyhow!("Client secret required"))?;
            let expected_secret = client
                .client_secret
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Client secret not configured"))?;

            if provided_secret != expected_secret {
                return Err(anyhow::anyhow!("Invalid client credentials"));
            }
        }

        // Parse and validate scopes
        let _scope_manager = crate::oauth2::scopes::ScopeManager::new();
        let default_scopes = self.config.default_scopes.join(" ");
        let requested_scopes = scope.unwrap_or(&default_scopes);
        let scopes = parse_scope_string(requested_scopes);
        let validated_scopes: Vec<String> = scopes
            .into_iter()
            .filter(|scope| client.allowed_scopes.contains(scope))
            .collect();

        // Generate access token (no user context for client credentials)
        let (access_token, access_token_record) = self.token_manager.generate_access_token(
            "", // No user for client credentials
            client_id,
            &validated_scopes,
            None,
            Some(chrono::Utc::now().timestamp()),
            None,
        )?;

        // Store access token
        self.service
            .create_access_token(access_token_record)
            .await?;

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: Some(self.config.access_token_lifetime),
            refresh_token: None,
            scope: Some(validated_scopes.join(" ")),
            id_token: None,
        })
    }

    /// Handle refresh token grant
    async fn handle_refresh_token_grant(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: Option<&str>,
        scope: Option<&str>,
    ) -> Result<TokenResponse> {
        if !self.config.enable_refresh_tokens {
            return Err(anyhow::anyhow!("Refresh token grant not enabled"));
        }

        // Get and validate refresh token
        let token_record = self
            .service
            .get_refresh_token(refresh_token)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid refresh token"))?;

        if token_record.used {
            return Err(anyhow::anyhow!("Refresh token already used"));
        }

        if let Some(expires_at) = token_record.expires_at {
            if expires_at < Utc::now() {
                return Err(anyhow::anyhow!("Refresh token expired"));
            }
        }

        if token_record.client_id != client_id {
            return Err(anyhow::anyhow!("Client ID mismatch"));
        }

        // Get and validate client
        let client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid client"))?;

        // Authenticate client
        if !client.is_public {
            let provided_secret =
                client_secret.ok_or_else(|| anyhow::anyhow!("Client secret required"))?;
            let expected_secret = client
                .client_secret
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Client secret not configured"))?;

            if provided_secret != expected_secret {
                return Err(anyhow::anyhow!("Invalid client credentials"));
            }
        }

        // Validate scopes (can't request more than original)
        let _scope_manager = crate::oauth2::scopes::ScopeManager::new();
        let scopes = if let Some(scope) = scope {
            let requested_scopes = parse_scope_string(scope);
            let original_scopes = &token_record.scopes;

            // Ensure requested scopes are subset of original
            for requested_scope in &requested_scopes {
                if !original_scopes.contains(requested_scope) {
                    return Err(anyhow::anyhow!(
                        "Cannot request scope not in original token: {}",
                        requested_scope
                    ));
                }
            }
            requested_scopes
        } else {
            token_record.scopes.clone()
        };

        // Mark refresh token as used
        self.service.use_refresh_token(refresh_token).await?;

        // Revoke old access token
        self.service
            .revoke_access_token(&token_record.access_token)
            .await?;

        // Generate new tokens
        let user_id = token_record.user_id.as_deref().unwrap_or("");
        let (access_token, access_token_record) = self.token_manager.generate_access_token(
            user_id,
            client_id,
            &scopes,
            None,
            Some(chrono::Utc::now().timestamp()),
            None,
        )?;

        // Store new access token
        self.service
            .create_access_token(access_token_record)
            .await?;

        let mut response = TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: Some(self.config.access_token_lifetime),
            refresh_token: None,
            scope: Some(scopes.join(" ")),
            id_token: None,
        };

        // Generate new refresh token
        let (new_refresh_token, new_refresh_token_record) = self
            .token_manager
            .generate_refresh_token(&response.access_token, user_id, client_id, &scopes, None)?;

        self.service
            .create_refresh_token(new_refresh_token_record)
            .await?;
        response.refresh_token = Some(new_refresh_token);

        // Generate ID token if openid scope present
        if scopes.contains(&"openid".to_string()) && !user_id.is_empty() {
            let id_token = self.token_manager.generate_id_token(
                user_id,
                client_id,
                chrono::Utc::now().timestamp(),
                None,
                Some(&response.access_token),
                None,
                None,
            )?;

            response.id_token = Some(id_token);
        }

        Ok(response)
    }

    /// Handle device authorization for handlers
    pub async fn handle_device_authorization(
        &self,
        client_id: &str,
        scope: Option<&str>,
    ) -> Result<DeviceAuthorizationResponse> {
        if !self.config.enable_device_flow {
            return Err(anyhow::anyhow!("Device flow not enabled"));
        }

        // Get and validate client
        let client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid client"))?;

        if !client.allowed_grant_types.contains(&GrantType::DeviceCode) {
            return Err(anyhow::anyhow!(
                "Device code grant not allowed for this client"
            ));
        }

        // Validate and process scopes
        let _scope_manager = crate::oauth2::scopes::ScopeManager::new();
        let default_scopes = self.config.default_scopes.join(" ");
        let requested_scopes = scope.unwrap_or(&default_scopes);
        let scopes = parse_scope_string(requested_scopes);
        let validated_scopes: Vec<String> = scopes
            .into_iter()
            .filter(|scope| client.allowed_scopes.contains(scope))
            .collect();

        // Generate device code and user code
        let device_code = uuid::Uuid::new_v4().to_string();
        let user_code = self.generate_user_code();
        let verification_uri = format!("{}/device", self.config.base_url);
        let verification_uri_complete = format!("{}?user_code={}", verification_uri, user_code);

        let device_auth = DeviceAuthorization {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            verification_uri: verification_uri.clone(),
            verification_uri_complete: verification_uri_complete.clone(),
            client_id: client_id.to_string(),
            scopes: validated_scopes,
            expires_at: (chrono::Utc::now()
                + chrono::Duration::seconds(self.config.device_code_lifetime as i64))
            .into(),
            interval: self.config.device_code_interval,
            user_id: None,
            authorized: false,
        };

        // Store device authorization
        self.service
            .create_device_authorization(device_auth)
            .await?;

        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code,
            verification_uri,
            verification_uri_complete,
            expires_in: self.config.device_code_lifetime,
            interval: self.config.device_code_interval,
        })
    }

    /// Authorize device code for handlers
    pub async fn authorize_device_code(&self, user_code: &str, user_id: &str) -> Result<bool> {
        self.service.authorize_device(user_code, user_id).await
    }

    /// Generate user-friendly device code
    fn generate_user_code(&self) -> String {
        use rand::Rng;

        // Generate 8-character alphanumeric code (excluding confusing characters)
        let charset: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        let mut rng = rand::thread_rng();

        (0..8)
            .map(|_| {
                let idx = rng.gen_range(0..charset.len());
                charset[idx] as char
            })
            .collect()
    }

    /// Introspect token for handlers
    pub async fn introspect_token(&self, token: &str) -> Result<TokenIntrospection> {
        self.service.introspect_token(token).await
    }

    /// Revoke token for handlers
    pub async fn revoke_token(&self, token: &str) -> Result<bool> {
        // Try to revoke as access token first, then refresh token
        let access_revoked = self
            .service
            .revoke_access_token(token)
            .await
            .unwrap_or(false);
        if access_revoked {
            return Ok(true);
        }

        let refresh_revoked = self
            .service
            .revoke_refresh_token(token)
            .await
            .unwrap_or(false);
        Ok(refresh_revoked)
    }

    /// Get JWKS for handlers
    pub async fn get_jwks(&self) -> Result<serde_json::Value> {
        // TODO: Implement proper JWKS endpoint with public keys
        // For now, return a basic structure
        Ok(serde_json::json!({
            "keys": []
        }))
    }

    /// Handle authorization request (GET/POST /oauth2/authorize)
    pub async fn handle_authorize(
        &self,
        request: AuthorizeRequest,
        user: Option<User>,
    ) -> Result<AuthorizeResponse> {
        // Validate client
        let client = self
            .service
            .get_client(&request.client_id)
            .await?
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
                    if !client
                        .allowed_grant_types
                        .contains(&GrantType::AuthorizationCode)
                    {
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
        let default_scopes = self.config.default_scopes.join(" ");
        let requested_scopes = request.scope.as_deref().unwrap_or(&default_scopes);
        let scopes = parse_scope_string(requested_scopes);
        let allowed_scopes: Vec<String> = scopes
            .into_iter()
            .filter(|scope| client.allowed_scopes.contains(scope))
            .collect();

        // PKCE validation for public clients
        if client.is_public && request.code_challenge.is_none() {
            if self.config.require_pkce {
                return Err(anyhow!("PKCE required for public clients"));
            }
        }

        if let Some(_code_challenge) = &request.code_challenge {
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
                    login_url: format!(
                        "/auth/login?return_url={}",
                        urlencoding::encode(&format!(
                            "/oauth2/authorize?{}",
                            serde_urlencoded::to_string(&request)?
                        ))
                    ),
                });
            }
        };

        // Check if consent is required
        if self
            .requires_consent(&client, &allowed_scopes, &user)
            .await?
        {
            return Ok(AuthorizeResponse::ConsentRequired {
                consent_url: format!(
                    "/oauth2/consent?client_id={}&scopes={}&state={}",
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
            self.generate_authorization_code_response(request, client, user, allowed_scopes)
                .await
        } else {
            self.generate_implicit_response(request, client, user, allowed_scopes)
                .await
        }
    }

    /// Handle token request (POST /oauth2/token)
    pub async fn handle_token(&self, request: TokenRequest) -> Result<TokenResponse> {
        match request.grant_type.as_str() {
            "authorization_code" => {
                let code = request
                    .code
                    .as_deref()
                    .ok_or_else(|| anyhow!("Missing authorization code"))?;
                let client_id = request
                    .client_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("Missing client ID"))?;
                let redirect_uri = request
                    .redirect_uri
                    .as_deref()
                    .ok_or_else(|| anyhow!("Missing redirect URI"))?;
                self.handle_authorization_code_grant(
                    code,
                    client_id,
                    request.client_secret.as_deref(),
                    redirect_uri,
                    request.code_verifier.as_deref(),
                )
                .await
            }
            "client_credentials" => {
                let client_id = request
                    .client_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("Missing client ID"))?;
                self.handle_client_credentials_grant(
                    client_id,
                    request.client_secret.as_deref(),
                    request.scope.as_deref(),
                )
                .await
            }
            "refresh_token" => {
                let refresh_token = request
                    .refresh_token
                    .as_deref()
                    .ok_or_else(|| anyhow!("Missing refresh token"))?;
                let client_id = request
                    .client_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("Missing client ID"))?;
                self.handle_refresh_token_grant(
                    refresh_token,
                    client_id,
                    request.client_secret.as_deref(),
                    request.scope.as_deref(),
                )
                .await
            }
            "urn:ietf:params:oauth:grant-type:device_code" => {
                let device_code = request
                    .code
                    .as_deref()
                    .ok_or_else(|| anyhow!("Missing device code"))?;

                // Get device authorization
                let auth = self
                    .service
                    .get_device_authorization_by_device_code(device_code)
                    .await?
                    .ok_or_else(|| anyhow!("Invalid device code"))?;

                if auth.expires_at < Utc::now() {
                    return Err(anyhow!("Device code expired"));
                }

                if !auth.authorized {
                    return Err(anyhow!("Device not yet authorized by user"));
                }

                let user_id = auth
                    .user_id
                    .ok_or_else(|| anyhow!("Device authorization missing user"))?;

                // Get client
                let client = self
                    .service
                    .get_client(&auth.client_id)
                    .await?
                    .ok_or_else(|| anyhow!("Client not found"))?;

                // Generate tokens
                let (access_token_str, _) = self.token_manager.generate_access_token(
                    &user_id,
                    &client.client_id,
                    &auth.scopes,
                    Some(vec![client.client_id.clone()]),
                    Some(Utc::now().timestamp()),
                    None,
                )?;

                Ok(TokenResponse {
                    access_token: access_token_str,
                    token_type: "Bearer".to_string(),
                    expires_in: Some(self.config.access_token_lifetime),
                    refresh_token: None,
                    scope: Some(auth.scopes.join(" ")),
                    id_token: None,
                })
            }
            _ => Err(anyhow!("Unsupported grant type")),
        }
    }

    /// Handle device verification (GET/POST /oauth2/device)
    pub async fn handle_device_verification(
        &self,
        user_code: String,
        _user: User,
    ) -> Result<DeviceVerificationResponse> {
        // Get device authorization
        let auth = self
            .service
            .get_device_authorization_by_user_code(&user_code)
            .await?
            .ok_or_else(|| anyhow!("Invalid user code"))?;

        if auth.expires_at < Utc::now() {
            return Err(anyhow!("User code expired"));
        }

        if auth.authorized {
            return Err(anyhow!("Device already authorized"));
        }

        // Get client information
        let client = self
            .service
            .get_client(&auth.client_id)
            .await?
            .ok_or_else(|| anyhow!("Client not found"))?;

        Ok(DeviceVerificationResponse {
            client: client.clone(),
            scopes: auth.scopes.clone(),
            user_code,
        })
    }

    /// Authorize device (POST /oauth2/device/authorize)
    pub async fn authorize_device(&self, user_code: String, user: User) -> Result<()> {
        let user_id = user
            .id
            .map(|id| id.to_string())
            .unwrap_or_else(|| user.email.clone());
        self.service.authorize_device(&user_code, &user_id).await?;
        Ok(())
    }

    /// Handle token revocation (POST /oauth2/revoke)
    pub async fn handle_revocation(
        &self,
        token: String,
        _token_type_hint: Option<String>,
    ) -> Result<()> {
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
        let token = self
            .service
            .get_access_token(&access_token)
            .await?
            .ok_or_else(|| anyhow!("Invalid access token"))?;

        if token.revoked || token.expires_at < Utc::now() {
            return Err(anyhow!("Token expired or revoked"));
        }

        let user_id = token
            .user_id
            .ok_or_else(|| anyhow!("Token not associated with user"))?;

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

    /// Check if user consent is required for the given client and scopes
    async fn requires_consent(
        &self,
        _client: &OAuth2Client,
        _scopes: &[String],
        _user: &User,
    ) -> Result<bool> {
        // For now, always require consent for non-first-party apps
        // In a real implementation, you'd check if user has already consented to these scopes
        Ok(true)
    }

    /// Generate authorization code response for successful authorization
    async fn generate_authorization_code_response(
        &self,
        request: AuthorizeRequest,
        client: OAuth2Client,
        user: User,
        scopes: Vec<String>,
    ) -> Result<AuthorizeResponse> {
        let code = self.generate_authorization_code();
        let redirect_uri = request
            .redirect_uri
            .unwrap_or_else(|| client.redirect_uris[0].clone());

        let auth_code = AuthorizationCode {
            code: code.clone(),
            client_id: client.client_id,
            user_id: user
                .id
                .map(|id| id.to_string())
                .unwrap_or_else(|| user.email.clone()),
            redirect_uri: redirect_uri.clone(),
            scopes,
            expires_at: Utc::now()
                + chrono::Duration::seconds(self.config.authorization_code_lifetime as i64),
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

    /// Generate implicit flow response
    async fn generate_implicit_response(
        &self,
        _request: AuthorizeRequest,
        _client: OAuth2Client,
        _user: User,
        _scopes: Vec<String>,
    ) -> Result<AuthorizeResponse> {
        // Simplified implementation for now
        Err(anyhow!("Implicit flow not yet implemented"))
    }

    /// Generate authorization code
    fn generate_authorization_code(&self) -> String {
        self.generate_random_token(32)
    }

    /// Generate device code
    fn generate_device_code(&self) -> String {
        self.generate_random_token(40)
    }

    /// Generate random token
    fn generate_random_token(&self, length: usize) -> String {
        use rand::{distributions::Alphanumeric, Rng};
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
    Redirect {
        url: String,
    },
    LoginRequired {
        login_url: String,
    },
    ConsentRequired {
        consent_url: String,
        client: OAuth2Client,
        scopes: Vec<String>,
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

/// Stub implementation of OAuth2Service for temporary use
struct StubOAuth2Service;

#[async_trait::async_trait]
impl OAuth2Service for StubOAuth2Service {
    async fn create_client(&self, _client: OAuth2Client) -> Result<OAuth2Client> {
        Err(anyhow!("OAuth2Service not implemented"))
    }

    async fn get_client(&self, _client_id: &str) -> Result<Option<OAuth2Client>> {
        Ok(None)
    }

    async fn update_client(&self, _client: OAuth2Client) -> Result<OAuth2Client> {
        Err(anyhow!("OAuth2Service not implemented"))
    }

    async fn delete_client(&self, _client_id: &str) -> Result<bool> {
        Ok(false)
    }

    async fn list_clients(
        &self,
        _limit: Option<u64>,
        _offset: Option<u64>,
    ) -> Result<Vec<OAuth2Client>> {
        Ok(Vec::new())
    }

    async fn create_auth_code(&self, _code: AuthorizationCode) -> Result<AuthorizationCode> {
        Err(anyhow!("OAuth2Service not implemented"))
    }

    async fn get_auth_code(&self, _code: &str) -> Result<Option<AuthorizationCode>> {
        Ok(None)
    }

    async fn use_auth_code(&self, _code: &str) -> Result<bool> {
        Ok(false)
    }

    async fn cleanup_expired_codes(&self) -> Result<u64> {
        Ok(0)
    }

    async fn create_access_token(&self, _token: AccessToken) -> Result<AccessToken> {
        Err(anyhow!("OAuth2Service not implemented"))
    }

    async fn get_access_token(&self, _token: &str) -> Result<Option<AccessToken>> {
        Ok(None)
    }

    async fn revoke_access_token(&self, _token: &str) -> Result<bool> {
        Ok(false)
    }

    async fn cleanup_expired_tokens(&self) -> Result<u64> {
        Ok(0)
    }

    async fn create_refresh_token(&self, _token: RefreshToken) -> Result<RefreshToken> {
        Err(anyhow!("OAuth2Service not implemented"))
    }

    async fn get_refresh_token(&self, _token: &str) -> Result<Option<RefreshToken>> {
        Ok(None)
    }

    async fn use_refresh_token(&self, _token: &str) -> Result<bool> {
        Ok(false)
    }

    async fn revoke_refresh_token(&self, _token: &str) -> Result<bool> {
        Ok(false)
    }

    async fn create_device_authorization(
        &self,
        _auth: DeviceAuthorization,
    ) -> Result<DeviceAuthorization> {
        Err(anyhow!("OAuth2Service not implemented"))
    }

    async fn get_device_authorization_by_device_code(
        &self,
        _device_code: &str,
    ) -> Result<Option<DeviceAuthorization>> {
        Ok(None)
    }

    async fn get_device_authorization_by_user_code(
        &self,
        _user_code: &str,
    ) -> Result<Option<DeviceAuthorization>> {
        Ok(None)
    }

    async fn authorize_device(&self, _user_code: &str, _user_id: &str) -> Result<bool> {
        Ok(false)
    }

    async fn cleanup_expired_device_authorizations(&self) -> Result<u64> {
        Ok(0)
    }

    async fn introspect_token(&self, _token: &str) -> Result<TokenIntrospection> {
        Ok(TokenIntrospection {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        })
    }

    async fn revoke_all_user_tokens(&self, _user_id: &str) -> Result<u64> {
        Ok(0)
    }

    async fn revoke_all_client_tokens(&self, _client_id: &str) -> Result<u64> {
        Ok(0)
    }

    async fn get_user_tokens(&self, _user_id: &str) -> Result<Vec<AccessToken>> {
        Ok(Vec::new())
    }

    async fn get_client_tokens(&self, _client_id: &str) -> Result<Vec<AccessToken>> {
        Ok(Vec::new())
    }
}
