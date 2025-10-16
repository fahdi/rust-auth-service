use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use uuid::Uuid;

use super::pkce::{verify_pkce, PKCEVerificationResult};
use super::scopes::ScopeManager;
use super::tokens::{AccessTokenClaims, TokenManager};
use super::{
    AuthorizationCode, DeviceAuthorization, GrantType, OAuth2Client, OAuth2Config, OAuth2Error,
    OAuth2ErrorResponse, OAuth2Service, ResponseType, TokenResponse,
};

/// OAuth2 flow handler for different authorization flows
pub struct OAuth2FlowHandler<T: OAuth2Service> {
    service: T,
    config: OAuth2Config,
    token_manager: TokenManager,
    scope_manager: ScopeManager,
}

impl<T: OAuth2Service> OAuth2FlowHandler<T> {
    pub fn new(
        service: T,
        config: OAuth2Config,
        token_manager: TokenManager,
        scope_manager: ScopeManager,
    ) -> Self {
        Self {
            service,
            config,
            token_manager,
            scope_manager,
        }
    }

    /// Handle authorization code flow - authorization endpoint
    pub async fn handle_authorization_request(
        &self,
        response_type: &str,
        client_id: &str,
        redirect_uri: Option<&str>,
        scope: Option<&str>,
        state: Option<&str>,
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
        nonce: Option<&str>,
        user_id: &str,
    ) -> Result<String> {
        // Validate response type
        let response_type = match response_type {
            "code" => ResponseType::Code,
            "token" => ResponseType::Token,
            "id_token" => ResponseType::IdToken,
            "code token" => ResponseType::CodeToken,
            "code id_token" => ResponseType::CodeIdToken,
            _ => return Err(anyhow!("Unsupported response type: {}", response_type)),
        };

        // Get and validate client
        let client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow!("Invalid client_id"))?;

        if !client.is_active {
            return Err(anyhow!("Client is not active"));
        }

        // Validate redirect URI
        let redirect_uri = redirect_uri.unwrap_or_else(|| client.redirect_uris.first().unwrap());
        if !client.redirect_uris.contains(&redirect_uri.to_string()) {
            return Err(anyhow!("Invalid redirect_uri"));
        }

        // Validate and process scopes
        let default_scopes = self.config.default_scopes.join(" ");
        let requested_scopes = scope.unwrap_or(&default_scopes);
        let scopes = crate::oauth2::scopes::utils::parse_scope_string(requested_scopes);
        let validation_result = self.scope_manager.validate_scopes(&scopes);
        if !validation_result.invalid.is_empty() {
            return Err(anyhow!(
                "Invalid scopes: {}",
                validation_result.invalid.join(", ")
            ));
        }
        if !validation_result.conflicts.is_empty() {
            return Err(anyhow!(
                "Scope conflicts: {}",
                validation_result
                    .conflicts
                    .iter()
                    .map(|c| &c.reason)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        // Filter scopes to only include those allowed for the client
        let validated_scopes: Vec<String> = scopes
            .into_iter()
            .filter(|scope| client.allowed_scopes.contains(scope))
            .collect();

        // Validate PKCE for public clients
        if client.is_public || self.config.require_pkce {
            if code_challenge.is_none() {
                return Err(anyhow!("PKCE required for this client"));
            }
        }

        // Generate authorization code for code flows
        if matches!(
            response_type,
            ResponseType::Code | ResponseType::CodeToken | ResponseType::CodeIdToken
        ) {
            let code = self
                .generate_authorization_code(
                    &client,
                    user_id,
                    redirect_uri,
                    &validated_scopes,
                    code_challenge,
                    code_challenge_method,
                    nonce,
                    state,
                )
                .await?;

            // For hybrid flows, also generate tokens
            match response_type {
                ResponseType::Code => {
                    let mut url = format!("{}?code={}", redirect_uri, code);
                    if let Some(state) = state {
                        url.push_str(&format!("&state={}", urlencoding::encode(state)));
                    }
                    Ok(url)
                }
                ResponseType::CodeToken => {
                    let (access_token, _) = self.token_manager.generate_access_token(
                        user_id,
                        client_id,
                        &validated_scopes,
                        None,
                        Some(Utc::now().timestamp()),
                        None,
                    )?;

                    let mut url = format!(
                        "{}?code={}&access_token={}&token_type=Bearer",
                        redirect_uri, code, access_token
                    );
                    if let Some(state) = state {
                        url.push_str(&format!("&state={}", urlencoding::encode(state)));
                    }
                    Ok(url)
                }
                ResponseType::CodeIdToken => {
                    let id_token = self.token_manager.generate_id_token(
                        user_id,
                        client_id,
                        Utc::now().timestamp(),
                        nonce.map(|s| s.to_string()),
                        None,
                        Some(&code),
                        None,
                    )?;

                    let mut url = format!("{}?code={}&id_token={}", redirect_uri, code, id_token);
                    if let Some(state) = state {
                        url.push_str(&format!("&state={}", urlencoding::encode(state)));
                    }
                    Ok(url)
                }
                _ => unreachable!(),
            }
        } else {
            // Implicit flow - return tokens directly
            match response_type {
                ResponseType::Token => {
                    let (access_token, _) = self.token_manager.generate_access_token(
                        user_id,
                        client_id,
                        &validated_scopes,
                        None,
                        Some(Utc::now().timestamp()),
                        None,
                    )?;

                    let mut url = format!(
                        "{}#access_token={}&token_type=Bearer&expires_in={}",
                        redirect_uri, access_token, self.config.access_token_lifetime
                    );
                    if let Some(state) = state {
                        url.push_str(&format!("&state={}", urlencoding::encode(state)));
                    }
                    Ok(url)
                }
                ResponseType::IdToken => {
                    let id_token = self.token_manager.generate_id_token(
                        user_id,
                        client_id,
                        Utc::now().timestamp(),
                        nonce.map(|s| s.to_string()),
                        None,
                        None,
                        None,
                    )?;

                    let mut url = format!("{}#id_token={}", redirect_uri, id_token);
                    if let Some(state) = state {
                        url.push_str(&format!("&state={}", urlencoding::encode(state)));
                    }
                    Ok(url)
                }
                _ => Err(anyhow!("Unsupported response type for implicit flow")),
            }
        }
    }

    /// Handle authorization code flow - token endpoint
    pub async fn handle_authorization_code_grant(
        &self,
        code: &str,
        client_id: &str,
        client_secret: Option<&str>,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse> {
        // Get and validate authorization code
        let auth_code = self
            .service
            .get_auth_code(code)
            .await?
            .ok_or_else(|| anyhow!("Invalid authorization code"))?;

        if auth_code.used {
            return Err(anyhow!("Authorization code already used"));
        }

        if auth_code.expires_at < Utc::now() {
            return Err(anyhow!("Authorization code expired"));
        }

        if auth_code.client_id != client_id {
            return Err(anyhow!("Client ID mismatch"));
        }

        if auth_code.redirect_uri != redirect_uri {
            return Err(anyhow!("Redirect URI mismatch"));
        }

        // Get and validate client
        let client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow!("Invalid client"))?;

        // Authenticate client
        self.authenticate_client(&client, client_secret).await?;

        // Verify PKCE if present
        let pkce_result = verify_pkce(
            code_verifier,
            auth_code.code_challenge.as_deref(),
            auth_code.code_challenge_method.as_deref(),
        );

        match pkce_result {
            PKCEVerificationResult::Valid => {}
            PKCEVerificationResult::Invalid => return Err(anyhow!("PKCE verification failed")),
            PKCEVerificationResult::MethodMismatch => return Err(anyhow!("PKCE method mismatch")),
            PKCEVerificationResult::MissingVerifier => {
                if auth_code.code_challenge.is_some() {
                    return Err(anyhow!("PKCE verifier required"));
                }
            }
            PKCEVerificationResult::MissingChallenge => {
                if code_verifier.is_some() {
                    return Err(anyhow!("PKCE not used in authorization"));
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
            Some(Utc::now().timestamp()),
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
                Utc::now().timestamp(),
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
    pub async fn handle_client_credentials_grant(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        scope: Option<&str>,
    ) -> Result<TokenResponse> {
        if !self.config.enable_client_credentials {
            return Err(anyhow!("Client credentials grant not enabled"));
        }

        // Get and validate client
        let client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow!("Invalid client"))?;

        if !client
            .allowed_grant_types
            .contains(&GrantType::ClientCredentials)
        {
            return Err(anyhow!(
                "Client credentials grant not allowed for this client"
            ));
        }

        // Authenticate client
        self.authenticate_client(&client, client_secret).await?;

        // Validate and process scopes
        let default_scopes = self.config.default_scopes.join(" ");
        let requested_scopes = scope.unwrap_or(&default_scopes);
        let scopes = crate::oauth2::scopes::utils::parse_scope_string(requested_scopes);
        let validation_result = self.scope_manager.validate_scopes(&scopes);
        if !validation_result.invalid.is_empty() {
            return Err(anyhow!(
                "Invalid scopes: {}",
                validation_result.invalid.join(", ")
            ));
        }
        if !validation_result.conflicts.is_empty() {
            return Err(anyhow!(
                "Scope conflicts: {}",
                validation_result
                    .conflicts
                    .iter()
                    .map(|c| &c.reason)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        // Filter scopes to only include those allowed for the client
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
            Some(Utc::now().timestamp()),
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
    pub async fn handle_refresh_token_grant(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: Option<&str>,
        scope: Option<&str>,
    ) -> Result<TokenResponse> {
        if !self.config.enable_refresh_tokens {
            return Err(anyhow!("Refresh token grant not enabled"));
        }

        // Get and validate refresh token
        let token_record = self
            .service
            .get_refresh_token(refresh_token)
            .await?
            .ok_or_else(|| anyhow!("Invalid refresh token"))?;

        if token_record.used {
            return Err(anyhow!("Refresh token already used"));
        }

        if let Some(expires_at) = token_record.expires_at {
            if expires_at < Utc::now() {
                return Err(anyhow!("Refresh token expired"));
            }
        }

        if token_record.client_id != client_id {
            return Err(anyhow!("Client ID mismatch"));
        }

        // Get and validate client
        let client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow!("Invalid client"))?;

        // Authenticate client
        self.authenticate_client(&client, client_secret).await?;

        // Validate scopes (can't request more than original)
        let scopes = if let Some(scope) = scope {
            let requested_scopes = crate::oauth2::scopes::utils::parse_scope_string(scope);
            let original_scopes = &token_record.scopes;

            // Ensure requested scopes are subset of original
            for requested_scope in &requested_scopes {
                if !original_scopes.contains(requested_scope) {
                    return Err(anyhow!(
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
            Some(Utc::now().timestamp()),
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
                Utc::now().timestamp(),
                None,
                Some(&response.access_token),
                None,
                None,
            )?;

            response.id_token = Some(id_token);
        }

        Ok(response)
    }

    /// Handle device authorization flow - device authorization endpoint
    pub async fn handle_device_authorization(
        &self,
        client_id: &str,
        scope: Option<&str>,
    ) -> Result<super::DeviceAuthorizationResponse> {
        if !self.config.enable_device_flow {
            return Err(anyhow!("Device flow not enabled"));
        }

        // Get and validate client
        let client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow!("Invalid client"))?;

        if !client.allowed_grant_types.contains(&GrantType::DeviceCode) {
            return Err(anyhow!("Device code grant not allowed for this client"));
        }

        // Validate and process scopes
        let default_scopes = self.config.default_scopes.join(" ");
        let requested_scopes = scope.unwrap_or(&default_scopes);
        let scopes = crate::oauth2::scopes::utils::parse_scope_string(requested_scopes);
        let validation_result = self.scope_manager.validate_scopes(&scopes);
        if !validation_result.invalid.is_empty() {
            return Err(anyhow!(
                "Invalid scopes: {}",
                validation_result.invalid.join(", ")
            ));
        }
        if !validation_result.conflicts.is_empty() {
            return Err(anyhow!(
                "Scope conflicts: {}",
                validation_result
                    .conflicts
                    .iter()
                    .map(|c| &c.reason)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        // Filter scopes to only include those allowed for the client
        let validated_scopes: Vec<String> = scopes
            .into_iter()
            .filter(|scope| client.allowed_scopes.contains(scope))
            .collect();

        // Generate device code and user code
        let device_code = Uuid::new_v4().to_string();
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
            expires_at: (Utc::now() + Duration::seconds(self.config.device_code_lifetime as i64))
                .into(),
            interval: self.config.device_code_interval,
            user_id: None,
            authorized: false,
        };

        // Store device authorization
        self.service
            .create_device_authorization(device_auth)
            .await?;

        Ok(super::DeviceAuthorizationResponse {
            device_code,
            user_code,
            verification_uri,
            verification_uri_complete,
            expires_in: self.config.device_code_lifetime,
            interval: self.config.device_code_interval,
        })
    }

    /// Handle device code grant
    pub async fn handle_device_code_grant(
        &self,
        device_code: &str,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<TokenResponse> {
        if !self.config.enable_device_flow {
            return Err(anyhow!("Device flow not enabled"));
        }

        // Get and validate device authorization
        let device_auth = self
            .service
            .get_device_authorization_by_device_code(device_code)
            .await?
            .ok_or_else(|| anyhow!("Invalid device code"))?;

        if device_auth.expires_at < Utc::now() {
            return Err(anyhow!("Device code expired"));
        }

        if device_auth.client_id != client_id {
            return Err(anyhow!("Client ID mismatch"));
        }

        if !device_auth.authorized {
            return Err(anyhow!("Authorization pending"));
        }

        // Get and validate client
        let client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow!("Invalid client"))?;

        // Authenticate client
        self.authenticate_client(&client, client_secret).await?;

        let user_id = device_auth
            .user_id
            .as_ref()
            .ok_or_else(|| anyhow!("Device authorization not completed"))?;

        // Generate tokens
        let (access_token, access_token_record) = self.token_manager.generate_access_token(
            user_id,
            client_id,
            &device_auth.scopes,
            None,
            Some(Utc::now().timestamp()),
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
            scope: Some(device_auth.scopes.join(" ")),
            id_token: None,
        };

        // Generate refresh token if enabled
        if self.config.enable_refresh_tokens {
            let (refresh_token, refresh_token_record) = self.token_manager.generate_refresh_token(
                &response.access_token,
                user_id,
                client_id,
                &device_auth.scopes,
                None,
            )?;

            self.service
                .create_refresh_token(refresh_token_record)
                .await?;
            response.refresh_token = Some(refresh_token);
        }

        // Generate ID token if openid scope requested
        if device_auth.scopes.contains(&"openid".to_string()) {
            let id_token = self.token_manager.generate_id_token(
                user_id,
                client_id,
                Utc::now().timestamp(),
                None,
                Some(&response.access_token),
                None,
                None,
            )?;

            response.id_token = Some(id_token);
        }

        Ok(response)
    }

    /// Authenticate device user code
    pub async fn authorize_device_code(&self, user_code: &str, user_id: &str) -> Result<bool> {
        self.service.authorize_device(user_code, user_id).await
    }

    /// Generate authorization code
    async fn generate_authorization_code(
        &self,
        client: &OAuth2Client,
        user_id: &str,
        redirect_uri: &str,
        scopes: &[String],
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
        nonce: Option<&str>,
        state: Option<&str>,
    ) -> Result<String> {
        let code = Uuid::new_v4().to_string();
        let expires_at =
            Utc::now() + Duration::seconds(self.config.authorization_code_lifetime as i64);

        let auth_code = AuthorizationCode {
            code: code.clone(),
            client_id: client.client_id.clone(),
            user_id: user_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scopes: scopes.to_vec(),
            expires_at: expires_at.into(),
            code_challenge: code_challenge.map(|s| s.to_string()),
            code_challenge_method: code_challenge_method.map(|s| s.to_string()),
            nonce: nonce.map(|s| s.to_string()),
            state: state.map(|s| s.to_string()),
            used: false,
        };

        self.service.create_auth_code(auth_code).await?;
        Ok(code)
    }

    /// Authenticate client based on authentication method
    async fn authenticate_client(
        &self,
        client: &OAuth2Client,
        client_secret: Option<&str>,
    ) -> Result<()> {
        if client.is_public {
            // Public clients don't require authentication
            return Ok(());
        }

        // Confidential clients require secret
        let provided_secret = client_secret.ok_or_else(|| anyhow!("Client secret required"))?;
        let expected_secret = client
            .client_secret
            .as_ref()
            .ok_or_else(|| anyhow!("Client secret not configured"))?;

        if provided_secret != expected_secret {
            return Err(anyhow!("Invalid client credentials"));
        }

        Ok(())
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

    /// Cleanup expired authorization codes and tokens
    pub async fn cleanup_expired(&self) -> Result<()> {
        self.service.cleanup_expired_codes().await?;
        self.service.cleanup_expired_tokens().await?;
        self.service.cleanup_expired_device_authorizations().await?;
        Ok(())
    }
}

/// Error response helper
pub fn create_error_response(
    error: OAuth2Error,
    description: Option<String>,
) -> OAuth2ErrorResponse {
    OAuth2ErrorResponse {
        error,
        error_description: description,
        error_uri: None,
        state: None,
    }
}

/// Validate redirect URI format
pub fn validate_redirect_uri(uri: &str) -> Result<()> {
    let parsed = url::Url::parse(uri).map_err(|_| anyhow!("Invalid redirect URI format"))?;

    // Reject fragment identifiers
    if parsed.fragment().is_some() {
        return Err(anyhow!("Redirect URI must not contain fragment"));
    }

    // For security, require HTTPS in production (except localhost)
    if parsed.scheme() != "https" && !parsed.host_str().unwrap_or("").starts_with("localhost") {
        return Err(anyhow!("Redirect URI must use HTTPS"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2::{
        AccessToken, AuthorizationCode, DeviceAuthorization, OAuth2Client, OAuth2Service,
        RefreshToken,
    };
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // Mock OAuth2 service for testing
    #[derive(Clone)]
    struct MockOAuth2Service {
        clients: Arc<Mutex<HashMap<String, OAuth2Client>>>,
        auth_codes: Arc<Mutex<HashMap<String, AuthorizationCode>>>,
        access_tokens: Arc<Mutex<HashMap<String, AccessToken>>>,
        refresh_tokens: Arc<Mutex<HashMap<String, RefreshToken>>>,
        device_auths: Arc<Mutex<HashMap<String, DeviceAuthorization>>>,
    }

    impl MockOAuth2Service {
        fn new() -> Self {
            Self {
                clients: Arc::new(Mutex::new(HashMap::new())),
                auth_codes: Arc::new(Mutex::new(HashMap::new())),
                access_tokens: Arc::new(Mutex::new(HashMap::new())),
                refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
                device_auths: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl OAuth2Service for MockOAuth2Service {
        async fn create_client(&self, client: OAuth2Client) -> Result<OAuth2Client> {
            self.clients
                .lock()
                .unwrap()
                .insert(client.client_id.clone(), client.clone());
            Ok(client)
        }

        async fn get_client(&self, client_id: &str) -> Result<Option<OAuth2Client>> {
            Ok(self.clients.lock().unwrap().get(client_id).cloned())
        }

        async fn update_client(&self, client: OAuth2Client) -> Result<OAuth2Client> {
            self.clients
                .lock()
                .unwrap()
                .insert(client.client_id.clone(), client.clone());
            Ok(client)
        }

        async fn delete_client(&self, client_id: &str) -> Result<bool> {
            Ok(self.clients.lock().unwrap().remove(client_id).is_some())
        }

        async fn list_clients(
            &self,
            _limit: Option<u64>,
            _offset: Option<u64>,
        ) -> Result<Vec<OAuth2Client>> {
            Ok(self.clients.lock().unwrap().values().cloned().collect())
        }

        async fn create_auth_code(&self, code: AuthorizationCode) -> Result<AuthorizationCode> {
            self.auth_codes
                .lock()
                .unwrap()
                .insert(code.code.clone(), code.clone());
            Ok(code)
        }

        async fn get_auth_code(&self, code: &str) -> Result<Option<AuthorizationCode>> {
            Ok(self.auth_codes.lock().unwrap().get(code).cloned())
        }

        async fn use_auth_code(&self, code: &str) -> Result<bool> {
            if let Some(auth_code) = self.auth_codes.lock().unwrap().get_mut(code) {
                auth_code.used = true;
                Ok(true)
            } else {
                Ok(false)
            }
        }

        async fn cleanup_expired_codes(&self) -> Result<u64> {
            Ok(0)
        }

        async fn create_access_token(&self, token: AccessToken) -> Result<AccessToken> {
            self.access_tokens
                .lock()
                .unwrap()
                .insert(token.token.clone(), token.clone());
            Ok(token)
        }

        async fn get_access_token(&self, token: &str) -> Result<Option<AccessToken>> {
            Ok(self.access_tokens.lock().unwrap().get(token).cloned())
        }

        async fn revoke_access_token(&self, token: &str) -> Result<bool> {
            if let Some(access_token) = self.access_tokens.lock().unwrap().get_mut(token) {
                access_token.revoked = true;
                Ok(true)
            } else {
                Ok(false)
            }
        }

        async fn cleanup_expired_tokens(&self) -> Result<u64> {
            Ok(0)
        }

        async fn create_refresh_token(&self, token: RefreshToken) -> Result<RefreshToken> {
            self.refresh_tokens
                .lock()
                .unwrap()
                .insert(token.token.clone(), token.clone());
            Ok(token)
        }

        async fn get_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>> {
            Ok(self.refresh_tokens.lock().unwrap().get(token).cloned())
        }

        async fn use_refresh_token(&self, token: &str) -> Result<bool> {
            if let Some(refresh_token) = self.refresh_tokens.lock().unwrap().get_mut(token) {
                refresh_token.used = true;
                Ok(true)
            } else {
                Ok(false)
            }
        }

        async fn revoke_refresh_token(&self, token: &str) -> Result<bool> {
            Ok(self.refresh_tokens.lock().unwrap().remove(token).is_some())
        }

        async fn create_device_authorization(
            &self,
            auth: DeviceAuthorization,
        ) -> Result<DeviceAuthorization> {
            self.device_auths
                .lock()
                .unwrap()
                .insert(auth.device_code.clone(), auth.clone());
            Ok(auth)
        }

        async fn get_device_authorization_by_device_code(
            &self,
            device_code: &str,
        ) -> Result<Option<DeviceAuthorization>> {
            Ok(self.device_auths.lock().unwrap().get(device_code).cloned())
        }

        async fn get_device_authorization_by_user_code(
            &self,
            user_code: &str,
        ) -> Result<Option<DeviceAuthorization>> {
            Ok(self
                .device_auths
                .lock()
                .unwrap()
                .values()
                .find(|auth| auth.user_code == user_code)
                .cloned())
        }

        async fn authorize_device(&self, user_code: &str, user_id: &str) -> Result<bool> {
            for auth in self.device_auths.lock().unwrap().values_mut() {
                if auth.user_code == user_code {
                    auth.authorized = true;
                    auth.user_id = Some(user_id.to_string());
                    return Ok(true);
                }
            }
            Ok(false)
        }

        async fn cleanup_expired_device_authorizations(&self) -> Result<u64> {
            Ok(0)
        }

        async fn introspect_token(&self, _token: &str) -> Result<super::TokenIntrospection> {
            unimplemented!()
        }

        async fn revoke_all_user_tokens(&self, _user_id: &str) -> Result<u64> {
            Ok(0)
        }

        async fn revoke_all_client_tokens(&self, _client_id: &str) -> Result<u64> {
            Ok(0)
        }

        async fn get_user_tokens(&self, _user_id: &str) -> Result<Vec<AccessToken>> {
            Ok(vec![])
        }

        async fn get_client_tokens(&self, _client_id: &str) -> Result<Vec<AccessToken>> {
            Ok(vec![])
        }
    }

    fn create_test_config() -> OAuth2Config {
        OAuth2Config {
            issuer: "https://test.example.com".to_string(),
            authorization_code_lifetime: 600,
            access_token_lifetime: 3600,
            refresh_token_lifetime: Some(86400),
            enable_refresh_tokens: true,
            enable_client_credentials: true,
            enable_device_flow: true,
            ..Default::default()
        }
    }

    fn create_test_client() -> OAuth2Client {
        OAuth2Client {
            client_id: "test_client".to_string(),
            client_secret: Some("test_secret".to_string()),
            name: "Test Client".to_string(),
            description: None,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            allowed_scopes: vec!["read".to_string(), "write".to_string()],
            allowed_grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::ClientCredentials,
                GrantType::RefreshToken,
                GrantType::DeviceCode,
            ],
            is_public: false,
            logo_uri: None,
            contact_email: None,
            tos_uri: None,
            policy_uri: None,
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            is_active: true,
        }
    }

    #[tokio::test]
    async fn test_validate_redirect_uri() {
        assert!(validate_redirect_uri("https://example.com/callback").is_ok());
        assert!(validate_redirect_uri("http://localhost:3000/callback").is_ok());
        assert!(validate_redirect_uri("https://example.com/callback#fragment").is_err());
        assert!(validate_redirect_uri("http://example.com/callback").is_err());
        assert!(validate_redirect_uri("invalid-uri").is_err());
    }

    #[test]
    fn test_generate_user_code() {
        let service = MockOAuth2Service::new();
        let config = create_test_config();
        let token_manager = super::super::tokens::TokenManager::new(
            config.clone(),
            b"test-secret-key-for-jwt-signing-must-be-long-enough",
            None,
        )
        .unwrap();
        let scope_manager = ScopeManager::new();

        let flow_handler = OAuth2FlowHandler::new(service, config, token_manager, scope_manager);

        let user_code = flow_handler.generate_user_code();
        assert_eq!(user_code.len(), 8);
        assert!(user_code.chars().all(|c| c.is_ascii_alphanumeric()));

        // Should not contain confusing characters
        assert!(!user_code.contains('0'));
        assert!(!user_code.contains('O'));
        assert!(!user_code.contains('I'));
        assert!(!user_code.contains('1'));
    }
}
