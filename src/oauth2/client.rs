use anyhow::{anyhow, Result};
use chrono::Utc;
use regex::Regex;
use std::collections::HashSet;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use super::flows::validate_redirect_uri;
use super::{GrantType, OAuth2Client, OAuth2Service};

/// Client registration request (RFC 7591)
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Validate)]
pub struct ClientRegistrationRequest {
    #[validate(length(min = 1, max = 255))]
    pub client_name: String,

    #[validate(length(max = 1000))]
    pub client_description: Option<String>,

    #[validate(custom(function = "validate_redirect_uris"))]
    pub redirect_uris: Vec<String>,

    #[validate(custom(function = "validate_grant_types"))]
    pub grant_types: Vec<String>,

    #[validate(custom(function = "validate_scopes"))]
    pub scope: Option<String>,

    #[validate(url)]
    pub logo_uri: Option<String>,

    #[validate(email)]
    pub contact_email: Option<String>,

    #[validate(url)]
    pub tos_uri: Option<String>,

    #[validate(url)]
    pub policy_uri: Option<String>,

    pub application_type: Option<String>, // "web" or "native"
    pub token_endpoint_auth_method: Option<String>,
    pub jwks_uri: Option<String>,
    pub jwks: Option<serde_json::Value>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
}

/// Client registration response
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_id_issued_at: i64,
    pub client_secret_expires_at: Option<i64>,
    pub client_name: String,
    pub client_description: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scope: String,
    pub logo_uri: Option<String>,
    pub contact_email: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub application_type: String,
    pub token_endpoint_auth_method: String,
}

/// Client update request
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Validate)]
pub struct ClientUpdateRequest {
    #[validate(length(min = 1, max = 255))]
    pub client_name: Option<String>,

    #[validate(length(max = 1000))]
    pub client_description: Option<String>,

    #[validate(custom(function = "validate_redirect_uris"))]
    pub redirect_uris: Option<Vec<String>>,

    #[validate(custom(function = "validate_grant_types"))]
    pub grant_types: Option<Vec<String>>,

    #[validate(custom(function = "validate_scopes"))]
    pub scope: Option<String>,

    #[validate(url)]
    pub logo_uri: Option<String>,

    #[validate(email)]
    pub contact_email: Option<String>,

    #[validate(url)]
    pub tos_uri: Option<String>,

    #[validate(url)]
    pub policy_uri: Option<String>,

    pub is_active: Option<bool>,
}

/// Client query parameters
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ClientQuery {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub name: Option<String>,
    pub active: Option<bool>,
    pub grant_type: Option<String>,
}

/// OAuth2 client manager
pub struct OAuth2ClientManager<T: OAuth2Service> {
    service: T,
    default_scopes: Vec<String>,
    supported_scopes: Vec<String>,
    supported_grant_types: Vec<GrantType>,
    require_https_redirect: bool,
    max_redirect_uris: usize,
    client_secret_length: usize,
}

impl<T: OAuth2Service> OAuth2ClientManager<T> {
    pub fn new(
        service: T,
        default_scopes: Vec<String>,
        supported_scopes: Vec<String>,
        supported_grant_types: Vec<GrantType>,
        require_https_redirect: bool,
    ) -> Self {
        Self {
            service,
            default_scopes,
            supported_scopes,
            supported_grant_types,
            require_https_redirect,
            max_redirect_uris: 10,
            client_secret_length: 32,
        }
    }

    /// Register a new OAuth2 client
    pub async fn register_client(
        &self,
        request: ClientRegistrationRequest,
    ) -> Result<ClientRegistrationResponse> {
        // Validate request
        request
            .validate()
            .map_err(|e| anyhow!("Validation error: {}", e))?;

        // Generate client credentials
        let client_id = self.generate_client_id();
        let client_secret = if self.requires_client_secret(&request) {
            Some(self.generate_client_secret())
        } else {
            None
        };

        // Determine application type
        let application_type = request
            .application_type
            .clone()
            .unwrap_or_else(|| self.infer_application_type(&request.redirect_uris));

        let is_public = application_type == "native" || client_secret.is_none();

        // Parse and validate scopes
        let scopes = self.parse_and_validate_scopes(request.scope.as_deref())?;

        // Parse and validate grant types
        let grant_types = self.parse_and_validate_grant_types(&request.grant_types)?;

        // Determine token endpoint auth method
        let token_endpoint_auth_method =
            request
                .token_endpoint_auth_method
                .clone()
                .unwrap_or_else(|| {
                    if is_public {
                        "none".to_string()
                    } else {
                        "client_secret_basic".to_string()
                    }
                });

        // Create client record
        let client = OAuth2Client {
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            name: request.client_name.clone(),
            description: request.client_description.clone(),
            redirect_uris: request.redirect_uris.clone(),
            allowed_scopes: scopes.clone(),
            allowed_grant_types: grant_types.clone(),
            is_public,
            logo_uri: request.logo_uri.clone(),
            contact_email: request.contact_email.clone(),
            tos_uri: request.tos_uri.clone(),
            policy_uri: request.policy_uri.clone(),
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            is_active: true,
        };

        // Store client
        let stored_client = self.service.create_client(client).await?;

        // Return registration response
        Ok(ClientRegistrationResponse {
            client_id,
            client_secret,
            client_id_issued_at: stored_client.created_at.timestamp(),
            client_secret_expires_at: None, // We don't expire client secrets
            client_name: request.client_name,
            client_description: request.client_description,
            redirect_uris: request.redirect_uris,
            grant_types: request.grant_types,
            scope: scopes.join(" "),
            logo_uri: request.logo_uri,
            contact_email: request.contact_email,
            tos_uri: request.tos_uri,
            policy_uri: request.policy_uri,
            application_type,
            token_endpoint_auth_method,
        })
    }

    /// Get a client by ID
    pub async fn get_client(&self, client_id: &str) -> Result<Option<OAuth2Client>> {
        self.service.get_client(client_id).await
    }

    /// Update an existing client
    pub async fn update_client(
        &self,
        client_id: &str,
        request: ClientUpdateRequest,
    ) -> Result<OAuth2Client> {
        // Validate request
        request
            .validate()
            .map_err(|e| anyhow!("Validation error: {}", e))?;

        // Get existing client
        let mut client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow!("Client not found"))?;

        // Update fields
        if let Some(name) = request.client_name {
            client.name = name;
        }

        if let Some(description) = request.client_description {
            client.description = Some(description);
        }

        if let Some(redirect_uris) = request.redirect_uris {
            client.redirect_uris = redirect_uris;
        }

        if let Some(grant_types) = request.grant_types {
            client.allowed_grant_types = self.parse_and_validate_grant_types(&grant_types)?;
        }

        if let Some(scope) = request.scope {
            client.allowed_scopes = self.parse_and_validate_scopes(Some(&scope))?;
        }

        if let Some(logo_uri) = request.logo_uri {
            client.logo_uri = Some(logo_uri);
        }

        if let Some(contact_email) = request.contact_email {
            client.contact_email = Some(contact_email);
        }

        if let Some(tos_uri) = request.tos_uri {
            client.tos_uri = Some(tos_uri);
        }

        if let Some(policy_uri) = request.policy_uri {
            client.policy_uri = Some(policy_uri);
        }

        if let Some(is_active) = request.is_active {
            client.is_active = is_active;
        }

        client.updated_at = Utc::now().into();

        // Update client
        self.service.update_client(client).await
    }

    /// Delete a client
    pub async fn delete_client(&self, client_id: &str) -> Result<bool> {
        // Revoke all client tokens before deletion
        self.service.revoke_all_client_tokens(client_id).await?;

        // Delete client
        self.service.delete_client(client_id).await
    }

    /// List clients with filtering
    pub async fn list_clients(&self, query: ClientQuery) -> Result<Vec<OAuth2Client>> {
        let clients = self.service.list_clients(query.limit, query.offset).await?;

        // Apply filters
        let filtered_clients: Vec<OAuth2Client> = clients
            .into_iter()
            .filter(|client| {
                // Filter by name
                if let Some(ref name_filter) = query.name {
                    if !client
                        .name
                        .to_lowercase()
                        .contains(&name_filter.to_lowercase())
                    {
                        return false;
                    }
                }

                // Filter by active status
                if let Some(active_filter) = query.active {
                    if client.is_active != active_filter {
                        return false;
                    }
                }

                // Filter by grant type
                if let Some(ref grant_type_filter) = query.grant_type {
                    if let Ok(grant_type) = self.parse_grant_type(grant_type_filter) {
                        if !client.allowed_grant_types.contains(&grant_type) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }

                true
            })
            .collect();

        Ok(filtered_clients)
    }

    /// Regenerate client secret
    pub async fn regenerate_client_secret(&self, client_id: &str) -> Result<String> {
        let mut client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow!("Client not found"))?;

        if client.is_public {
            return Err(anyhow!("Cannot regenerate secret for public client"));
        }

        let new_secret = self.generate_client_secret();
        client.client_secret = Some(new_secret.clone());
        client.updated_at = Utc::now().into();

        self.service.update_client(client).await?;
        Ok(new_secret)
    }

    /// Activate/deactivate a client
    pub async fn set_client_status(&self, client_id: &str, active: bool) -> Result<OAuth2Client> {
        let mut client = self
            .service
            .get_client(client_id)
            .await?
            .ok_or_else(|| anyhow!("Client not found"))?;

        client.is_active = active;
        client.updated_at = Utc::now().into();

        // If deactivating, revoke all tokens
        if !active {
            self.service.revoke_all_client_tokens(client_id).await?;
        }

        self.service.update_client(client).await
    }

    /// Validate client for specific grant type
    pub fn validate_client_for_grant_type(
        &self,
        client: &OAuth2Client,
        grant_type: &GrantType,
    ) -> Result<()> {
        if !client.is_active {
            return Err(anyhow!("Client is not active"));
        }

        if !client.allowed_grant_types.contains(grant_type) {
            return Err(anyhow!("Grant type not allowed for this client"));
        }

        Ok(())
    }

    /// Generate client ID
    fn generate_client_id(&self) -> String {
        format!("client_{}", Uuid::new_v4().simple())
    }

    /// Generate client secret
    fn generate_client_secret(&self) -> String {
        use rand::Rng;

        let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut rng = rand::thread_rng();

        (0..self.client_secret_length)
            .map(|_| {
                let idx = rng.gen_range(0..charset.len());
                charset[idx] as char
            })
            .collect()
    }

    /// Determine if client requires secret
    fn requires_client_secret(&self, request: &ClientRegistrationRequest) -> bool {
        // Native applications are typically public clients
        let application_type = request.application_type.as_deref().unwrap_or("web");
        application_type == "web"
    }

    /// Infer application type from redirect URIs
    fn infer_application_type(&self, redirect_uris: &[String]) -> String {
        for uri in redirect_uris {
            if uri.starts_with("http://localhost")
                || uri.starts_with("http://127.0.0.1")
                || uri.starts_with("urn:")
                || uri.contains("://localhost")
            {
                return "native".to_string();
            }
        }
        "web".to_string()
    }

    /// Parse and validate scopes
    fn parse_and_validate_scopes(&self, scope: Option<&str>) -> Result<Vec<String>> {
        let scopes = if let Some(scope_str) = scope {
            scope_str
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        } else {
            self.default_scopes.clone()
        };

        // Validate each scope
        for scope in &scopes {
            if !self.supported_scopes.contains(scope) {
                return Err(anyhow!("Unsupported scope: {}", scope));
            }
        }

        Ok(scopes)
    }

    /// Parse and validate grant types
    fn parse_and_validate_grant_types(&self, grant_types: &[String]) -> Result<Vec<GrantType>> {
        let mut parsed_types = Vec::new();

        for grant_type_str in grant_types {
            let grant_type = self.parse_grant_type(grant_type_str)?;

            if !self.supported_grant_types.contains(&grant_type) {
                return Err(anyhow!("Unsupported grant type: {}", grant_type_str));
            }

            parsed_types.push(grant_type);
        }

        if parsed_types.is_empty() {
            return Err(anyhow!("At least one grant type must be specified"));
        }

        Ok(parsed_types)
    }

    /// Parse grant type string
    fn parse_grant_type(&self, grant_type: &str) -> Result<GrantType> {
        match grant_type {
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            "client_credentials" => Ok(GrantType::ClientCredentials),
            "refresh_token" => Ok(GrantType::RefreshToken),
            "implicit" => Ok(GrantType::Implicit),
            "urn:ietf:params:oauth:grant-type:device_code" => Ok(GrantType::DeviceCode),
            _ => Err(anyhow!("Invalid grant type: {}", grant_type)),
        }
    }
}

/// Validation functions
fn validate_redirect_uris(redirect_uris: &[String]) -> Result<(), ValidationError> {
    if redirect_uris.is_empty() {
        return Err(ValidationError::new(
            "At least one redirect URI is required",
        ));
    }

    if redirect_uris.len() > 10 {
        return Err(ValidationError::new("Too many redirect URIs (max 10)"));
    }

    // Check for duplicates
    let mut seen = HashSet::new();
    for uri in redirect_uris {
        if !seen.insert(uri) {
            return Err(ValidationError::new("Duplicate redirect URIs not allowed"));
        }

        // Validate URI format
        if let Err(_e) = validate_redirect_uri(uri) {
            return Err(ValidationError::new("Invalid redirect URI format"));
        }
    }

    Ok(())
}

fn validate_grant_types(grant_types: &[String]) -> Result<(), ValidationError> {
    if grant_types.is_empty() {
        return Err(ValidationError::new("At least one grant type is required"));
    }

    let valid_grant_types = [
        "authorization_code",
        "client_credentials",
        "refresh_token",
        "implicit",
        "urn:ietf:params:oauth:grant-type:device_code",
    ];

    for grant_type in grant_types {
        if !valid_grant_types.contains(&grant_type.as_str()) {
            return Err(ValidationError::new("Invalid grant type"));
        }
    }

    Ok(())
}

fn validate_scopes(scopes: &String) -> Result<(), ValidationError> {
    // Basic scope validation - no control characters
    let scope_regex = Regex::new(r"^[a-zA-Z0-9:/_-]+( [a-zA-Z0-9:/_-]+)*$").unwrap();
    if !scope_regex.is_match(scopes) {
        return Err(ValidationError::new("Invalid scope format"));
    }

    // Check scope length
    if scopes.len() > 1000 {
        return Err(ValidationError::new("Scope string too long"));
    }

    Ok(())
}

/// Client statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClientStatistics {
    pub total_clients: u64,
    pub active_clients: u64,
    pub public_clients: u64,
    pub confidential_clients: u64,
    pub clients_by_grant_type: std::collections::HashMap<String, u64>,
}

impl<T: OAuth2Service> OAuth2ClientManager<T> {
    /// Get client statistics
    pub async fn get_client_statistics(&self) -> Result<ClientStatistics> {
        let clients = self.service.list_clients(None, None).await?;

        let total_clients = clients.len() as u64;
        let active_clients = clients.iter().filter(|c| c.is_active).count() as u64;
        let public_clients = clients.iter().filter(|c| c.is_public).count() as u64;
        let confidential_clients = total_clients - public_clients;

        let mut clients_by_grant_type = std::collections::HashMap::new();
        for client in &clients {
            for grant_type in &client.allowed_grant_types {
                let grant_type_str = match grant_type {
                    GrantType::AuthorizationCode => "authorization_code",
                    GrantType::ClientCredentials => "client_credentials",
                    GrantType::RefreshToken => "refresh_token",
                    GrantType::Implicit => "implicit",
                    GrantType::DeviceCode => "device_code",
                };
                *clients_by_grant_type
                    .entry(grant_type_str.to_string())
                    .or_insert(0) += 1;
            }
        }

        Ok(ClientStatistics {
            total_clients,
            active_clients,
            public_clients,
            confidential_clients,
            clients_by_grant_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2::OAuth2Service;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // Mock OAuth2 service for testing
    #[derive(Clone)]
    struct MockOAuth2Service {
        clients: Arc<Mutex<HashMap<String, OAuth2Client>>>,
    }

    impl MockOAuth2Service {
        fn new() -> Self {
            Self {
                clients: Arc::new(Mutex::new(HashMap::new())),
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

        // Other methods not needed for client tests
        async fn create_auth_code(
            &self,
            _code: super::AuthorizationCode,
        ) -> Result<super::AuthorizationCode> {
            unimplemented!()
        }
        async fn get_auth_code(&self, _code: &str) -> Result<Option<super::AuthorizationCode>> {
            unimplemented!()
        }
        async fn use_auth_code(&self, _code: &str) -> Result<bool> {
            unimplemented!()
        }
        async fn cleanup_expired_codes(&self) -> Result<u64> {
            unimplemented!()
        }
        async fn create_access_token(
            &self,
            _token: super::AccessToken,
        ) -> Result<super::AccessToken> {
            unimplemented!()
        }
        async fn get_access_token(&self, _token: &str) -> Result<Option<super::AccessToken>> {
            unimplemented!()
        }
        async fn revoke_access_token(&self, _token: &str) -> Result<bool> {
            Ok(true)
        }
        async fn cleanup_expired_tokens(&self) -> Result<u64> {
            unimplemented!()
        }
        async fn create_refresh_token(
            &self,
            _token: super::RefreshToken,
        ) -> Result<super::RefreshToken> {
            unimplemented!()
        }
        async fn get_refresh_token(&self, _token: &str) -> Result<Option<super::RefreshToken>> {
            unimplemented!()
        }
        async fn use_refresh_token(&self, _token: &str) -> Result<bool> {
            unimplemented!()
        }
        async fn revoke_refresh_token(&self, _token: &str) -> Result<bool> {
            unimplemented!()
        }
        async fn create_device_authorization(
            &self,
            _auth: super::DeviceAuthorization,
        ) -> Result<super::DeviceAuthorization> {
            unimplemented!()
        }
        async fn get_device_authorization_by_device_code(
            &self,
            _device_code: &str,
        ) -> Result<Option<super::DeviceAuthorization>> {
            unimplemented!()
        }
        async fn get_device_authorization_by_user_code(
            &self,
            _user_code: &str,
        ) -> Result<Option<super::DeviceAuthorization>> {
            unimplemented!()
        }
        async fn authorize_device(&self, _user_code: &str, _user_id: &str) -> Result<bool> {
            unimplemented!()
        }
        async fn cleanup_expired_device_authorizations(&self) -> Result<u64> {
            unimplemented!()
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
        async fn get_user_tokens(&self, _user_id: &str) -> Result<Vec<super::AccessToken>> {
            unimplemented!()
        }
        async fn get_client_tokens(&self, _client_id: &str) -> Result<Vec<super::AccessToken>> {
            unimplemented!()
        }
    }

    fn create_test_client_manager() -> OAuth2ClientManager<MockOAuth2Service> {
        let service = MockOAuth2Service::new();
        let default_scopes = vec!["read".to_string()];
        let supported_scopes = vec!["read".to_string(), "write".to_string(), "admin".to_string()];
        let supported_grant_types = vec![
            GrantType::AuthorizationCode,
            GrantType::ClientCredentials,
            GrantType::RefreshToken,
        ];

        OAuth2ClientManager::new(
            service,
            default_scopes,
            supported_scopes,
            supported_grant_types,
            true,
        )
    }

    #[tokio::test]
    async fn test_register_client() {
        let manager = create_test_client_manager();

        let request = ClientRegistrationRequest {
            client_name: "Test App".to_string(),
            client_description: Some("A test application".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            scope: Some("read write".to_string()),
            logo_uri: None,
            contact_email: Some("test@example.com".to_string()),
            tos_uri: None,
            policy_uri: None,
            application_type: Some("web".to_string()),
            token_endpoint_auth_method: None,
            jwks_uri: None,
            jwks: None,
            software_id: None,
            software_version: None,
        };

        let response = manager.register_client(request).unwrap();

        assert!(response.client_id.starts_with("client_"));
        assert!(response.client_secret.is_some());
        assert_eq!(response.client_name, "Test App");
        assert_eq!(response.scope, "read write");
        assert_eq!(response.application_type, "web");
        assert_eq!(response.token_endpoint_auth_method, "client_secret_basic");
    }

    #[tokio::test]
    async fn test_register_native_client() {
        let manager = create_test_client_manager();

        let request = ClientRegistrationRequest {
            client_name: "Mobile App".to_string(),
            client_description: None,
            redirect_uris: vec!["http://localhost:3000/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            scope: None,
            logo_uri: None,
            contact_email: None,
            tos_uri: None,
            policy_uri: None,
            application_type: Some("native".to_string()),
            token_endpoint_auth_method: None,
            jwks_uri: None,
            jwks: None,
            software_id: None,
            software_version: None,
        };

        let response = manager.register_client(request).unwrap();

        assert!(response.client_secret.is_none()); // Native clients are public
        assert_eq!(response.application_type, "native");
        assert_eq!(response.token_endpoint_auth_method, "none");
        assert_eq!(response.scope, "read"); // Default scope
    }

    #[test]
    fn test_validate_redirect_uris() {
        // Valid URIs
        assert!(validate_redirect_uris(&vec!["https://example.com/callback".to_string()]).is_ok());
        assert!(
            validate_redirect_uris(&vec!["http://localhost:3000/callback".to_string()]).is_ok()
        );

        // Invalid cases
        assert!(validate_redirect_uris(&vec![]).is_err()); // Empty
        assert!(validate_redirect_uris(&vec!["invalid-uri".to_string()]).is_err()); // Invalid format
        assert!(validate_redirect_uris(&vec![
            "https://example.com/callback".to_string(),
            "https://example.com/callback".to_string()
        ])
        .is_err()); // Duplicates
    }

    #[test]
    fn test_validate_grant_types() {
        // Valid grant types
        assert!(validate_grant_types(&vec!["authorization_code".to_string()]).is_ok());
        assert!(validate_grant_types(&vec![
            "client_credentials".to_string(),
            "refresh_token".to_string()
        ])
        .is_ok());

        // Invalid cases
        assert!(validate_grant_types(&vec![]).is_err()); // Empty
        assert!(validate_grant_types(&vec!["invalid_grant".to_string()]).is_err());
        // Invalid grant type
    }

    #[test]
    fn test_validate_scopes() {
        // Valid scopes
        assert!(validate_scopes(&Some("read write".to_string())).is_ok());
        assert!(validate_scopes(&Some("openid profile email".to_string())).is_ok());
        assert!(validate_scopes(&None).is_ok());

        // Invalid cases
        assert!(validate_scopes(&Some("invalid@scope".to_string())).is_err()); // Invalid characters
        assert!(validate_scopes(&Some("a".repeat(1001))).is_err()); // Too long
    }
}
