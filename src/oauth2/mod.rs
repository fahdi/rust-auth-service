use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub mod client;
pub mod flows;
pub mod pkce;
pub mod scopes;
pub mod server;
pub mod tokens;

/// OAuth2 grant types supported by the server
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
    Implicit,
    DeviceCode,
}

/// OAuth2 response types for authorization endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    Code,
    Token,
    IdToken,
    #[serde(rename = "code token")]
    CodeToken,
    #[serde(rename = "code id_token")]
    CodeIdToken,
}

/// OAuth2 client application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Client {
    pub client_id: String,
    pub client_secret: Option<String>, // None for public clients
    pub name: String,
    pub description: Option<String>,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_grant_types: Vec<GrantType>,
    pub is_public: bool, // PKCE required for public clients
    pub logo_uri: Option<String>,
    pub contact_email: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

/// OAuth2 authorization code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>, // For OpenID Connect
    pub state: Option<String>,
    pub used: bool,
}

/// OAuth2 access token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub token: String,
    pub token_type: String, // "Bearer"
    pub client_id: String,
    pub user_id: Option<String>, // None for client credentials
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

/// OAuth2 refresh token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub token: String,
    pub access_token: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>, // None = never expires
    pub created_at: DateTime<Utc>,
    pub used: bool,
}

/// OAuth2 device authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub interval: u32,           // Polling interval in seconds
    pub user_id: Option<String>, // Set when user authorizes
    pub authorized: bool,
}

/// Token introspection response (RFC 7662)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIntrospection {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
}

/// OAuth2 error responses (RFC 6749)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2Error {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    AccessDenied,
    UnsupportedResponseType,
    ServerError,
    TemporarilyUnavailable,
    // OpenID Connect specific errors
    InteractionRequired,
    LoginRequired,
    AccountSelectionRequired,
    ConsentRequired,
    InvalidRequestUri,
    InvalidRequestObject,
    RequestNotSupported,
    RequestUriNotSupported,
    RegistrationNotSupported,
}

/// OAuth2 error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2ErrorResponse {
    pub error: OAuth2Error,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
    pub state: Option<String>,
}

/// OAuth2 token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>, // OpenID Connect
}

/// Authorization request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,         // OpenID Connect
    pub prompt: Option<String>,        // OpenID Connect
    pub max_age: Option<u64>,          // OpenID Connect
    pub id_token_hint: Option<String>, // OpenID Connect
    pub login_hint: Option<String>,    // OpenID Connect
}

/// Token request parameters
#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>, // PKCE
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub username: Option<String>, // Resource owner password credentials
    pub password: Option<String>, // Resource owner password credentials
}

/// Device authorization request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationRequest {
    pub client_id: String,
    pub scope: Option<String>,
}

/// Device authorization response
#[derive(Debug, Clone, Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u32,
}

/// Client credentials for authentication
#[derive(Debug, Clone)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub auth_method: ClientAuthMethod,
}

/// Client authentication methods
#[derive(Debug, Clone, PartialEq)]
pub enum ClientAuthMethod {
    ClientSecretBasic, // HTTP Basic Auth
    ClientSecretPost,  // POST parameters
    ClientSecretJwt,   // JWT assertion
    PrivateKeyJwt,     // JWT with private key
    None,              // Public clients
}

/// OAuth2 configuration/metadata (RFC 8414)
#[derive(Debug, Clone, Serialize)]
pub struct OAuth2Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub registration_endpoint: Option<String>,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    pub service_documentation: Option<String>,
    pub ui_locales_supported: Vec<String>,
    pub op_policy_uri: Option<String>,
    pub op_tos_uri: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    pub introspection_endpoint: Option<String>,
    pub introspection_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    // OpenID Connect specific
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
}

impl Default for OAuth2Metadata {
    fn default() -> Self {
        Self {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/oauth2/authorize".to_string(),
            token_endpoint: "https://auth.example.com/oauth2/token".to_string(),
            userinfo_endpoint: Some("https://auth.example.com/oauth2/userinfo".to_string()),
            jwks_uri: Some("https://auth.example.com/.well-known/jwks.json".to_string()),
            registration_endpoint: Some("https://auth.example.com/oauth2/register".to_string()),
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "read".to_string(),
                "write".to_string(),
            ],
            response_types_supported: vec![
                "code".to_string(),
                "token".to_string(),
                "id_token".to_string(),
                "code token".to_string(),
                "code id_token".to_string(),
            ],
            response_modes_supported: vec![
                "query".to_string(),
                "fragment".to_string(),
                "form_post".to_string(),
            ],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
                "refresh_token".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "client_secret_jwt".to_string(),
                "private_key_jwt".to_string(),
                "none".to_string(),
            ],
            token_endpoint_auth_signing_alg_values_supported: vec![
                "HS256".to_string(),
                "RS256".to_string(),
                "ES256".to_string(),
            ],
            service_documentation: Some("https://docs.example.com/oauth2".to_string()),
            ui_locales_supported: vec!["en".to_string(), "es".to_string(), "fr".to_string()],
            op_policy_uri: Some("https://example.com/privacy".to_string()),
            op_tos_uri: Some("https://example.com/terms".to_string()),
            revocation_endpoint: Some("https://auth.example.com/oauth2/revoke".to_string()),
            revocation_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "none".to_string(),
            ],
            introspection_endpoint: Some("https://auth.example.com/oauth2/introspect".to_string()),
            introspection_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
            ],
            code_challenge_methods_supported: vec!["plain".to_string(), "S256".to_string()],
            subject_types_supported: vec!["public".to_string(), "pairwise".to_string()],
            id_token_signing_alg_values_supported: vec![
                "RS256".to_string(),
                "ES256".to_string(),
                "HS256".to_string(),
            ],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "auth_time".to_string(),
                "nonce".to_string(),
                "email".to_string(),
                "email_verified".to_string(),
                "name".to_string(),
                "given_name".to_string(),
                "family_name".to_string(),
                "picture".to_string(),
            ],
            request_parameter_supported: true,
            request_uri_parameter_supported: false,
        }
    }
}

/// OAuth2 service trait for database operations
#[async_trait::async_trait]
pub trait OAuth2Service: Send + Sync {
    // Client management
    async fn create_client(&self, client: OAuth2Client) -> Result<OAuth2Client>;
    async fn get_client(&self, client_id: &str) -> Result<Option<OAuth2Client>>;
    async fn update_client(&self, client: OAuth2Client) -> Result<OAuth2Client>;
    async fn delete_client(&self, client_id: &str) -> Result<bool>;
    async fn list_clients(
        &self,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> Result<Vec<OAuth2Client>>;

    // Authorization codes
    async fn create_auth_code(&self, code: AuthorizationCode) -> Result<AuthorizationCode>;
    async fn get_auth_code(&self, code: &str) -> Result<Option<AuthorizationCode>>;
    async fn use_auth_code(&self, code: &str) -> Result<bool>;
    async fn cleanup_expired_codes(&self) -> Result<u64>;

    // Access tokens
    async fn create_access_token(&self, token: AccessToken) -> Result<AccessToken>;
    async fn get_access_token(&self, token: &str) -> Result<Option<AccessToken>>;
    async fn revoke_access_token(&self, token: &str) -> Result<bool>;
    async fn cleanup_expired_tokens(&self) -> Result<u64>;

    // Refresh tokens
    async fn create_refresh_token(&self, token: RefreshToken) -> Result<RefreshToken>;
    async fn get_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>>;
    async fn use_refresh_token(&self, token: &str) -> Result<bool>;
    async fn revoke_refresh_token(&self, token: &str) -> Result<bool>;

    // Device authorization
    async fn create_device_authorization(
        &self,
        auth: DeviceAuthorization,
    ) -> Result<DeviceAuthorization>;
    async fn get_device_authorization_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorization>>;
    async fn get_device_authorization_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceAuthorization>>;
    async fn authorize_device(&self, user_code: &str, user_id: &str) -> Result<bool>;
    async fn cleanup_expired_device_authorizations(&self) -> Result<u64>;

    // Token introspection
    async fn introspect_token(&self, token: &str) -> Result<TokenIntrospection>;

    // Utility methods
    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<u64>;
    async fn revoke_all_client_tokens(&self, client_id: &str) -> Result<u64>;
    async fn get_user_tokens(&self, user_id: &str) -> Result<Vec<AccessToken>>;
    async fn get_client_tokens(&self, client_id: &str) -> Result<Vec<AccessToken>>;
}

/// OAuth2 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Config {
    pub issuer: String,
    pub base_url: String,
    pub authorization_code_lifetime: u64,    // seconds
    pub access_token_lifetime: u64,          // seconds
    pub refresh_token_lifetime: Option<u64>, // seconds, None = never expires
    pub device_code_lifetime: u64,           // seconds
    pub device_code_interval: u32,           // polling interval
    pub require_pkce: bool,                  // require PKCE for all clients
    pub enforce_redirect_uri: bool,          // strict redirect URI validation
    pub supported_scopes: Vec<String>,
    pub default_scopes: Vec<String>,
    pub enable_device_flow: bool,
    pub enable_client_credentials: bool,
    pub enable_refresh_tokens: bool,
    pub jwt_signing_algorithm: String,   // RS256, ES256, HS256
    pub jwt_signing_key: Option<String>, // for HMAC algorithms
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            issuer: "https://auth.example.com".to_string(),
            base_url: "https://auth.example.com".to_string(),
            authorization_code_lifetime: 600,     // 10 minutes
            access_token_lifetime: 3600,          // 1 hour
            refresh_token_lifetime: Some(604800), // 7 days
            device_code_lifetime: 600,            // 10 minutes
            device_code_interval: 5,              // 5 seconds
            require_pkce: true,
            enforce_redirect_uri: true,
            supported_scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "read".to_string(),
                "write".to_string(),
                "admin".to_string(),
            ],
            default_scopes: vec!["read".to_string()],
            enable_device_flow: true,
            enable_client_credentials: true,
            enable_refresh_tokens: true,
            jwt_signing_algorithm: "RS256".to_string(),
            jwt_signing_key: None,
        }
    }
}
