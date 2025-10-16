use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod discord;
pub mod github;
pub mod google;

/// Social login provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SocialProvider {
    Google,
    GitHub,
    Discord,
    Facebook,
    Twitter,
    Microsoft,
    Apple,
}

/// Social login configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialConfig {
    pub provider: SocialProvider,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub enabled: bool,
}

/// Social user profile information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialUserProfile {
    pub provider: SocialProvider,
    pub provider_user_id: String,
    pub email: String,
    pub name: String,
    pub avatar_url: Option<String>,
    pub username: Option<String>,
    pub verified_email: bool,
    pub raw_profile: serde_json::Value,
}

/// Social login authorization URL response
#[derive(Debug, Serialize, Deserialize)]
pub struct SocialAuthUrl {
    pub provider: SocialProvider,
    pub authorization_url: String,
    pub state: String,
    pub pkce_verifier: Option<String>,
}

/// Social login callback request
#[derive(Debug, Deserialize)]
pub struct SocialCallbackRequest {
    pub code: String,
    pub state: String,
    pub provider: SocialProvider,
}

/// Social login result
#[derive(Debug, Serialize, Deserialize)]
pub struct SocialLoginResult {
    pub user_profile: SocialUserProfile,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

/// Trait for social login providers
#[async_trait::async_trait]
pub trait SocialLoginProvider: Send + Sync {
    /// Get the provider type
    fn provider_type(&self) -> SocialProvider;

    /// Generate authorization URL for OAuth flow
    async fn get_authorization_url(&self, state: &str) -> Result<SocialAuthUrl>;

    /// Exchange authorization code for access token and user profile
    async fn exchange_code(&self, code: &str, state: &str) -> Result<SocialLoginResult>;

    /// Get user profile using access token
    async fn get_user_profile(&self, access_token: &str) -> Result<SocialUserProfile>;

    /// Refresh access token if supported
    async fn refresh_token(&self, refresh_token: &str) -> Result<SocialLoginResult>;

    /// Validate the provider configuration
    fn validate_config(&self) -> Result<()>;
}

/// Social login manager
pub struct SocialLoginManager {
    providers: HashMap<SocialProvider, Box<dyn SocialLoginProvider>>,
    http_client: reqwest::Client,
}

impl SocialLoginManager {
    /// Create new social login manager
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            http_client: reqwest::Client::new(),
        }
    }

    /// Add a social login provider
    pub fn add_provider(&mut self, provider: Box<dyn SocialLoginProvider>) -> Result<()> {
        provider.validate_config()?;
        let provider_type = provider.provider_type();
        self.providers.insert(provider_type, provider);
        Ok(())
    }

    /// Get available providers
    pub fn get_available_providers(&self) -> Vec<SocialProvider> {
        self.providers.keys().cloned().collect()
    }

    /// Check if provider is available
    pub fn is_provider_available(&self, provider: &SocialProvider) -> bool {
        self.providers.contains_key(provider)
    }

    /// Get authorization URL for a provider
    pub async fn get_authorization_url(
        &self,
        provider: &SocialProvider,
        state: &str,
    ) -> Result<SocialAuthUrl> {
        let provider_impl = self
            .providers
            .get(provider)
            .ok_or_else(|| anyhow::anyhow!("Provider {:?} not configured", provider))?;

        provider_impl.get_authorization_url(state).await
    }

    /// Handle OAuth callback
    pub async fn handle_callback(
        &self,
        request: SocialCallbackRequest,
    ) -> Result<SocialLoginResult> {
        let provider_impl = self
            .providers
            .get(&request.provider)
            .ok_or_else(|| anyhow::anyhow!("Provider {:?} not configured", request.provider))?;

        provider_impl
            .exchange_code(&request.code, &request.state)
            .await
    }

    /// Get user profile from provider
    pub async fn get_user_profile(
        &self,
        provider: &SocialProvider,
        access_token: &str,
    ) -> Result<SocialUserProfile> {
        let provider_impl = self
            .providers
            .get(provider)
            .ok_or_else(|| anyhow::anyhow!("Provider {:?} not configured", provider))?;

        provider_impl.get_user_profile(access_token).await
    }

    /// Refresh token for a provider
    pub async fn refresh_token(
        &self,
        provider: &SocialProvider,
        refresh_token: &str,
    ) -> Result<SocialLoginResult> {
        let provider_impl = self
            .providers
            .get(provider)
            .ok_or_else(|| anyhow::anyhow!("Provider {:?} not configured", provider))?;

        provider_impl.refresh_token(refresh_token).await
    }

    /// Get HTTP client for providers to use
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }
}

impl Default for SocialLoginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate secure random state for OAuth flow
pub fn generate_state() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    URL_SAFE_NO_PAD.encode(random_bytes)
}

/// Validate OAuth state parameter
pub fn validate_state(expected: &str, received: &str) -> bool {
    expected == received
}

/// Extract email from social profile with fallback
pub fn extract_primary_email(profile: &SocialUserProfile) -> Option<String> {
    if !profile.email.is_empty() {
        Some(profile.email.clone())
    } else {
        // Try to extract from raw profile data
        profile
            .raw_profile
            .get("email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

/// Generate username from social profile
pub fn generate_username_from_profile(profile: &SocialUserProfile) -> String {
    // Try username first
    if let Some(username) = &profile.username {
        if !username.is_empty() {
            return username.clone();
        }
    }

    // Try extracting from email
    if !profile.email.is_empty() {
        if let Some(local_part) = profile.email.split('@').next() {
            return local_part.to_string();
        }
    }

    // Try extracting from name
    if !profile.name.is_empty() {
        return profile
            .name
            .to_lowercase()
            .replace([' ', '.', '-'], "_")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect();
    }

    // Fallback to provider + user ID
    format!(
        "{}_{}",
        format!("{:?}", profile.provider).to_lowercase(),
        profile.provider_user_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_state() {
        let state1 = generate_state();
        let state2 = generate_state();

        assert_ne!(state1, state2);
        assert!(state1.len() > 10);
        assert!(state2.len() > 10);
    }

    #[test]
    fn test_validate_state() {
        let state = "test_state_123";
        assert!(validate_state(state, state));
        assert!(!validate_state(state, "different_state"));
    }

    #[test]
    fn test_generate_username_from_profile() {
        let profile = SocialUserProfile {
            provider: SocialProvider::GitHub,
            provider_user_id: "12345".to_string(),
            email: "user@example.com".to_string(),
            name: "Test User".to_string(),
            avatar_url: None,
            username: Some("testuser".to_string()),
            verified_email: true,
            raw_profile: serde_json::json!({}),
        };

        assert_eq!(generate_username_from_profile(&profile), "testuser");

        let profile_no_username = SocialUserProfile {
            username: None,
            ..profile.clone()
        };

        assert_eq!(generate_username_from_profile(&profile_no_username), "user");

        let profile_no_email = SocialUserProfile {
            username: None,
            email: "".to_string(),
            ..profile.clone()
        };

        assert_eq!(
            generate_username_from_profile(&profile_no_email),
            "test_user"
        );
    }
}
