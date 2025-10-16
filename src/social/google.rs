use super::{
    SocialAuthUrl, SocialConfig, SocialLoginProvider, SocialLoginResult, SocialProvider,
    SocialUserProfile,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Google OAuth2 configuration
#[derive(Debug, Clone)]
pub struct GoogleProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: Vec<String>,
    http_client: reqwest::Client,
}

/// Google OAuth2 token response
#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    token_type: String,
}

/// Google user profile response
#[derive(Debug, Serialize, Deserialize)]
struct GoogleUserInfo {
    id: String,
    email: String,
    verified_email: bool,
    name: String,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
    locale: Option<String>,
}

impl GoogleProvider {
    /// Create new Google provider
    pub fn new(config: SocialConfig) -> Result<Self> {
        if config.provider != SocialProvider::Google {
            return Err(anyhow::anyhow!("Invalid provider type for Google"));
        }

        let scopes = if config.scopes.is_empty() {
            vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ]
        } else {
            config.scopes
        };

        Ok(Self {
            client_id: config.client_id,
            client_secret: config.client_secret,
            redirect_uri: config.redirect_uri,
            scopes,
            http_client: reqwest::Client::new(),
        })
    }

    /// Get Google OAuth2 authorization URL
    fn get_auth_url(&self, state: &str) -> String {
        let scope_string = self.scopes.join(" ");

        format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&scope={}&response_type=code&state={}&access_type=offline&prompt=consent",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(&scope_string),
            urlencoding::encode(state)
        )
    }

    /// Exchange authorization code for access token
    async fn exchange_code_for_token(&self, code: &str) -> Result<GoogleTokenResponse> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", self.redirect_uri.as_str()),
        ];

        let response = self
            .http_client
            .post("https://oauth2.googleapis.com/token")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "Google token exchange failed: {}",
                error_text
            ));
        }

        let token_response: GoogleTokenResponse = response.json().await?;
        Ok(token_response)
    }

    /// Get user info from Google API
    async fn get_user_info(&self, access_token: &str) -> Result<GoogleUserInfo> {
        let response = self
            .http_client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "Failed to get Google user info: {}",
                error_text
            ));
        }

        let user_info: GoogleUserInfo = response.json().await?;
        Ok(user_info)
    }

    /// Convert Google user info to social user profile
    fn convert_to_profile(&self, user_info: GoogleUserInfo) -> SocialUserProfile {
        let raw_profile = serde_json::to_value(&user_info).unwrap_or_default();

        SocialUserProfile {
            provider: SocialProvider::Google,
            provider_user_id: user_info.id,
            email: user_info.email,
            name: user_info.name,
            avatar_url: user_info.picture,
            username: None, // Google doesn't provide username
            verified_email: user_info.verified_email,
            raw_profile,
        }
    }
}

#[async_trait::async_trait]
impl SocialLoginProvider for GoogleProvider {
    fn provider_type(&self) -> SocialProvider {
        SocialProvider::Google
    }

    async fn get_authorization_url(&self, state: &str) -> Result<SocialAuthUrl> {
        let authorization_url = self.get_auth_url(state);

        Ok(SocialAuthUrl {
            provider: SocialProvider::Google,
            authorization_url,
            state: state.to_string(),
            pkce_verifier: None, // Google doesn't require PKCE for server-side apps
        })
    }

    async fn exchange_code(&self, code: &str, _state: &str) -> Result<SocialLoginResult> {
        let token_response = self.exchange_code_for_token(code).await?;
        let user_info = self.get_user_info(&token_response.access_token).await?;
        let user_profile = self.convert_to_profile(user_info);

        Ok(SocialLoginResult {
            user_profile,
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            expires_in: token_response.expires_in,
        })
    }

    async fn get_user_profile(&self, access_token: &str) -> Result<SocialUserProfile> {
        let user_info = self.get_user_info(access_token).await?;
        Ok(self.convert_to_profile(user_info))
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<SocialLoginResult> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ];

        let response = self
            .http_client
            .post("https://oauth2.googleapis.com/token")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "Google token refresh failed: {}",
                error_text
            ));
        }

        let token_response: GoogleTokenResponse = response.json().await?;
        let user_info = self.get_user_info(&token_response.access_token).await?;
        let user_profile = self.convert_to_profile(user_info);

        Ok(SocialLoginResult {
            user_profile,
            access_token: token_response.access_token,
            refresh_token: token_response
                .refresh_token
                .or_else(|| Some(refresh_token.to_string())),
            expires_in: token_response.expires_in,
        })
    }

    fn validate_config(&self) -> Result<()> {
        if self.client_id.is_empty() {
            return Err(anyhow::anyhow!("Google client_id is required"));
        }
        if self.client_secret.is_empty() {
            return Err(anyhow::anyhow!("Google client_secret is required"));
        }
        if self.redirect_uri.is_empty() {
            return Err(anyhow::anyhow!("Google redirect_uri is required"));
        }
        if !self.redirect_uri.starts_with("https://")
            && !self.redirect_uri.starts_with("http://localhost")
        {
            return Err(anyhow::anyhow!(
                "Google redirect_uri must use HTTPS or localhost"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> SocialConfig {
        SocialConfig {
            provider: SocialProvider::Google,
            client_id: "test_client_id".to_string(),
            client_secret: "test_client_secret".to_string(),
            redirect_uri: "https://example.com/auth/google/callback".to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            enabled: true,
        }
    }

    #[test]
    fn test_google_provider_creation() {
        let config = create_test_config();
        let provider = GoogleProvider::new(config).unwrap();

        assert_eq!(provider.provider_type(), SocialProvider::Google);
    }

    #[test]
    fn test_google_provider_validation() {
        let config = create_test_config();
        let provider = GoogleProvider::new(config).unwrap();

        assert!(provider.validate_config().is_ok());
    }

    #[test]
    fn test_google_provider_invalid_config() {
        let mut config = create_test_config();
        config.client_id = "".to_string();

        let provider = GoogleProvider::new(config).unwrap();
        assert!(provider.validate_config().is_err());
    }

    #[test]
    fn test_google_auth_url_generation() {
        let config = create_test_config();
        let provider = GoogleProvider::new(config).unwrap();
        let state = "test_state";

        let auth_url = provider.get_auth_url(state);

        assert!(auth_url.contains("accounts.google.com"));
        assert!(auth_url.contains("test_client_id"));
        assert!(auth_url.contains("test_state"));
        assert!(auth_url.contains("openid"));
        assert!(auth_url.contains("email"));
        assert!(auth_url.contains("profile"));
    }

    #[test]
    fn test_convert_to_profile() {
        let config = create_test_config();
        let provider = GoogleProvider::new(config).unwrap();

        let google_user = GoogleUserInfo {
            id: "123456789".to_string(),
            email: "test@gmail.com".to_string(),
            verified_email: true,
            name: "Test User".to_string(),
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            picture: Some("https://example.com/avatar.jpg".to_string()),
            locale: Some("en".to_string()),
        };

        let profile = provider.convert_to_profile(google_user);

        assert_eq!(profile.provider, SocialProvider::Google);
        assert_eq!(profile.provider_user_id, "123456789");
        assert_eq!(profile.email, "test@gmail.com");
        assert_eq!(profile.name, "Test User");
        assert!(profile.verified_email);
        assert_eq!(
            profile.avatar_url,
            Some("https://example.com/avatar.jpg".to_string())
        );
        assert!(profile.username.is_none());
    }
}
