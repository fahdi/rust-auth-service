use super::{
    SocialAuthUrl, SocialConfig, SocialLoginProvider, SocialLoginResult, SocialProvider,
    SocialUserProfile,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// GitHub OAuth2 configuration
#[derive(Debug, Clone)]
pub struct GitHubProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: Vec<String>,
    http_client: reqwest::Client,
}

/// GitHub OAuth2 token response
#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    token_type: String,
    scope: String,
}

/// GitHub user profile response
#[derive(Debug, Serialize, Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: String,
    bio: Option<String>,
    location: Option<String>,
    company: Option<String>,
    blog: Option<String>,
    public_repos: Option<u32>,
    public_gists: Option<u32>,
    followers: Option<u32>,
    following: Option<u32>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

/// GitHub email response
#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
    visibility: Option<String>,
}

impl GitHubProvider {
    /// Create new GitHub provider
    pub fn new(config: SocialConfig) -> Result<Self> {
        if config.provider != SocialProvider::GitHub {
            return Err(anyhow::anyhow!("Invalid provider type for GitHub"));
        }

        let scopes = if config.scopes.is_empty() {
            vec!["user:email".to_string()]
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

    /// Get GitHub OAuth2 authorization URL
    fn get_auth_url(&self, state: &str) -> String {
        let scope_string = self.scopes.join(" ");

        format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope={}&state={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(&scope_string),
            urlencoding::encode(state)
        )
    }

    /// Exchange authorization code for access token
    async fn exchange_code_for_token(&self, code: &str) -> Result<GitHubTokenResponse> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", code),
        ];

        let response = self
            .http_client
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "GitHub token exchange failed: {}",
                error_text
            ));
        }

        let token_response: GitHubTokenResponse = response.json().await?;
        Ok(token_response)
    }

    /// Get user info from GitHub API
    async fn get_user_info(&self, access_token: &str) -> Result<GitHubUser> {
        let response = self
            .http_client
            .get("https://api.github.com/user")
            .header("Authorization", format!("token {}", access_token))
            .header("User-Agent", "rust-auth-service")
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "Failed to get GitHub user info: {}",
                error_text
            ));
        }

        let user_info: GitHubUser = response.json().await?;
        Ok(user_info)
    }

    /// Get user emails from GitHub API
    async fn get_user_emails(&self, access_token: &str) -> Result<Vec<GitHubEmail>> {
        let response = self
            .http_client
            .get("https://api.github.com/user/emails")
            .header("Authorization", format!("token {}", access_token))
            .header("User-Agent", "rust-auth-service")
            .send()
            .await?;

        if !response.status().is_success() {
            // If we can't get emails, return empty vec rather than failing
            return Ok(vec![]);
        }

        let emails: Vec<GitHubEmail> = response.json().await.unwrap_or_default();
        Ok(emails)
    }

    /// Convert GitHub user info to social user profile
    async fn convert_to_profile(
        &self,
        user_info: GitHubUser,
        access_token: &str,
    ) -> Result<SocialUserProfile> {
        // Serialize raw profile first before any field moves
        let raw_profile = serde_json::to_value(&user_info).unwrap_or_default();
        let username = user_info.login.clone();
        let display_name = user_info
            .name
            .clone()
            .unwrap_or_else(|| user_info.login.clone());
        let avatar_url = user_info.avatar_url.clone();
        let provider_user_id = user_info.id.to_string();

        // Get primary verified email
        let mut email = String::new();
        let mut verified_email = false;

        // Try to get email from user profile first
        if let Some(profile_email) = user_info.email {
            email = profile_email;
            verified_email = true; // Assume verified if public
        } else {
            // Get emails from API
            let emails = self.get_user_emails(access_token).await?;
            if let Some(primary_email) = emails.iter().find(|e| e.primary && e.verified) {
                email = primary_email.email.clone();
                verified_email = true;
            } else if let Some(first_verified) = emails.iter().find(|e| e.verified) {
                email = first_verified.email.clone();
                verified_email = true;
            } else if let Some(first_email) = emails.first() {
                email = first_email.email.clone();
                verified_email = first_email.verified;
            }
        }

        Ok(SocialUserProfile {
            provider: SocialProvider::GitHub,
            provider_user_id,
            email,
            name: display_name,
            avatar_url: Some(avatar_url),
            username: Some(username),
            verified_email,
            raw_profile,
        })
    }
}

#[async_trait::async_trait]
impl SocialLoginProvider for GitHubProvider {
    fn provider_type(&self) -> SocialProvider {
        SocialProvider::GitHub
    }

    async fn get_authorization_url(&self, state: &str) -> Result<SocialAuthUrl> {
        let authorization_url = self.get_auth_url(state);

        Ok(SocialAuthUrl {
            provider: SocialProvider::GitHub,
            authorization_url,
            state: state.to_string(),
            pkce_verifier: None, // GitHub doesn't require PKCE for server-side apps
        })
    }

    async fn exchange_code(&self, code: &str, _state: &str) -> Result<SocialLoginResult> {
        let token_response = self.exchange_code_for_token(code).await?;
        let user_info = self.get_user_info(&token_response.access_token).await?;
        let user_profile = self
            .convert_to_profile(user_info, &token_response.access_token)
            .await?;

        Ok(SocialLoginResult {
            user_profile,
            access_token: token_response.access_token,
            refresh_token: None, // GitHub doesn't provide refresh tokens
            expires_in: None,    // GitHub tokens don't expire
        })
    }

    async fn get_user_profile(&self, access_token: &str) -> Result<SocialUserProfile> {
        let user_info = self.get_user_info(access_token).await?;
        self.convert_to_profile(user_info, access_token).await
    }

    async fn refresh_token(&self, _refresh_token: &str) -> Result<SocialLoginResult> {
        Err(anyhow::anyhow!("GitHub does not support token refresh"))
    }

    fn validate_config(&self) -> Result<()> {
        if self.client_id.is_empty() {
            return Err(anyhow::anyhow!("GitHub client_id is required"));
        }
        if self.client_secret.is_empty() {
            return Err(anyhow::anyhow!("GitHub client_secret is required"));
        }
        if self.redirect_uri.is_empty() {
            return Err(anyhow::anyhow!("GitHub redirect_uri is required"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> SocialConfig {
        SocialConfig {
            provider: SocialProvider::GitHub,
            client_id: "test_client_id".to_string(),
            client_secret: "test_client_secret".to_string(),
            redirect_uri: "https://example.com/auth/github/callback".to_string(),
            scopes: vec!["user:email".to_string()],
            enabled: true,
        }
    }

    #[test]
    fn test_github_provider_creation() {
        let config = create_test_config();
        let provider = GitHubProvider::new(config).unwrap();

        assert_eq!(provider.provider_type(), SocialProvider::GitHub);
    }

    #[test]
    fn test_github_provider_validation() {
        let config = create_test_config();
        let provider = GitHubProvider::new(config).unwrap();

        assert!(provider.validate_config().is_ok());
    }

    #[test]
    fn test_github_provider_invalid_config() {
        let mut config = create_test_config();
        config.client_id = "".to_string();

        let provider = GitHubProvider::new(config).unwrap();
        assert!(provider.validate_config().is_err());
    }

    #[test]
    fn test_github_auth_url_generation() {
        let config = create_test_config();
        let provider = GitHubProvider::new(config).unwrap();
        let state = "test_state";

        let auth_url = provider.get_auth_url(state);

        assert!(auth_url.contains("github.com/login/oauth/authorize"));
        assert!(auth_url.contains("test_client_id"));
        assert!(auth_url.contains("test_state"));
        assert!(auth_url.contains("user%3Aemail"));
    }

    #[tokio::test]
    async fn test_convert_to_profile() {
        let config = create_test_config();
        let provider = GitHubProvider::new(config).unwrap();

        let github_user = GitHubUser {
            id: 123456,
            login: "testuser".to_string(),
            name: Some("Test User".to_string()),
            email: Some("test@example.com".to_string()),
            avatar_url: "https://github.com/avatar.jpg".to_string(),
            bio: Some("A test user".to_string()),
            location: Some("Test City".to_string()),
            company: Some("Test Company".to_string()),
            blog: Some("https://testuser.dev".to_string()),
            public_repos: Some(10),
            public_gists: Some(5),
            followers: Some(100),
            following: Some(50),
            created_at: Some("2020-01-01T00:00:00Z".to_string()),
            updated_at: Some("2023-01-01T00:00:00Z".to_string()),
        };

        let profile = provider
            .convert_to_profile(github_user, "fake_token")
            .await
            .unwrap();

        assert_eq!(profile.provider, SocialProvider::GitHub);
        assert_eq!(profile.provider_user_id, "123456");
        assert_eq!(profile.email, "test@example.com");
        assert_eq!(profile.name, "Test User");
        assert!(profile.verified_email);
        assert_eq!(
            profile.avatar_url,
            Some("https://github.com/avatar.jpg".to_string())
        );
        assert_eq!(profile.username, Some("testuser".to_string()));
    }
}
