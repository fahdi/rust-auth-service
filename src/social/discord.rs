use super::{
    SocialAuthUrl, SocialConfig, SocialLoginProvider, SocialLoginResult, SocialProvider,
    SocialUserProfile,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Discord OAuth2 configuration
#[derive(Debug, Clone)]
pub struct DiscordProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: Vec<String>,
    http_client: reqwest::Client,
}

/// Discord OAuth2 token response
#[derive(Debug, Deserialize)]
struct DiscordTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: String,
    scope: String,
}

/// Discord user profile response
#[derive(Debug, Serialize, Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    discriminator: String,
    global_name: Option<String>,
    avatar: Option<String>,
    bot: Option<bool>,
    system: Option<bool>,
    mfa_enabled: Option<bool>,
    banner: Option<String>,
    accent_color: Option<u32>,
    locale: Option<String>,
    verified: Option<bool>,
    email: Option<String>,
    flags: Option<u32>,
    premium_type: Option<u32>,
    public_flags: Option<u32>,
}

impl DiscordProvider {
    /// Create new Discord provider
    pub fn new(config: SocialConfig) -> Result<Self> {
        if config.provider != SocialProvider::Discord {
            return Err(anyhow::anyhow!("Invalid provider type for Discord"));
        }

        let scopes = if config.scopes.is_empty() {
            vec!["identify".to_string(), "email".to_string()]
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

    /// Get Discord OAuth2 authorization URL
    fn get_auth_url(&self, state: &str) -> String {
        let scope_string = self.scopes.join(" ");

        format!(
            "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(&scope_string),
            urlencoding::encode(state)
        )
    }

    /// Exchange authorization code for access token
    async fn exchange_code_for_token(&self, code: &str) -> Result<DiscordTokenResponse> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
        ];

        let response = self
            .http_client
            .post("https://discord.com/api/oauth2/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "Discord token exchange failed: {}",
                error_text
            ));
        }

        let token_response: DiscordTokenResponse = response.json().await?;
        Ok(token_response)
    }

    /// Get user info from Discord API
    async fn get_user_info(&self, access_token: &str) -> Result<DiscordUser> {
        let response = self
            .http_client
            .get("https://discord.com/api/users/@me")
            .header("Authorization", format!("Bearer {value}"), access_token))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "Failed to get Discord user info: {}",
                error_text
            ));
        }

        let user_info: DiscordUser = response.json().await?;
        Ok(user_info)
    }

    /// Convert Discord user info to social user profile
    fn convert_to_profile(&self, user_info: DiscordUser) -> SocialUserProfile {
        // Serialize raw profile first before any field moves
        let raw_profile = serde_json::to_value(&user_info).unwrap_or_default();
        let provider_user_id = user_info.id.clone();
        let email = user_info.email.clone().unwrap_or_default();
        let verified_email = user_info.verified.unwrap_or(false);

        // Create Discord username (username#discriminator or new @username format)
        let discord_username = if user_info.discriminator == "0" {
            // New username format (no discriminator)
            user_info.username.clone()
        } else {
            // Legacy format with discriminator
            format!("{}#{value}"), user_info.username, user_info.discriminator)
        };

        // Generate avatar URL if avatar hash is provided
        let avatar_url = user_info.avatar.map(|avatar_hash| {
            format!(
                "https://cdn.discordapp.com/avatars/{}/{}.png",
                user_info.id, avatar_hash
            )
        });

        // Use global_name if available, otherwise use username
        let display_name = user_info
            .global_name
            .unwrap_or_else(|| user_info.username.clone());

        SocialUserProfile {
            provider: SocialProvider::Discord,
            provider_user_id,
            email,
            name: display_name,
            avatar_url,
            username: Some(discord_username),
            verified_email,
            raw_profile,
        }
    }

    /// Refresh Discord access token
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<DiscordTokenResponse> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];

        let response = self
            .http_client
            .post("https://discord.com/api/oauth2/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "Discord token refresh failed: {}",
                error_text
            ));
        }

        let token_response: DiscordTokenResponse = response.json().await?;
        Ok(token_response)
    }
}

#[async_trait::async_trait]
impl SocialLoginProvider for DiscordProvider {
    fn provider_type(&self) -> SocialProvider {
        SocialProvider::Discord
    }

    async fn get_authorization_url(&self, state: &str) -> Result<SocialAuthUrl> {
        let authorization_url = self.get_auth_url(state);

        Ok(SocialAuthUrl {
            provider: SocialProvider::Discord,
            authorization_url,
            state: state.to_string(),
            pkce_verifier: None, // Discord doesn't require PKCE for server-side apps
        })
    }

    async fn exchange_code(&self, code: &str, _state: &str) -> Result<SocialLoginResult> {
        let token_response = self.exchange_code_for_token(code).await?;
        let user_info = self.get_user_info(&token_response.access_token).await?;
        let user_profile = self.convert_to_profile(user_info);

        Ok(SocialLoginResult {
            user_profile,
            access_token: token_response.access_token,
            refresh_token: Some(token_response.refresh_token),
            expires_in: Some(token_response.expires_in),
        })
    }

    async fn get_user_profile(&self, access_token: &str) -> Result<SocialUserProfile> {
        let user_info = self.get_user_info(access_token).await?;
        Ok(self.convert_to_profile(user_info))
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<SocialLoginResult> {
        let token_response = self.refresh_access_token(refresh_token).await?;
        let user_info = self.get_user_info(&token_response.access_token).await?;
        let user_profile = self.convert_to_profile(user_info);

        Ok(SocialLoginResult {
            user_profile,
            access_token: token_response.access_token,
            refresh_token: Some(token_response.refresh_token),
            expires_in: Some(token_response.expires_in),
        })
    }

    fn validate_config(&self) -> Result<()> {
        if self.client_id.is_empty() {
            return Err(anyhow::anyhow!("Discord client_id is required"));
        }
        if self.client_secret.is_empty() {
            return Err(anyhow::anyhow!("Discord client_secret is required"));
        }
        if self.redirect_uri.is_empty() {
            return Err(anyhow::anyhow!("Discord redirect_uri is required"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> SocialConfig {
        SocialConfig {
            provider: SocialProvider::Discord,
            client_id: "test_client_id".to_string(),
            client_secret: "test_client_secret".to_string(),
            redirect_uri: "https://example.com/auth/discord/callback".to_string(),
            scopes: vec!["identify".to_string(), "email".to_string()],
            enabled: true,
        }
    }

    #[test]
    fn test_discord_provider_creation() {
        let config = create_test_config();
        let provider = DiscordProvider::new(config).unwrap();

        assert_eq!(provider.provider_type(), SocialProvider::Discord);
    }

    #[test]
    fn test_discord_provider_validation() {
        let config = create_test_config();
        let provider = DiscordProvider::new(config).unwrap();

        assert!(provider.validate_config().is_ok());
    }

    #[test]
    fn test_discord_provider_invalid_config() {
        let mut config = create_test_config();
        config.client_id = "".to_string();

        let provider = DiscordProvider::new(config).unwrap();
        assert!(provider.validate_config().is_err());
    }

    #[test]
    fn test_discord_auth_url_generation() {
        let config = create_test_config();
        let provider = DiscordProvider::new(config).unwrap();
        let state = "test_state";

        let auth_url = provider.get_auth_url(state);

        assert!(auth_url.contains("discord.com/api/oauth2/authorize"));
        assert!(auth_url.contains("test_client_id"));
        assert!(auth_url.contains("test_state"));
        assert!(auth_url.contains("identify"));
        assert!(auth_url.contains("email"));
    }

    #[test]
    fn test_convert_to_profile_legacy_format() {
        let config = create_test_config();
        let provider = DiscordProvider::new(config).unwrap();

        let discord_user = DiscordUser {
            id: "123456789012345678".to_string(),
            username: "testuser".to_string(),
            discriminator: "1234".to_string(),
            global_name: Some("Test User".to_string()),
            avatar: Some("avatar_hash_123".to_string()),
            bot: Some(false),
            system: Some(false),
            mfa_enabled: Some(true),
            banner: None,
            accent_color: None,
            locale: Some("en-US".to_string()),
            verified: Some(true),
            email: Some("test@example.com".to_string()),
            flags: Some(0),
            premium_type: Some(0),
            public_flags: Some(0),
        };

        let profile = provider.convert_to_profile(discord_user);

        assert_eq!(profile.provider, SocialProvider::Discord);
        assert_eq!(profile.provider_user_id, "123456789012345678");
        assert_eq!(profile.email, "test@example.com");
        assert_eq!(profile.name, "Test User");
        assert!(profile.verified_email);
        assert_eq!(
            profile.avatar_url,
            Some(
                "https://cdn.discordapp.com/avatars/123456789012345678/avatar_hash_123.png"
                    .to_string()
            )
        );
        assert_eq!(profile.username, Some("testuser#1234".to_string()));
    }

    #[test]
    fn test_convert_to_profile_new_format() {
        let config = create_test_config();
        let provider = DiscordProvider::new(config).unwrap();

        let discord_user = DiscordUser {
            id: "123456789012345678".to_string(),
            username: "testuser".to_string(),
            discriminator: "0".to_string(), // New format has discriminator "0"
            global_name: Some("Test User".to_string()),
            avatar: Some("avatar_hash_123".to_string()),
            bot: Some(false),
            system: Some(false),
            mfa_enabled: Some(true),
            banner: None,
            accent_color: None,
            locale: Some("en-US".to_string()),
            verified: Some(true),
            email: Some("test@example.com".to_string()),
            flags: Some(0),
            premium_type: Some(0),
            public_flags: Some(0),
        };

        let profile = provider.convert_to_profile(discord_user);

        assert_eq!(profile.provider, SocialProvider::Discord);
        assert_eq!(profile.provider_user_id, "123456789012345678");
        assert_eq!(profile.email, "test@example.com");
        assert_eq!(profile.name, "Test User");
        assert!(profile.verified_email);
        assert_eq!(
            profile.avatar_url,
            Some(
                "https://cdn.discordapp.com/avatars/123456789012345678/avatar_hash_123.png"
                    .to_string()
            )
        );
        assert_eq!(profile.username, Some("testuser".to_string())); // No discriminator in new format
    }
}
