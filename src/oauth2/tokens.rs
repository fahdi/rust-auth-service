use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::{AccessToken, OAuth2Config, RefreshToken};

/// JWT claims for OAuth2 access tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,              // User ID
    pub aud: Vec<String>,         // Audience (client IDs)
    pub iss: String,              // Issuer
    pub exp: i64,                 // Expiration time
    pub iat: i64,                 // Issued at
    pub nbf: i64,                 // Not before
    pub jti: String,              // JWT ID (token ID)
    pub scope: String,            // Space-separated scopes
    pub client_id: String,        // OAuth2 client ID
    pub token_type: String,       // "access_token"
    pub azp: Option<String>,      // Authorized party
    pub auth_time: Option<i64>,   // Authentication time
    pub acr: Option<String>,      // Authentication context class reference
    pub amr: Option<Vec<String>>, // Authentication methods references
    pub sid: Option<String>,      // Session ID
}

/// JWT claims for OAuth2 refresh tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,             // User ID
    pub aud: Vec<String>,        // Audience (client IDs)
    pub iss: String,             // Issuer
    pub exp: Option<i64>,        // Expiration time (None = never expires)
    pub iat: i64,                // Issued at
    pub nbf: i64,                // Not before
    pub jti: String,             // JWT ID (token ID)
    pub scope: String,           // Space-separated scopes
    pub client_id: String,       // OAuth2 client ID
    pub token_type: String,      // "refresh_token"
    pub access_token_id: String, // Associated access token ID
}

/// ID token claims for OpenID Connect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,             // User ID
    pub aud: Vec<String>,        // Audience (client IDs)
    pub iss: String,             // Issuer
    pub exp: i64,                // Expiration time
    pub iat: i64,                // Issued at
    pub auth_time: i64,          // Authentication time
    pub nonce: Option<String>,   // Nonce from authorization request
    pub azp: Option<String>,     // Authorized party
    pub at_hash: Option<String>, // Access token hash
    pub c_hash: Option<String>,  // Code hash

    // Standard claims
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub address: Option<serde_json::Value>,
    pub updated_at: Option<i64>,
}

/// Token generator and validator
#[derive(Clone)]
pub struct TokenManager {
    config: OAuth2Config,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

impl TokenManager {
    /// Create new token manager with configuration
    pub fn new(
        config: OAuth2Config,
        private_key: &[u8],
        public_key: Option<&[u8]>,
    ) -> Result<Self> {
        let algorithm = match config.jwt_signing_algorithm.as_str() {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            "ES256" => Algorithm::ES256,
            "ES384" => Algorithm::ES384,
            _ => {
                return Err(anyhow!(
                    "Unsupported JWT algorithm: {}",
                    config.jwt_signing_algorithm
                ))
            }
        };

        let encoding_key = match algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                EncodingKey::from_secret(private_key)
            }
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                EncodingKey::from_rsa_pem(private_key)?
            }
            Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(private_key)?,
            _ => return Err(anyhow!("Unsupported algorithm for encoding key")),
        };

        let decoding_key = match algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                DecodingKey::from_secret(private_key)
            }
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                let key_data = public_key.unwrap_or(private_key);
                DecodingKey::from_rsa_pem(key_data)?
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                let key_data = public_key.unwrap_or(private_key);
                DecodingKey::from_ec_pem(key_data)?
            }
            _ => return Err(anyhow!("Unsupported algorithm for decoding key")),
        };

        Ok(TokenManager {
            config,
            encoding_key,
            decoding_key,
            algorithm,
        })
    }

    /// Generate access token
    pub fn generate_access_token(
        &self,
        user_id: &str,
        client_id: &str,
        scopes: &[String],
        audience: Option<Vec<String>>,
        auth_time: Option<i64>,
        session_id: Option<String>,
    ) -> Result<(String, AccessToken)> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.access_token_lifetime as i64);
        let token_id = Uuid::new_v4().to_string();

        let claims = AccessTokenClaims {
            sub: user_id.to_string(),
            aud: audience.unwrap_or_else(|| vec![client_id.to_string()]),
            iss: self.config.issuer.clone(),
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: token_id.clone(),
            scope: scopes.join(" "),
            client_id: client_id.to_string(),
            token_type: "access_token".to_string(),
            azp: Some(client_id.to_string()),
            auth_time,
            acr: None,
            amr: None,
            sid: session_id,
        };

        let header = Header::new(self.algorithm);
        let token = encode(&header, &claims, &self.encoding_key)?;

        let access_token = AccessToken {
            token: token.clone(),
            token_type: "Bearer".to_string(),
            client_id: client_id.to_string(),
            user_id: Some(user_id.to_string()),
            scopes: scopes.to_vec(),
            expires_at: expires_at.into(),
            created_at: now.into(),
            revoked: false,
        };

        Ok((token, access_token))
    }

    /// Generate refresh token
    pub fn generate_refresh_token(
        &self,
        access_token_id: &str,
        user_id: &str,
        client_id: &str,
        scopes: &[String],
        audience: Option<Vec<String>>,
    ) -> Result<(String, RefreshToken)> {
        let now = Utc::now();
        let expires_at = self
            .config
            .refresh_token_lifetime
            .map(|lifetime| now + Duration::seconds(lifetime as i64));
        let token_id = Uuid::new_v4().to_string();

        let claims = RefreshTokenClaims {
            sub: user_id.to_string(),
            aud: audience.unwrap_or_else(|| vec![client_id.to_string()]),
            iss: self.config.issuer.clone(),
            exp: expires_at.map(|exp| exp.timestamp()),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: token_id.clone(),
            scope: scopes.join(" "),
            client_id: client_id.to_string(),
            token_type: "refresh_token".to_string(),
            access_token_id: access_token_id.to_string(),
        };

        let header = Header::new(self.algorithm);
        let token = encode(&header, &claims, &self.encoding_key)?;

        let refresh_token = RefreshToken {
            token: token.clone(),
            access_token: access_token_id.to_string(),
            client_id: client_id.to_string(),
            user_id: Some(user_id.to_string()),
            scopes: scopes.to_vec(),
            expires_at: expires_at.map(|exp| exp.into()),
            created_at: now.into(),
            used: false,
        };

        Ok((token, refresh_token))
    }

    /// Generate ID token for OpenID Connect
    pub fn generate_id_token(
        &self,
        user_id: &str,
        client_id: &str,
        auth_time: i64,
        nonce: Option<String>,
        access_token: Option<&str>,
        code: Option<&str>,
        user_claims: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<String> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.access_token_lifetime as i64);

        let mut claims = IdTokenClaims {
            sub: user_id.to_string(),
            aud: vec![client_id.to_string()],
            iss: self.config.issuer.clone(),
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            auth_time,
            nonce,
            azp: Some(client_id.to_string()),
            at_hash: None,
            c_hash: None,
            name: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            preferred_username: None,
            profile: None,
            picture: None,
            website: None,
            email: None,
            email_verified: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            phone_number: None,
            phone_number_verified: None,
            address: None,
            updated_at: None,
        };

        // Add access token hash if provided
        if let Some(token) = access_token {
            claims.at_hash = Some(self.generate_hash(token)?);
        }

        // Add code hash if provided
        if let Some(authorization_code) = code {
            claims.c_hash = Some(self.generate_hash(authorization_code)?);
        }

        // Add user claims if provided
        if let Some(user_data) = user_claims {
            if let Some(name) = user_data.get("name").and_then(|v| v.as_str()) {
                claims.name = Some(name.to_string());
            }
            if let Some(given_name) = user_data.get("given_name").and_then(|v| v.as_str()) {
                claims.given_name = Some(given_name.to_string());
            }
            if let Some(family_name) = user_data.get("family_name").and_then(|v| v.as_str()) {
                claims.family_name = Some(family_name.to_string());
            }
            if let Some(email) = user_data.get("email").and_then(|v| v.as_str()) {
                claims.email = Some(email.to_string());
            }
            if let Some(email_verified) = user_data.get("email_verified").and_then(|v| v.as_bool())
            {
                claims.email_verified = Some(email_verified);
            }
            if let Some(picture) = user_data.get("picture").and_then(|v| v.as_str()) {
                claims.picture = Some(picture.to_string());
            }
            if let Some(preferred_username) =
                user_data.get("preferred_username").and_then(|v| v.as_str())
            {
                claims.preferred_username = Some(preferred_username.to_string());
            }
        }

        let header = Header::new(self.algorithm);
        let token = encode(&header, &claims, &self.encoding_key)?;

        Ok(token)
    }

    /// Validate and decode access token
    pub fn validate_access_token(&self, token: &str) -> Result<TokenData<AccessTokenClaims>> {
        let mut validation = Validation::new(self.algorithm);
        validation.set_issuer(&[&self.config.issuer]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        decode::<AccessTokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| anyhow!("Invalid access token: {}", e))
    }

    /// Validate and decode refresh token
    pub fn validate_refresh_token(&self, token: &str) -> Result<TokenData<RefreshTokenClaims>> {
        let mut validation = Validation::new(self.algorithm);
        validation.set_issuer(&[&self.config.issuer]);
        validation.validate_exp = false; // Refresh tokens may not expire
        validation.validate_nbf = true;

        decode::<RefreshTokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| anyhow!("Invalid refresh token: {}", e))
    }

    /// Validate and decode ID token
    pub fn validate_id_token(&self, token: &str) -> Result<TokenData<IdTokenClaims>> {
        let mut validation = Validation::new(self.algorithm);
        validation.set_issuer(&[&self.config.issuer]);
        validation.validate_exp = true;
        validation.validate_nbf = false;

        decode::<IdTokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| anyhow!("Invalid ID token: {}", e))
    }

    /// Extract token from Authorization header
    pub fn extract_bearer_token(authorization: &str) -> Result<&str> {
        if !authorization.starts_with("Bearer ") {
            return Err(anyhow!("Invalid authorization header format"));
        }

        let token = &authorization[7..]; // Remove "Bearer " prefix
        if token.is_empty() {
            return Err(anyhow!("Empty bearer token"));
        }

        Ok(token)
    }

    /// Generate hash for ID token (at_hash, c_hash)
    fn generate_hash(&self, input: &str) -> Result<String> {
        use sha2::{Digest, Sha256};

        let hash = Sha256::digest(input.as_bytes());
        let half_length = hash.len() / 2;
        let truncated = &hash[..half_length];

        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            truncated,
        ))
    }

    /// Get JWT header for key discovery
    pub fn get_jwt_header(&self) -> Header {
        Header::new(self.algorithm)
    }

    /// Get algorithm name
    pub fn algorithm(&self) -> &str {
        match self.algorithm {
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            _ => "Unknown",
        }
    }
}

/// Token introspection helper
pub struct TokenIntrospector {
    token_manager: TokenManager,
}

impl TokenIntrospector {
    pub fn new(token_manager: TokenManager) -> Self {
        Self { token_manager }
    }

    /// Introspect access token and return claims
    pub fn introspect_access_token(&self, token: &str) -> Result<AccessTokenClaims> {
        let token_data = self.token_manager.validate_access_token(token)?;
        Ok(token_data.claims)
    }

    /// Check if token is expired
    pub fn is_token_expired(&self, exp: i64) -> bool {
        let now = Utc::now().timestamp();
        exp <= now
    }

    /// Check if token is not yet valid
    pub fn is_token_not_yet_valid(&self, nbf: i64) -> bool {
        let now = Utc::now().timestamp();
        nbf > now
    }

    /// Extract scopes from token
    pub fn extract_scopes(&self, token: &str) -> Result<Vec<String>> {
        let claims = self.introspect_access_token(token)?;
        Ok(claims
            .scope
            .split_whitespace()
            .map(|s| s.to_string())
            .collect())
    }

    /// Check if token has specific scope
    pub fn has_scope(&self, token: &str, required_scope: &str) -> Result<bool> {
        let scopes = self.extract_scopes(token)?;
        Ok(scopes.contains(&required_scope.to_string()))
    }

    /// Check if token has any of the required scopes
    pub fn has_any_scope(&self, token: &str, required_scopes: &[String]) -> Result<bool> {
        let scopes = self.extract_scopes(token)?;
        Ok(required_scopes.iter().any(|scope| scopes.contains(scope)))
    }

    /// Check if token has all required scopes
    pub fn has_all_scopes(&self, token: &str, required_scopes: &[String]) -> Result<bool> {
        let scopes = self.extract_scopes(token)?;
        Ok(required_scopes.iter().all(|scope| scopes.contains(scope)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> OAuth2Config {
        OAuth2Config {
            issuer: "https://test.example.com".to_string(),
            jwt_signing_algorithm: "HS256".to_string(),
            access_token_lifetime: 3600,
            refresh_token_lifetime: Some(86400),
            ..Default::default()
        }
    }

    fn create_test_token_manager() -> TokenManager {
        let config = create_test_config();
        let secret = b"test-secret-key-for-jwt-signing-must-be-long-enough";
        TokenManager::new(config, secret, None).unwrap()
    }

    #[test]
    fn test_generate_access_token() {
        let token_manager = create_test_token_manager();

        let (token, access_token) = token_manager
            .generate_access_token(
                "user123",
                "client456",
                &["read".to_string(), "write".to_string()],
                None,
                None,
                None,
            )
            .unwrap();

        assert!(!token.is_empty());
        assert_eq!(access_token.client_id, "client456");
        assert_eq!(access_token.user_id, Some("user123".to_string()));
        assert_eq!(access_token.scopes, vec!["read", "write"]);
        assert_eq!(access_token.token_type, "Bearer");
    }

    #[test]
    fn test_validate_access_token() {
        let token_manager = create_test_token_manager();

        let (token, _) = token_manager
            .generate_access_token(
                "user123",
                "client456",
                &["read".to_string()],
                None,
                None,
                None,
            )
            .unwrap();

        let token_data = token_manager.validate_access_token(&token).unwrap();

        assert_eq!(token_data.claims.sub, "user123");
        assert_eq!(token_data.claims.client_id, "client456");
        assert_eq!(token_data.claims.scope, "read");
    }

    #[test]
    fn test_generate_refresh_token() {
        let token_manager = create_test_token_manager();

        let (token, refresh_token) = token_manager
            .generate_refresh_token(
                "access123",
                "user123",
                "client456",
                &["read".to_string()],
                None,
            )
            .unwrap();

        assert!(!token.is_empty());
        assert_eq!(refresh_token.access_token, "access123");
        assert_eq!(refresh_token.client_id, "client456");
        assert_eq!(refresh_token.user_id, Some("user123".to_string()));
    }

    #[test]
    fn test_generate_id_token() {
        let token_manager = create_test_token_manager();

        let mut user_claims = HashMap::new();
        user_claims.insert(
            "email".to_string(),
            serde_json::Value::String("user@example.com".to_string()),
        );
        user_claims.insert(
            "name".to_string(),
            serde_json::Value::String("Test User".to_string()),
        );

        let token = token_manager
            .generate_id_token(
                "user123",
                "client456",
                Utc::now().timestamp(),
                Some("nonce123".to_string()),
                None,
                None,
                Some(user_claims),
            )
            .unwrap();

        assert!(!token.is_empty());

        let token_data = token_manager.validate_id_token(&token).unwrap();
        assert_eq!(token_data.claims.sub, "user123");
        assert_eq!(token_data.claims.nonce, Some("nonce123".to_string()));
        assert_eq!(
            token_data.claims.email,
            Some("user@example.com".to_string())
        );
        assert_eq!(token_data.claims.name, Some("Test User".to_string()));
    }

    #[test]
    fn test_extract_bearer_token() {
        let auth_header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let token = TokenManager::extract_bearer_token(auth_header).unwrap();
        assert_eq!(token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");

        assert!(TokenManager::extract_bearer_token("Invalid header").is_err());
        assert!(TokenManager::extract_bearer_token("Bearer ").is_err());
    }

    #[test]
    fn test_token_introspection() {
        let token_manager = create_test_token_manager();
        let introspector = TokenIntrospector::new(token_manager);

        let token_manager = create_test_token_manager();
        let (token, _) = token_manager
            .generate_access_token(
                "user123",
                "client456",
                &["read".to_string(), "write".to_string()],
                None,
                None,
                None,
            )
            .unwrap();

        let scopes = introspector.extract_scopes(&token).unwrap();
        assert_eq!(scopes, vec!["read", "write"]);

        assert!(introspector.has_scope(&token, "read").unwrap());
        assert!(!introspector.has_scope(&token, "admin").unwrap());

        assert!(introspector
            .has_any_scope(&token, &["read".to_string(), "admin".to_string()])
            .unwrap());
        assert!(introspector
            .has_all_scopes(&token, &["read".to_string(), "write".to_string()])
            .unwrap());
        assert!(!introspector
            .has_all_scopes(&token, &["read".to_string(), "admin".to_string()])
            .unwrap());
    }
}
