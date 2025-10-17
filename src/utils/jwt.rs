use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use utoipa::ToSchema;
use uuid::Uuid;

// Re-export Claims as JwtClaims for compatibility
pub use Claims as JwtClaims;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub email: String,      // User email
    pub role: String,       // User role
    pub exp: i64,           // Expiration time (Unix timestamp)
    pub iat: i64,           // Issued at (Unix timestamp)
    pub jti: String,        // JWT ID (for blacklisting)
    pub token_type: String, // "access" or "refresh"
}

#[derive(Clone)]
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_token_expiry: Duration,
    refresh_token_expiry: Duration,
    blacklist: HashSet<String>, // In production, this should be Redis-backed
}

impl JwtManager {
    pub fn new(
        secret: &str,
        access_token_expiry_days: i64,
        refresh_token_expiry_days: i64,
    ) -> Self {
        let encoding_key = EncodingKey::from_secret(secret.as_ref());
        let decoding_key = DecodingKey::from_secret(secret.as_ref());

        Self {
            encoding_key,
            decoding_key,
            access_token_expiry: Duration::days(access_token_expiry_days),
            refresh_token_expiry: Duration::days(refresh_token_expiry_days),
            blacklist: HashSet::new(),
        }
    }

    /// Generate an access token for the user
    pub fn generate_access_token(&self, user_id: &str, email: &str, role: &str) -> Result<String> {
        let now = Utc::now();
        let exp = now + self.access_token_expiry;

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            token_type: "access".to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .context("Failed to generate access token")
    }

    /// Generate a refresh token for the user
    pub fn generate_refresh_token(&self, user_id: &str, email: &str, role: &str) -> Result<String> {
        let now = Utc::now();
        let exp = now + self.refresh_token_expiry;

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            token_type: "refresh".to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .context("Failed to generate refresh token")
    }

    /// Generate both access and refresh tokens
    pub fn generate_token_pair(
        &self,
        user_id: &str,
        email: &str,
        role: &str,
    ) -> Result<(String, String)> {
        let access_token = self.generate_access_token(user_id, email, role)?;
        let refresh_token = self.generate_refresh_token(user_id, email, role)?;

        Ok((access_token, refresh_token))
    }

    /// Validate and decode a JWT token
    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        // Check if token is blacklisted
        let claims = self.decode_token_without_validation(token)?;
        if self.blacklist.contains(&claims.jti) {
            return Err(anyhow::anyhow!("Token has been revoked"));
        }

        // Validate token signature and expiration
        let validation = Validation::default();
        let token_data =
            decode::<Claims>(token, &self.decoding_key, &validation).context("Invalid token")?;

        Ok(token_data.claims)
    }

    /// Decode token without validation (for getting JTI for blacklisting)
    fn decode_token_without_validation(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::default();
        validation.validate_exp = false;
        validation.validate_aud = false;

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .context("Failed to decode token")?;

        Ok(token_data.claims)
    }

    /// Refresh an access token using a refresh token
    pub fn refresh_access_token(&self, refresh_token: &str) -> Result<String> {
        let claims = self.validate_token(refresh_token)?;

        // Ensure it's a refresh token
        if claims.token_type != "refresh" {
            return Err(anyhow::anyhow!("Invalid token type for refresh"));
        }

        // Generate new access token
        self.generate_access_token(&claims.sub, &claims.email, &claims.role)
    }

    /// Blacklist a token (logout functionality)
    pub fn blacklist_token(&mut self, token: &str) -> Result<()> {
        let claims = self.decode_token_without_validation(token)?;
        self.blacklist.insert(claims.jti);
        Ok(())
    }

    /// Check if a token is blacklisted
    pub fn is_token_blacklisted(&self, token: &str) -> bool {
        if let Ok(claims) = self.decode_token_without_validation(token) {
            self.blacklist.contains(&claims.jti)
        } else {
            true // Consider invalid tokens as blacklisted
        }
    }

    /// Extract user ID from token without full validation
    pub fn extract_user_id(&self, token: &str) -> Result<String> {
        let claims = self.decode_token_without_validation(token)?;
        Ok(claims.sub)
    }

    /// Get token expiration time
    pub fn get_token_expiration(&self, token: &str) -> Result<i64> {
        let claims = self.decode_token_without_validation(token)?;
        Ok(claims.exp)
    }

    /// Check if token is expired
    pub fn is_token_expired(&self, token: &str) -> bool {
        if let Ok(exp) = self.get_token_expiration(token) {
            Utc::now().timestamp() > exp
        } else {
            true // Consider invalid tokens as expired
        }
    }
}

/// Token validation result for middleware
#[derive(Debug)]
pub enum TokenValidationResult {
    Valid(Claims),
    Expired,
    Invalid,
    Blacklisted,
}

impl JwtManager {
    /// Validate token and return detailed result for middleware
    pub fn validate_token_detailed(&self, token: &str) -> TokenValidationResult {
        // First check if blacklisted
        if self.is_token_blacklisted(token) {
            return TokenValidationResult::Blacklisted;
        }

        // Check if expired
        if self.is_token_expired(token) {
            return TokenValidationResult::Expired;
        }

        // Validate signature and claims
        match self.validate_token(token) {
            Ok(claims) => TokenValidationResult::Valid(claims),
            Err(_) => TokenValidationResult::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> JwtManager {
        JwtManager::new("test_secret_key_that_is_long_enough", 7, 30)
    }

    #[test]
    fn test_generate_access_token() {
        let manager = create_test_manager();
        let token = manager
            .generate_access_token("user123", "test@example.com", "user")
            .unwrap();

        assert!(!token.is_empty());
        assert!(token.contains('.'));
    }

    #[test]
    fn test_generate_refresh_token() {
        let manager = create_test_manager();
        let token = manager
            .generate_refresh_token("user123", "test@example.com", "user")
            .unwrap();

        assert!(!token.is_empty());
        assert!(token.contains('.'));
    }

    #[test]
    fn test_generate_token_pair() {
        let manager = create_test_manager();
        let (access_token, refresh_token) = manager
            .generate_token_pair("user123", "test@example.com", "user")
            .unwrap();

        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());
        assert_ne!(access_token, refresh_token);
    }

    #[test]
    fn test_validate_token() {
        let manager = create_test_manager();
        let token = manager
            .generate_access_token("user123", "test@example.com", "user")
            .unwrap();

        let claims = manager.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.role, "user");
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_refresh_access_token() {
        let manager = create_test_manager();
        let refresh_token = manager
            .generate_refresh_token("user123", "test@example.com", "user")
            .unwrap();

        let new_access_token = manager.refresh_access_token(&refresh_token).unwrap();
        let claims = manager.validate_token(&new_access_token).unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_blacklist_token() {
        let mut manager = create_test_manager();
        let token = manager
            .generate_access_token("user123", "test@example.com", "user")
            .unwrap();

        // Token should be valid initially
        assert!(manager.validate_token(&token).is_ok());

        // Blacklist the token
        manager.blacklist_token(&token).unwrap();

        // Token should now be invalid
        assert!(manager.validate_token(&token).is_err());
        assert!(manager.is_token_blacklisted(&token));
    }

    #[test]
    fn test_invalid_token() {
        let manager = create_test_manager();
        let invalid_token = "invalid.token.here";

        assert!(manager.validate_token(invalid_token).is_err());
    }

    #[test]
    fn test_token_validation_detailed() {
        let mut manager = create_test_manager();
        let token = manager
            .generate_access_token("user123", "test@example.com", "user")
            .unwrap();

        // Should be valid initially
        match manager.validate_token_detailed(&token) {
            TokenValidationResult::Valid(claims) => {
                assert_eq!(claims.sub, "user123");
            }
            _ => panic!("Token should be valid"),
        }

        // Blacklist and test
        manager.blacklist_token(&token).unwrap();
        match manager.validate_token_detailed(&token) {
            TokenValidationResult::Blacklisted => {}
            _ => panic!("Token should be blacklisted"),
        }
    }
}

// Utility functions for simple JWT operations without manager
pub fn generate_token(
    user_id: &str,
    email: &str,
    role: &str,
    expiry_hours: i64,
    secret: &str,
) -> Result<String> {
    let now = Utc::now();
    let exp = now + Duration::hours(expiry_hours);

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        token_type: "access".to_string(),
    };

    let encoding_key = EncodingKey::from_secret(secret.as_ref());
    encode(&Header::default(), &claims, &encoding_key).context("Failed to generate token")
}

pub fn verify_token(token: &str, secret: &str) -> Result<Claims> {
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::default();

    let token_data =
        decode::<Claims>(token, &decoding_key, &validation).context("Failed to verify token")?;

    Ok(token_data.claims)
}
