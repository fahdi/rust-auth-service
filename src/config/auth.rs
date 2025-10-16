use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt: JwtConfig,
    pub password: PasswordConfig,
    pub verification: VerificationConfig,
    pub jwt_secret: String,
    pub password_hash_rounds: u32,
    pub session_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordConfig {
    pub bcrypt_rounds: u32,
    pub min_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    pub token_expiry_hours: u64,
    pub required: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt: JwtConfig::default(),
            password: PasswordConfig::default(),
            verification: VerificationConfig::default(),
            jwt_secret: "your-secret-key-change-in-production".to_string(),
            password_hash_rounds: 12,
            session_timeout: 3600, // 1 hour
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "your-secret-key-change-in-production".to_string(),
            expiration_days: 7,
        }
    }
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            bcrypt_rounds: 12,
            min_length: 6,
        }
    }
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            token_expiry_hours: 24,
            required: true,
        }
    }
}
