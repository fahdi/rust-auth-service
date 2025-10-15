use anyhow::Result;
use base32::Alphabet;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp, Sha1};

/// TOTP provider for generating and validating time-based one-time passwords
#[derive(Debug, Clone)]
pub struct TotpProvider {
    pub digits: usize,
    pub window: i64,
}

/// TOTP secret and QR code data
#[derive(Debug, Serialize, Deserialize)]
pub struct TotpSetup {
    pub secret: String,
    pub qr_code: String,
    pub backup_codes: Vec<String>,
}

impl TotpProvider {
    /// Create new TOTP provider
    pub fn new(digits: usize, window: i64) -> Result<Self> {
        Ok(Self { digits, window })
    }

    /// Generate a new TOTP secret
    pub fn generate_secret(&self) -> String {
        let secret_bytes: Vec<u8> = (0..20).map(|_| rand::random::<u8>()).collect();
        base32::encode(Alphabet::Rfc4648 { padding: false }, &secret_bytes)
    }

    /// Generate TOTP setup data including QR code
    pub fn setup_totp(&self, secret: &str, account: &str, issuer: &str) -> Result<TotpSetup> {
        // Create TOTP URI for QR code
        let uri = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&digits={}&period=30",
            issuer, account, secret, issuer, self.digits
        );

        // Generate QR code
        let qr_code = qrcode::QrCode::new(&uri)?;
        let image = qr_code.render::<qrcode::render::unicode::Dense1x2>().build();

        Ok(TotpSetup {
            secret: secret.to_string(),
            qr_code: image,
            backup_codes: self.generate_backup_codes(),
        })
    }

    /// Generate TOTP code from secret
    pub fn generate_code(&self, secret: &str) -> Result<String> {
        let secret_bytes = base32::decode(Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| anyhow::anyhow!("Invalid base32 secret"))?;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        let code = totp::<Sha1>(&secret_bytes, timestamp / 30);
        // Pad to specified digits
        Ok(format!("{:0width$}", code.parse::<u32>().unwrap_or(0) % 10_u32.pow(self.digits as u32), width = self.digits))
    }

    /// Verify TOTP code
    pub fn verify_code(&self, secret: &str, code: &str) -> Result<bool> {
        let secret_bytes = base32::decode(Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| anyhow::anyhow!("Invalid base32 secret"))?;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        // Check current time window and adjacent windows for clock skew
        for window_offset in -self.window..=self.window {
            let adjusted_timestamp = timestamp as i64 + (window_offset * 30);
            if adjusted_timestamp < 0 {
                continue;
            }
            
            let expected_code = totp::<Sha1>(&secret_bytes, adjusted_timestamp as u64 / 30);
            let formatted_code = format!("{:0width$}", expected_code.parse::<u32>().unwrap_or(0) % 10_u32.pow(self.digits as u32), width = self.digits);
            if formatted_code == code {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Generate backup codes
    fn generate_backup_codes(&self) -> Vec<String> {
        (0..8).map(|_| {
            format!("{:08}", rand::random::<u32>() % 100_000_000)
        }).collect()
    }

    /// Validate TOTP secret format
    pub fn validate_secret(&self, secret: &str) -> bool {
        base32::decode(Alphabet::Rfc4648 { padding: false }, secret).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation_and_verification() {
        let provider = TotpProvider::new(6, 1).unwrap();
        let secret = provider.generate_secret();
        
        // Generate a code
        let code = provider.generate_code(&secret).unwrap();
        assert_eq!(code.len(), 6);
        
        // Verify the code
        assert!(provider.verify_code(&secret, &code).unwrap());
        
        // Verify invalid code fails
        assert!(!provider.verify_code(&secret, "123456").unwrap());
    }

    #[test]
    fn test_totp_setup() {
        let provider = TotpProvider::new(6, 1).unwrap();
        let secret = provider.generate_secret();
        
        let setup = provider.setup_totp(&secret, "user@example.com", "AuthService").unwrap();
        assert_eq!(setup.secret, secret);
        assert!(!setup.qr_code.is_empty());
        assert_eq!(setup.backup_codes.len(), 8);
    }

    #[test]
    fn test_secret_validation() {
        let provider = TotpProvider::new(6, 1).unwrap();
        let valid_secret = provider.generate_secret();
        
        assert!(provider.validate_secret(&valid_secret));
        assert!(!provider.validate_secret("invalid-secret"));
    }
}