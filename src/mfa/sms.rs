use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// SMS provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsConfig {
    pub provider: String,
    pub api_key: String,
    pub from_number: String,
    pub code_length: usize,
    pub expiry_minutes: u64,
}

/// SMS verification code
#[derive(Debug, Clone)]
pub struct SmsCode {
    pub code: String,
    pub phone_number: String,
    pub expires_at: SystemTime,
}

/// SMS provider for sending verification codes
#[derive(Debug, Clone)]
pub struct SmsProvider {
    config: SmsConfig,
    // In-memory storage for demo - replace with database in production
    pending_codes: std::sync::Arc<std::sync::Mutex<HashMap<String, SmsCode>>>,
}

impl SmsProvider {
    /// Create new SMS provider
    pub fn new(config: SmsConfig) -> Result<Self> {
        Ok(Self {
            config,
            pending_codes: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Send SMS verification code
    pub async fn send_code(&self, phone_number: &str, user_id: &str) -> Result<String> {
        let code = self.generate_code();
        let expires_at = SystemTime::now() + Duration::from_secs(self.config.expiry_minutes * 60);
        
        // Store the code
        {
            let mut codes = self.pending_codes.lock().unwrap();
            codes.insert(
                user_id.to_string(),
                SmsCode {
                    code: code.clone(),
                    phone_number: phone_number.to_string(),
                    expires_at,
                },
            );
        }

        // Send SMS based on provider
        match self.config.provider.as_str() {
            "twilio" => self.send_twilio_sms(phone_number, &code).await?,
            "aws_sns" => self.send_aws_sns_sms(phone_number, &code).await?,
            "mock" => {
                // Mock provider for testing - just log the code
                tracing::info!("SMS code for {}: {}", phone_number, code);
            }
            _ => return Err(anyhow::anyhow!("Unsupported SMS provider: {}", self.config.provider)),
        }

        Ok(code)
    }

    /// Verify SMS code
    pub fn verify_code(&self, user_id: &str, code: &str) -> Result<bool> {
        let mut codes = self.pending_codes.lock().unwrap();
        
        if let Some(stored_code) = codes.get(user_id) {
            if SystemTime::now() > stored_code.expires_at {
                codes.remove(user_id);
                return Ok(false);
            }
            
            if stored_code.code == code {
                codes.remove(user_id);
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    /// Generate random verification code
    fn generate_code(&self) -> String {
        let mut code = String::new();
        for _ in 0..self.config.code_length {
            code.push_str(&(rand::random::<u8>() % 10).to_string());
        }
        code
    }

    /// Send SMS via Twilio (placeholder implementation)
    async fn send_twilio_sms(&self, phone_number: &str, code: &str) -> Result<()> {
        // TODO: Implement actual Twilio integration
        tracing::info!("Would send Twilio SMS to {}: {}", phone_number, code);
        Ok(())
    }

    /// Send SMS via AWS SNS (placeholder implementation)
    async fn send_aws_sns_sms(&self, phone_number: &str, code: &str) -> Result<()> {
        // TODO: Implement actual AWS SNS integration
        tracing::info!("Would send AWS SNS SMS to {}: {}", phone_number, code);
        Ok(())
    }

    /// Clean up expired codes
    pub fn cleanup_expired(&self) {
        let mut codes = self.pending_codes.lock().unwrap();
        let now = SystemTime::now();
        codes.retain(|_, code| now <= code.expires_at);
    }

    /// Format phone number to international format
    pub fn format_phone_number(&self, phone: &str) -> Result<String> {
        let cleaned = phone.chars().filter(|c| c.is_ascii_digit()).collect::<String>();
        
        if cleaned.len() < 10 || cleaned.len() > 15 {
            return Err(anyhow::anyhow!("Invalid phone number length"));
        }
        
        // Add country code if missing (assumes US +1)
        if cleaned.len() == 10 {
            Ok(format!("+1{}", cleaned))
        } else if cleaned.len() == 11 && cleaned.starts_with('1') {
            Ok(format!("+{}", cleaned))
        } else {
            Ok(format!("+{}", cleaned))
        }
    }

    /// Validate phone number format
    pub fn validate_phone_number(&self, phone: &str) -> bool {
        self.format_phone_number(phone).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_provider() -> SmsProvider {
        let config = SmsConfig {
            provider: "mock".to_string(),
            api_key: "test".to_string(),
            from_number: "+1234567890".to_string(),
            code_length: 6,
            expiry_minutes: 5,
        };
        SmsProvider::new(config).unwrap()
    }

    #[tokio::test]
    async fn test_sms_code_generation_and_verification() {
        let provider = create_test_provider();
        let phone = "+1234567890";
        let user_id = "test_user";
        
        // Send code
        let code = provider.send_code(phone, user_id).await.unwrap();
        assert_eq!(code.len(), 6);
        
        // Verify correct code
        assert!(provider.verify_code(user_id, &code).unwrap());
        
        // Code should be consumed after verification
        assert!(!provider.verify_code(user_id, &code).unwrap());
    }

    #[test]
    fn test_phone_number_formatting() {
        let provider = create_test_provider();
        
        assert_eq!(provider.format_phone_number("1234567890").unwrap(), "+11234567890");
        assert_eq!(provider.format_phone_number("11234567890").unwrap(), "+11234567890");
        assert_eq!(provider.format_phone_number("+11234567890").unwrap(), "+11234567890");
        
        assert!(provider.format_phone_number("123").is_err());
        assert!(provider.format_phone_number("123456789012345678").is_err());
    }

    #[test]
    fn test_phone_number_validation() {
        let provider = create_test_provider();
        
        assert!(provider.validate_phone_number("1234567890"));
        assert!(provider.validate_phone_number("+11234567890"));
        assert!(!provider.validate_phone_number("123"));
        assert!(!provider.validate_phone_number("invalid"));
    }
}