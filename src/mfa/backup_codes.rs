use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Backup code configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCodeConfig {
    pub count: usize,
    pub length: usize,
    pub format: BackupCodeFormat,
}

/// Backup code format options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupCodeFormat {
    Numeric,       // 12345678
    Alphanumeric,  // AB12CD34
    Hex,          // A1B2C3D4
}

/// Backup code with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCode {
    pub code: String,
    pub hash: String,
    pub used: bool,
    pub used_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for BackupCodeConfig {
    fn default() -> Self {
        Self {
            count: 8,
            length: 8,
            format: BackupCodeFormat::Alphanumeric,
        }
    }
}

/// Generate backup codes
pub fn generate_backup_codes(count: usize, length: usize) -> Vec<String> {
    let mut codes = Vec::with_capacity(count);
    let mut used_codes = HashSet::new();
    
    while codes.len() < count {
        let code = generate_single_code(length, &BackupCodeFormat::Alphanumeric);
        if used_codes.insert(code.clone()) {
            codes.push(code);
        }
    }
    
    codes
}

/// Generate backup codes with configuration
pub fn generate_backup_codes_with_config(config: &BackupCodeConfig) -> Vec<BackupCode> {
    let mut codes = Vec::with_capacity(config.count);
    let mut used_codes = HashSet::new();
    
    while codes.len() < config.count {
        let code = generate_single_code(config.length, &config.format);
        if used_codes.insert(code.clone()) {
            let hash = hash_backup_code(&code);
            codes.push(BackupCode {
                code: code.clone(),
                hash,
                used: false,
                used_at: None,
            });
        }
    }
    
    codes
}

/// Generate a single backup code
fn generate_single_code(length: usize, format: &BackupCodeFormat) -> String {
    let mut rng = rand::thread_rng();
    
    match format {
        BackupCodeFormat::Numeric => {
            (0..length)
                .map(|_| rng.gen_range(0..10).to_string())
                .collect()
        }
        BackupCodeFormat::Alphanumeric => {
            const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            (0..length)
                .map(|_| {
                    let idx = rng.gen_range(0..CHARS.len());
                    CHARS[idx] as char
                })
                .collect()
        }
        BackupCodeFormat::Hex => {
            const HEX_CHARS: &[u8] = b"0123456789ABCDEF";
            (0..length)
                .map(|_| {
                    let idx = rng.gen_range(0..HEX_CHARS.len());
                    HEX_CHARS[idx] as char
                })
                .collect()
        }
    }
}

/// Hash backup code for secure storage
pub fn hash_backup_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Verify backup code against hash
pub fn verify_backup_code(code: &str, hash: &str) -> bool {
    hash_backup_code(code) == hash
}

/// Format backup codes for display
pub fn format_backup_codes_for_display(codes: &[String]) -> Vec<String> {
    codes
        .iter()
        .map(|code| {
            // Insert dashes every 4 characters for readability
            if code.len() > 4 {
                let mut formatted = String::new();
                for (i, c) in code.chars().enumerate() {
                    if i > 0 && i % 4 == 0 {
                        formatted.push('-');
                    }
                    formatted.push(c);
                }
                formatted
            } else {
                code.clone()
            }
        })
        .collect()
}

/// Validate backup code format
pub fn validate_backup_code_format(code: &str, config: &BackupCodeConfig) -> Result<()> {
    let cleaned_code = code.replace(['-', ' '], "");
    
    if cleaned_code.len() != config.length {
        return Err(anyhow::anyhow!(
            "Backup code must be {} characters long",
            config.length
        ));
    }
    
    match config.format {
        BackupCodeFormat::Numeric => {
            if !cleaned_code.chars().all(|c| c.is_ascii_digit()) {
                return Err(anyhow::anyhow!("Backup code must contain only digits"));
            }
        }
        BackupCodeFormat::Alphanumeric => {
            if !cleaned_code.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(anyhow::anyhow!("Backup code must contain only letters and numbers"));
            }
        }
        BackupCodeFormat::Hex => {
            if !cleaned_code.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(anyhow::anyhow!("Backup code must contain only hexadecimal characters"));
            }
        }
    }
    
    Ok(())
}

/// Clean up backup code input (remove spaces, dashes, convert to uppercase)
pub fn clean_backup_code_input(code: &str) -> String {
    code.replace(['-', ' '], "").to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_code_generation() {
        let codes = generate_backup_codes(8, 8);
        assert_eq!(codes.len(), 8);
        
        // All codes should be unique
        let unique_codes: HashSet<_> = codes.iter().collect();
        assert_eq!(unique_codes.len(), 8);
        
        // All codes should be 8 characters
        for code in &codes {
            assert_eq!(code.len(), 8);
        }
    }

    #[test]
    fn test_backup_code_generation_with_config() {
        let config = BackupCodeConfig {
            count: 10,
            length: 12,
            format: BackupCodeFormat::Numeric,
        };
        
        let codes = generate_backup_codes_with_config(&config);
        assert_eq!(codes.len(), 10);
        
        for backup_code in &codes {
            assert_eq!(backup_code.code.len(), 12);
            assert!(backup_code.code.chars().all(|c| c.is_ascii_digit()));
            assert!(!backup_code.used);
            assert!(backup_code.used_at.is_none());
        }
    }

    #[test]
    fn test_backup_code_hashing_and_verification() {
        let code = "ABC12345";
        let hash = hash_backup_code(code);
        
        assert!(verify_backup_code(code, &hash));
        assert!(!verify_backup_code("wrong", &hash));
    }

    #[test]
    fn test_backup_code_formatting() {
        let codes = vec!["ABC12345".to_string(), "XYZ98765".to_string()];
        let formatted = format_backup_codes_for_display(&codes);
        
        assert_eq!(formatted[0], "ABC1-2345");
        assert_eq!(formatted[1], "XYZ9-8765");
    }

    #[test]
    fn test_backup_code_validation() {
        let config = BackupCodeConfig::default();
        
        assert!(validate_backup_code_format("ABC12345", &config).is_ok());
        assert!(validate_backup_code_format("ABC1-2345", &config).is_ok());
        assert!(validate_backup_code_format("ABC1 2345", &config).is_ok());
        
        assert!(validate_backup_code_format("ABC123", &config).is_err()); // Too short
        assert!(validate_backup_code_format("ABC12345XYZ", &config).is_err()); // Too long
    }

    #[test]
    fn test_backup_code_cleaning() {
        assert_eq!(clean_backup_code_input("abc1-2345"), "ABC12345");
        assert_eq!(clean_backup_code_input("ABC1 2345"), "ABC12345");
        assert_eq!(clean_backup_code_input("abc1 2-3 45"), "ABC12345");
    }
}