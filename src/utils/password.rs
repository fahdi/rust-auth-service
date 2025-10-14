use anyhow::{Context, Result};
use bcrypt::{hash, verify, DEFAULT_COST};
use rand::{distributions::Alphanumeric, Rng};

#[derive(Debug, Clone)]
pub struct PasswordManager {
    cost: u32,
}

impl PasswordManager {
    /// Create a new password manager with the specified bcrypt cost
    pub fn new(cost: u32) -> Self {
        Self { cost }
    }

    /// Create a new password manager with default cost
    pub fn default() -> Self {
        Self::new(DEFAULT_COST)
    }

    /// Hash a password using bcrypt
    pub fn hash_password(&self, password: &str) -> Result<String> {
        hash(password, self.cost).context("Failed to hash password")
    }

    /// Verify a password against its hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        verify(password, hash).context("Failed to verify password")
    }

    /// Generate a secure random password
    pub fn generate_random_password(&self, length: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    /// Generate a secure reset token
    pub fn generate_reset_token(&self) -> String {
        self.generate_random_password(32)
    }

    /// Generate a secure email verification token
    pub fn generate_verification_token(&self) -> String {
        self.generate_random_password(32)
    }

    /// Validate password strength
    pub fn validate_password_strength(&self, password: &str) -> PasswordValidationResult {
        let mut issues = Vec::new();

        if password.len() < 8 {
            issues.push("Password must be at least 8 characters long".to_string());
        }

        if password.len() > 128 {
            issues.push("Password must not exceed 128 characters".to_string());
        }

        if !password.chars().any(|c| c.is_ascii_lowercase()) {
            issues.push("Password must contain at least one lowercase letter".to_string());
        }

        if !password.chars().any(|c| c.is_ascii_uppercase()) {
            issues.push("Password must contain at least one uppercase letter".to_string());
        }

        if !password.chars().any(|c| c.is_ascii_digit()) {
            issues.push("Password must contain at least one digit".to_string());
        }

        if !password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
        {
            issues.push("Password must contain at least one special character".to_string());
        }

        // Check for common weak patterns
        if self.contains_common_patterns(password) {
            issues.push("Password contains common patterns and may be easily guessed".to_string());
        }

        if issues.is_empty() {
            PasswordValidationResult::Valid
        } else {
            PasswordValidationResult::Invalid(issues)
        }
    }

    /// Check for common weak password patterns
    fn contains_common_patterns(&self, password: &str) -> bool {
        let password_lower = password.to_lowercase();

        // Common weak patterns
        let weak_patterns = [
            "password",
            "123456",
            "qwerty",
            "abc123",
            "admin",
            "test",
            "user",
            "guest",
            "root",
            "default",
            "login",
            "pass",
            "12345678",
            "password123",
            "admin123",
            "qwerty123",
        ];

        weak_patterns
            .iter()
            .any(|&pattern| password_lower.contains(pattern))
    }

    /// Calculate password strength score (0-100)
    pub fn calculate_password_strength(&self, password: &str) -> PasswordStrength {
        let mut score = 0;
        let mut feedback = Vec::new();

        // Length scoring
        match password.len() {
            0..=7 => {
                feedback.push("Password is too short".to_string());
            }
            8..=11 => {
                score += 20;
                feedback.push("Password length is acceptable".to_string());
            }
            12..=15 => {
                score += 30;
                feedback.push("Good password length".to_string());
            }
            _ => {
                score += 40;
                feedback.push("Excellent password length".to_string());
            }
        }

        // Character variety scoring
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

        let char_types = [has_lower, has_upper, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();

        score += char_types * 10;

        if char_types >= 3 {
            feedback.push("Good character variety".to_string());
        } else {
            feedback.push(
                "Use more character types (uppercase, lowercase, digits, symbols)".to_string(),
            );
        }

        // Penalty for common patterns
        if self.contains_common_patterns(password) {
            score = score.saturating_sub(30);
            feedback.push("Avoid common password patterns".to_string());
        }

        // Penalty for repetitive patterns
        if self.has_repetitive_patterns(password) {
            score = score.saturating_sub(20);
            feedback.push("Avoid repetitive character patterns".to_string());
        }

        // Bonus for entropy
        let entropy = self.calculate_entropy(password);
        if entropy > 50.0 {
            score += 10;
            feedback.push("High entropy - excellent randomness".to_string());
        }

        let strength_level = match score {
            0..=30 => StrengthLevel::Weak,
            31..=60 => StrengthLevel::Fair,
            61..=80 => StrengthLevel::Good,
            81..=90 => StrengthLevel::Strong,
            _ => StrengthLevel::VeryStrong,
        };

        PasswordStrength {
            score: (score.min(100) as u32),
            level: strength_level,
            feedback,
            entropy,
        }
    }

    /// Check for repetitive patterns in password
    fn has_repetitive_patterns(&self, password: &str) -> bool {
        // Check for repeated characters (more than 3 in a row)
        let chars: Vec<char> = password.chars().collect();
        for window in chars.windows(4) {
            if window.iter().all(|&c| c == window[0]) {
                return true;
            }
        }

        // Check for sequential patterns
        for window in chars.windows(3) {
            if let (Some(a), Some(b), Some(c)) = (
                window[0].to_digit(36),
                window[1].to_digit(36),
                window[2].to_digit(36),
            ) {
                if b == a + 1 && c == b + 1 {
                    return true; // Sequential numbers/letters
                }
            }
        }

        false
    }

    /// Calculate password entropy
    fn calculate_entropy(&self, password: &str) -> f64 {
        if password.is_empty() {
            return 0.0;
        }

        let mut charset_size = 0;

        if password.chars().any(|c| c.is_ascii_lowercase()) {
            charset_size += 26;
        }
        if password.chars().any(|c| c.is_ascii_uppercase()) {
            charset_size += 26;
        }
        if password.chars().any(|c| c.is_ascii_digit()) {
            charset_size += 10;
        }
        if password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
        {
            charset_size += 32;
        }

        if charset_size == 0 {
            return 0.0;
        }

        password.len() as f64 * (charset_size as f64).log2()
    }
}

#[derive(Debug)]
pub enum PasswordValidationResult {
    Valid,
    Invalid(Vec<String>),
}

#[derive(Debug)]
pub struct PasswordStrength {
    pub score: u32,
    pub level: StrengthLevel,
    pub feedback: Vec<String>,
    pub entropy: f64,
}

#[derive(Debug, PartialEq)]
pub enum StrengthLevel {
    Weak,
    Fair,
    Good,
    Strong,
    VeryStrong,
}

impl std::fmt::Display for StrengthLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StrengthLevel::Weak => write!(f, "Weak"),
            StrengthLevel::Fair => write!(f, "Fair"),
            StrengthLevel::Good => write!(f, "Good"),
            StrengthLevel::Strong => write!(f, "Strong"),
            StrengthLevel::VeryStrong => write!(f, "Very Strong"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> PasswordManager {
        PasswordManager::new(4) // Lower cost for faster tests
    }

    #[test]
    fn test_hash_password() {
        let manager = create_test_manager();
        let password = "test_password_123";
        let hash = manager.hash_password(password).unwrap();

        assert!(!hash.is_empty());
        assert!(hash.starts_with("$2b$"));
        assert_ne!(hash, password);
    }

    #[test]
    fn test_verify_password() {
        let manager = create_test_manager();
        let password = "test_password_123";
        let hash = manager.hash_password(password).unwrap();

        assert!(manager.verify_password(password, &hash).unwrap());
        assert!(!manager.verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_generate_random_password() {
        let manager = create_test_manager();
        let password1 = manager.generate_random_password(16);
        let password2 = manager.generate_random_password(16);

        assert_eq!(password1.len(), 16);
        assert_eq!(password2.len(), 16);
        assert_ne!(password1, password2);
    }

    #[test]
    fn test_generate_tokens() {
        let manager = create_test_manager();
        let reset_token = manager.generate_reset_token();
        let verification_token = manager.generate_verification_token();

        assert_eq!(reset_token.len(), 32);
        assert_eq!(verification_token.len(), 32);
        assert_ne!(reset_token, verification_token);
    }

    #[test]
    fn test_password_validation() {
        let manager = create_test_manager();

        // Valid password
        match manager.validate_password_strength("MySecureK3y!") {
            PasswordValidationResult::Valid => {}
            _ => panic!("Password should be valid"),
        }

        // Invalid password (too short)
        match manager.validate_password_strength("short") {
            PasswordValidationResult::Invalid(issues) => {
                assert!(!issues.is_empty());
            }
            _ => panic!("Password should be invalid"),
        }
    }

    #[test]
    fn test_password_strength_calculation() {
        let manager = create_test_manager();

        let weak_strength = manager.calculate_password_strength("password");
        assert_eq!(weak_strength.level, StrengthLevel::Weak);

        let strong_strength = manager.calculate_password_strength("MyVerySecureP@ssw0rd2024!");
        assert!(matches!(
            strong_strength.level,
            StrengthLevel::Strong | StrengthLevel::VeryStrong
        ));
        assert!(strong_strength.score > 70);
    }

    #[test]
    fn test_common_patterns_detection() {
        let manager = create_test_manager();

        assert!(manager.contains_common_patterns("password123"));
        assert!(manager.contains_common_patterns("admin"));
        assert!(manager.contains_common_patterns("MyPassword"));
        assert!(!manager.contains_common_patterns("MySecureP@ssw0rd"));
    }

    #[test]
    fn test_repetitive_patterns() {
        let manager = create_test_manager();

        assert!(manager.has_repetitive_patterns("aaaa"));
        assert!(manager.has_repetitive_patterns("abc123"));
        assert!(!manager.has_repetitive_patterns("MySecurePassword"));
    }

    #[test]
    fn test_entropy_calculation() {
        let manager = create_test_manager();

        let entropy1 = manager.calculate_entropy("password");
        let entropy2 = manager.calculate_entropy("MyVerySecureP@ssw0rd!");

        assert!(entropy2 > entropy1);
        assert!(entropy2 > 50.0);
    }
}

// Utility functions for simple password operations
pub fn hash_password(password: &str) -> Result<String> {
    let manager = PasswordManager::default();
    manager.hash_password(password)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let manager = PasswordManager::default();
    manager.verify_password(password, hash)
}
