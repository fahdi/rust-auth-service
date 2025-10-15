use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use validator::ValidateEmail;

#[derive(Debug, Clone)]
pub struct InputValidator {
    email_regex: Regex,
    name_regex: Regex,
}

impl InputValidator {
    pub fn new() -> Result<Self> {
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .context("Failed to compile email regex")?;
        let name_regex =
            Regex::new(r"^[a-zA-Z\s'-]{1,50}$").context("Failed to compile name regex")?;

        Ok(Self {
            email_regex,
            name_regex,
        })
    }

    /// Validate email address
    pub fn validate_email(&self, email: &str) -> ValidationResult {
        let mut errors = Vec::new();

        if email.is_empty() {
            errors.push("Email is required".to_string());
            return ValidationResult::Invalid(errors);
        }

        if email.len() > 254 {
            errors.push("Email must not exceed 254 characters".to_string());
        }

        if !email.validate_email() || !self.email_regex.is_match(email) {
            errors.push("Invalid email format".to_string());
        }

        // Check for common email issues
        if email.contains("..") {
            errors.push("Email cannot contain consecutive dots".to_string());
        }

        if email.starts_with('.') || email.ends_with('.') {
            errors.push("Email cannot start or end with a dot".to_string());
        }

        if errors.is_empty() {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid(errors)
        }
    }

    /// Validate user name (first name, last name)
    pub fn validate_name(&self, name: &str, field_name: &str) -> ValidationResult {
        let mut errors = Vec::new();

        if name.is_empty() {
            errors.push(format!("{} is required", field_name));
            return ValidationResult::Invalid(errors);
        }

        if name.len() < 2 {
            errors.push(format!("{} must be at least 2 characters long", field_name));
        }

        if name.len() > 50 {
            errors.push(format!("{} must not exceed 50 characters", field_name));
        }

        if !self.name_regex.is_match(name) {
            errors.push(format!(
                "{} can only contain letters, spaces, hyphens, and apostrophes",
                field_name
            ));
        }

        // Check for suspicious patterns
        if name.chars().all(|c| c.is_ascii_digit()) {
            errors.push(format!("{} cannot be all numbers", field_name));
        }

        if errors.is_empty() {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid(errors)
        }
    }

    /// Validate user role
    pub fn validate_role(&self, role: &str) -> ValidationResult {
        let valid_roles = ["user", "admin", "moderator", "guest"];

        if role.is_empty() {
            return ValidationResult::Invalid(vec!["Role is required".to_string()]);
        }

        if !valid_roles.contains(&role.to_lowercase().as_str()) {
            return ValidationResult::Invalid(vec![format!(
                "Invalid role. Must be one of: {}",
                valid_roles.join(", ")
            )]);
        }

        ValidationResult::Valid
    }

    /// Sanitize input by removing potentially harmful characters
    pub fn sanitize_input(&self, input: &str) -> String {
        input
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
            .collect::<String>()
            .trim()
            .to_string()
    }

    /// Validate and sanitize email
    pub fn process_email(&self, email: &str) -> Result<String, Vec<String>> {
        let sanitized = self.sanitize_input(email).to_lowercase();

        match self.validate_email(&sanitized) {
            ValidationResult::Valid => Ok(sanitized),
            ValidationResult::Invalid(errors) => Err(errors),
        }
    }

    /// Validate and sanitize name
    pub fn process_name(&self, name: &str, field_name: &str) -> Result<String, Vec<String>> {
        let sanitized = self.sanitize_input(name);

        match self.validate_name(&sanitized, field_name) {
            ValidationResult::Valid => Ok(sanitized),
            ValidationResult::Invalid(errors) => Err(errors),
        }
    }

    /// Validate user ID format
    pub fn validate_user_id(&self, user_id: &str) -> ValidationResult {
        if user_id.is_empty() {
            return ValidationResult::Invalid(vec!["User ID is required".to_string()]);
        }

        if user_id.len() < 8 || user_id.len() > 36 {
            return ValidationResult::Invalid(vec![
                "User ID must be between 8 and 36 characters".to_string()
            ]);
        }

        // Check if it's a valid UUID format or custom ID format
        let uuid_regex = Regex::new(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        )
        .unwrap();
        let custom_id_regex = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();

        if !uuid_regex.is_match(user_id) && !custom_id_regex.is_match(user_id) {
            return ValidationResult::Invalid(vec![
                "User ID must be a valid UUID or contain only alphanumeric characters, hyphens, and underscores".to_string()
            ]);
        }

        ValidationResult::Valid
    }

    /// Validate token format
    pub fn validate_token(&self, token: &str) -> ValidationResult {
        if token.is_empty() {
            return ValidationResult::Invalid(vec!["Token is required".to_string()]);
        }

        if token.len() < 16 {
            return ValidationResult::Invalid(vec![
                "Token must be at least 16 characters long".to_string()
            ]);
        }

        if token.len() > 512 {
            return ValidationResult::Invalid(vec![
                "Token must not exceed 512 characters".to_string()
            ]);
        }

        // Check for JWT format (3 parts separated by dots)
        if token.matches('.').count() == 2 {
            let parts: Vec<&str> = token.split('.').collect();
            if parts.iter().all(|part| !part.is_empty()) {
                return ValidationResult::Valid;
            }
        }

        // Check for alphanumeric token format
        let token_regex = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
        if token_regex.is_match(token) {
            return ValidationResult::Valid;
        }

        ValidationResult::Invalid(vec!["Token format is invalid".to_string()])
    }

    /// Comprehensive validation for user registration
    pub fn validate_registration(
        &self,
        email: &str,
        first_name: &str,
        last_name: &str,
        role: Option<&str>,
    ) -> ValidationSummary {
        let mut errors = HashMap::new();
        let mut sanitized = HashMap::new();

        // Validate and process email
        match self.process_email(email) {
            Ok(clean_email) => {
                sanitized.insert("email".to_string(), clean_email);
            }
            Err(email_errors) => {
                errors.insert("email".to_string(), email_errors);
            }
        }

        // Validate and process first name
        match self.process_name(first_name, "First name") {
            Ok(clean_name) => {
                sanitized.insert("first_name".to_string(), clean_name);
            }
            Err(name_errors) => {
                errors.insert("first_name".to_string(), name_errors);
            }
        }

        // Validate and process last name
        match self.process_name(last_name, "Last name") {
            Ok(clean_name) => {
                sanitized.insert("last_name".to_string(), clean_name);
            }
            Err(name_errors) => {
                errors.insert("last_name".to_string(), name_errors);
            }
        }

        // Validate role if provided
        if let Some(role) = role {
            match self.validate_role(role) {
                ValidationResult::Valid => {
                    sanitized.insert("role".to_string(), role.to_lowercase());
                }
                ValidationResult::Invalid(role_errors) => {
                    errors.insert("role".to_string(), role_errors);
                }
            }
        } else {
            sanitized.insert("role".to_string(), "user".to_string()); // Default role
        }

        ValidationSummary {
            is_valid: errors.is_empty(),
            errors,
            sanitized,
        }
    }

    /// Rate limiting validation
    pub fn validate_rate_limit_key(&self, key: &str) -> ValidationResult {
        if key.is_empty() {
            return ValidationResult::Invalid(vec!["Rate limit key is required".to_string()]);
        }

        if key.len() > 100 {
            return ValidationResult::Invalid(vec![
                "Rate limit key must not exceed 100 characters".to_string(),
            ]);
        }

        let key_regex = Regex::new(r"^[a-zA-Z0-9._:-]+$").unwrap();
        if !key_regex.is_match(key) {
            return ValidationResult::Invalid(vec![
                "Rate limit key contains invalid characters".to_string()
            ]);
        }

        ValidationResult::Valid
    }
}

impl Default for InputValidator {
    fn default() -> Self {
        Self::new().expect("Failed to create default InputValidator")
    }
}

#[derive(Debug)]
pub enum ValidationResult {
    Valid,
    Invalid(Vec<String>),
}

#[derive(Debug)]
pub struct ValidationSummary {
    pub is_valid: bool,
    pub errors: HashMap<String, Vec<String>>,
    pub sanitized: HashMap<String, String>,
}

impl ValidationSummary {
    pub fn get_error_messages(&self) -> Vec<String> {
        self.errors
            .values()
            .flat_map(|errors| errors.iter())
            .cloned()
            .collect()
    }

    pub fn has_field_error(&self, field: &str) -> bool {
        self.errors.contains_key(field)
    }

    pub fn get_field_errors(&self, field: &str) -> Option<&Vec<String>> {
        self.errors.get(field)
    }

    pub fn get_sanitized_value(&self, field: &str) -> Option<&String> {
        self.sanitized.get(field)
    }
}

/// Standalone password strength validation function
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    let mut errors = Vec::new();
    
    if password.len() < 8 {
        errors.push("Password must be at least 8 characters long".to_string());
    }
    
    if password.len() > 128 {
        errors.push("Password must not exceed 128 characters".to_string());
    }
    
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    if !has_lowercase {
        errors.push("Password must contain at least one lowercase letter".to_string());
    }
    
    if !has_uppercase {
        errors.push("Password must contain at least one uppercase letter".to_string());
    }
    
    if !has_digit {
        errors.push("Password must contain at least one digit".to_string());
    }
    
    if !has_special {
        errors.push("Password must contain at least one special character".to_string());
    }
    
    // Check for common weak patterns
    let lower_password = password.to_lowercase();
    let weak_patterns = vec![
        "password", "123456", "qwerty", "abc123", "letmein", 
        "admin", "welcome", "monkey", "dragon", "master"
    ];
    
    for pattern in weak_patterns {
        if lower_password.contains(pattern) {
            errors.push("Password contains common weak patterns".to_string());
            break;
        }
    }
    
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Standalone email validation function  
pub fn validate_email(email: &str) -> Result<(), String> {
    if email.is_empty() {
        return Err("Email is required".to_string());
    }
    
    if email.len() > 254 {
        return Err("Email must not exceed 254 characters".to_string());
    }
    
    if !email.validate_email() {
        return Err("Invalid email format".to_string());
    }
    
    Ok(())
}

/// Utility functions for common validation tasks
pub mod utils {
    

    /// Check if a string is a valid URL
    pub fn is_valid_url(url: &str) -> bool {
        url::Url::parse(url).is_ok()
    }

    /// Check if a string contains only printable ASCII characters
    pub fn is_printable_ascii(input: &str) -> bool {
        input
            .chars()
            .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
    }

    /// Truncate string to maximum length
    pub fn truncate_string(input: &str, max_length: usize) -> String {
        if input.len() <= max_length {
            input.to_string()
        } else {
            input.chars().take(max_length).collect()
        }
    }

    /// Remove extra whitespace from string
    pub fn normalize_whitespace(input: &str) -> String {
        input.split_whitespace().collect::<Vec<&str>>().join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_validator() -> InputValidator {
        InputValidator::new().unwrap()
    }

    #[test]
    fn test_valid_email() {
        let validator = create_validator();
        match validator.validate_email("test@example.com") {
            ValidationResult::Valid => {}
            _ => panic!("Valid email should pass validation"),
        }
    }

    #[test]
    fn test_invalid_email() {
        let validator = create_validator();
        match validator.validate_email("invalid-email") {
            ValidationResult::Invalid(errors) => {
                assert!(!errors.is_empty());
            }
            _ => panic!("Invalid email should fail validation"),
        }
    }

    #[test]
    fn test_valid_name() {
        let validator = create_validator();
        match validator.validate_name("John", "First name") {
            ValidationResult::Valid => {}
            _ => panic!("Valid name should pass validation"),
        }
    }

    #[test]
    fn test_invalid_name() {
        let validator = create_validator();
        match validator.validate_name("J", "First name") {
            ValidationResult::Invalid(errors) => {
                assert!(!errors.is_empty());
            }
            _ => panic!("Invalid name should fail validation"),
        }
    }

    #[test]
    fn test_valid_role() {
        let validator = create_validator();
        match validator.validate_role("user") {
            ValidationResult::Valid => {}
            _ => panic!("Valid role should pass validation"),
        }
    }

    #[test]
    fn test_invalid_role() {
        let validator = create_validator();
        match validator.validate_role("invalid_role") {
            ValidationResult::Invalid(errors) => {
                assert!(!errors.is_empty());
            }
            _ => panic!("Invalid role should fail validation"),
        }
    }

    #[test]
    fn test_sanitize_input() {
        let validator = create_validator();
        let input = "  Test\x00String  ";
        let sanitized = validator.sanitize_input(input);
        assert_eq!(sanitized, "TestString");
    }

    #[test]
    fn test_process_email() {
        let validator = create_validator();
        let result = validator.process_email("  TEST@EXAMPLE.COM  ");
        assert_eq!(result.unwrap(), "test@example.com");
    }

    #[test]
    fn test_validate_user_id() {
        let validator = create_validator();

        // Valid UUID
        match validator.validate_user_id("550e8400-e29b-41d4-a716-446655440000") {
            ValidationResult::Valid => {}
            _ => panic!("Valid UUID should pass validation"),
        }

        // Valid custom ID
        match validator.validate_user_id("user_123") {
            ValidationResult::Valid => {}
            _ => panic!("Valid custom ID should pass validation"),
        }

        // Invalid ID
        match validator.validate_user_id("") {
            ValidationResult::Invalid(_) => {}
            _ => panic!("Empty ID should fail validation"),
        }
    }

    #[test]
    fn test_validate_token() {
        let validator = create_validator();

        // Valid JWT-like token
        match validator.validate_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c") {
            ValidationResult::Valid => {}
            _ => panic!("Valid JWT token should pass validation"),
        }

        // Invalid token
        match validator.validate_token("") {
            ValidationResult::Invalid(_) => {}
            _ => panic!("Empty token should fail validation"),
        }
    }

    #[test]
    fn test_validate_registration() {
        let validator = create_validator();
        let result =
            validator.validate_registration("test@example.com", "John", "Doe", Some("user"));

        assert!(result.is_valid);
        assert_eq!(
            result.get_sanitized_value("email").unwrap(),
            "test@example.com"
        );
        assert_eq!(result.get_sanitized_value("first_name").unwrap(), "John");
        assert_eq!(result.get_sanitized_value("last_name").unwrap(), "Doe");
        assert_eq!(result.get_sanitized_value("role").unwrap(), "user");
    }

    #[test]
    fn test_validation_utils() {
        assert!(utils::is_valid_url("https://example.com"));
        assert!(!utils::is_valid_url("not-a-url"));

        assert!(utils::is_printable_ascii("Hello World!"));
        assert!(!utils::is_printable_ascii("Hello\x00World"));

        assert_eq!(utils::truncate_string("Hello World", 5), "Hello");
        assert_eq!(
            utils::normalize_whitespace("  Hello   World  "),
            "Hello World"
        );
    }
}
