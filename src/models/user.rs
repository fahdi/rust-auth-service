use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// User model representing a user in the authentication system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<mongodb::bson::oid::ObjectId>,
    pub user_id: String,
    pub email: String,
    pub password_hash: String,
    pub first_name: String,
    pub last_name: String,
    pub role: UserRole,
    pub is_active: bool,
    pub email_verified: bool,
    pub email_verification_token: Option<String>,
    pub email_verification_expires: Option<DateTime<Utc>>,
    pub password_reset_token: Option<String>,
    pub password_reset_expires: Option<DateTime<Utc>>,
    pub last_login: Option<DateTime<Utc>>,
    pub login_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: UserMetadata,
}

/// User roles for role-based access control
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum UserRole {
    #[default]
    User,
    Admin,
    Moderator,
    Guest,
}


impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::User => write!(f, "user"),
            UserRole::Admin => write!(f, "admin"),
            UserRole::Moderator => write!(f, "moderator"),
            UserRole::Guest => write!(f, "guest"),
        }
    }
}

impl std::str::FromStr for UserRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(UserRole::User),
            "admin" => Ok(UserRole::Admin),
            "moderator" => Ok(UserRole::Moderator),
            "guest" => Ok(UserRole::Guest),
            _ => Err(format!("Invalid role: {}", s)),
        }
    }
}

/// Additional metadata for user tracking and analytics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserMetadata {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub registration_source: Option<String>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub preferences: serde_json::Value,
}

/// Request DTO for creating a new user
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    
    #[validate(length(min = 2, max = 50, message = "First name must be between 2 and 50 characters"))]
    pub first_name: String,
    
    #[validate(length(min = 2, max = 50, message = "Last name must be between 2 and 50 characters"))]
    pub last_name: String,
    
    pub role: Option<UserRole>,
    pub metadata: Option<UserMetadata>,
}

/// Request DTO for updating user information
#[derive(Debug, Clone, Serialize, Deserialize, Validate, Default)]
pub struct UpdateUserRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: Option<String>,
    
    #[validate(length(min = 2, max = 50, message = "First name must be between 2 and 50 characters"))]
    pub first_name: Option<String>,
    
    #[validate(length(min = 2, max = 50, message = "Last name must be between 2 and 50 characters"))]
    pub last_name: Option<String>,
    
    pub role: Option<UserRole>,
    pub is_active: Option<bool>,
    pub metadata: Option<UserMetadata>,
}

/// Request DTO for password reset
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PasswordResetRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

/// Request DTO for changing password with reset token
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PasswordChangeRequest {
    pub token: String,
    
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub new_password: String,
}

/// Request DTO for email verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerificationRequest {
    pub token: String,
}

/// Response DTO for user information (excludes sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub user_id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub role: UserRole,
    pub is_active: bool,
    pub email_verified: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Response DTO for authentication with tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64, // seconds until access token expires
}

/// Login attempt record for security tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttempt {
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub attempted_at: DateTime<Utc>,
}

/// Database error types for user operations
#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("User not found")]
    NotFound,
    
    #[error("Email already exists")]
    EmailAlreadyExists,
    
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Account is locked")]
    AccountLocked,
    
    #[error("Email not verified")]
    EmailNotVerified,
    
    #[error("Invalid verification token")]
    InvalidVerificationToken,
    
    #[error("Verification token expired")]
    VerificationTokenExpired,
    
    #[error("Invalid password reset token")]
    InvalidPasswordResetToken,
    
    #[error("Password reset token expired")]
    PasswordResetTokenExpired,
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
}

impl User {
    /// Create a new user with the provided information
    pub fn new(request: CreateUserRequest, password_hash: String) -> Self {
        let now = Utc::now();
        let user_id = Uuid::new_v4().to_string();
        
        Self {
            id: None, // Will be set by MongoDB
            user_id,
            email: request.email.to_lowercase(),
            password_hash,
            first_name: request.first_name,
            last_name: request.last_name,
            role: request.role.unwrap_or_default(),
            is_active: true,
            email_verified: false,
            email_verification_token: None,
            email_verification_expires: None,
            password_reset_token: None,
            password_reset_expires: None,
            last_login: None,
            login_attempts: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
            metadata: request.metadata.unwrap_or_default(),
        }
    }

    /// Get user's full name
    pub fn full_name(&self) -> String {
        format!("{} {}", self.first_name, self.last_name)
    }

    /// Check if user account is locked
    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            Utc::now() < locked_until
        } else {
            false
        }
    }

    /// Check if email verification token is valid and not expired
    pub fn is_verification_token_valid(&self, token: &str) -> bool {
        if let Some(stored_token) = &self.email_verification_token {
            if stored_token == token {
                if let Some(expires) = self.email_verification_expires {
                    return Utc::now() < expires;
                }
            }
        }
        false
    }

    /// Check if password reset token is valid and not expired
    pub fn is_password_reset_token_valid(&self, token: &str) -> bool {
        if let Some(stored_token) = &self.password_reset_token {
            if stored_token == token {
                if let Some(expires) = self.password_reset_expires {
                    return Utc::now() < expires;
                }
            }
        }
        false
    }

    /// Set email verification token with expiration
    pub fn set_email_verification_token(&mut self, token: String, hours_valid: u64) {
        self.email_verification_token = Some(token);
        self.email_verification_expires = Some(Utc::now() + chrono::Duration::hours(hours_valid as i64));
        self.updated_at = Utc::now();
    }

    /// Set password reset token with expiration
    pub fn set_password_reset_token(&mut self, token: String, hours_valid: u64) {
        self.password_reset_token = Some(token);
        self.password_reset_expires = Some(Utc::now() + chrono::Duration::hours(hours_valid as i64));
        self.updated_at = Utc::now();
    }

    /// Mark email as verified and clear verification token
    pub fn verify_email(&mut self) {
        self.email_verified = true;
        self.email_verification_token = None;
        self.email_verification_expires = None;
        self.updated_at = Utc::now();
    }

    /// Clear password reset token after successful reset
    pub fn clear_password_reset_token(&mut self) {
        self.password_reset_token = None;
        self.password_reset_expires = None;
        self.updated_at = Utc::now();
    }

    /// Record successful login
    pub fn record_login(&mut self) {
        self.last_login = Some(Utc::now());
        self.login_attempts = 0;
        self.locked_until = None;
        self.updated_at = Utc::now();
    }

    /// Record failed login attempt
    pub fn record_failed_login(&mut self, max_attempts: u32, lockout_hours: u64) {
        self.login_attempts += 1;
        self.updated_at = Utc::now();
        
        if self.login_attempts >= max_attempts {
            self.locked_until = Some(Utc::now() + chrono::Duration::hours(lockout_hours as i64));
        }
    }

    /// Update user information
    pub fn update(&mut self, request: UpdateUserRequest) {
        if let Some(email) = request.email {
            self.email = email.to_lowercase();
        }
        if let Some(first_name) = request.first_name {
            self.first_name = first_name;
        }
        if let Some(last_name) = request.last_name {
            self.last_name = last_name;
        }
        if let Some(role) = request.role {
            self.role = role;
        }
        if let Some(is_active) = request.is_active {
            self.is_active = is_active;
        }
        if let Some(metadata) = request.metadata {
            self.metadata = metadata;
        }
        self.updated_at = Utc::now();
    }

    /// Convert to UserResponse (safe for API responses)
    pub fn to_response(&self) -> UserResponse {
        UserResponse {
            user_id: self.user_id.clone(),
            email: self.email.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            role: self.role.clone(),
            is_active: self.is_active,
            email_verified: self.email_verified,
            last_login: self.last_login,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_user_request() -> CreateUserRequest {
        CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "securepassword123".to_string(),
            first_name: "John".to_string(),
            last_name: "Doe".to_string(),
            role: Some(UserRole::User),
            metadata: None,
        }
    }

    #[test]
    fn test_user_creation() {
        let request = create_test_user_request();
        let password_hash = "hashed_password".to_string();
        let user = User::new(request, password_hash.clone());

        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.password_hash, password_hash);
        assert_eq!(user.first_name, "John");
        assert_eq!(user.last_name, "Doe");
        assert_eq!(user.role, UserRole::User);
        assert!(!user.email_verified);
        assert!(user.is_active);
        assert_eq!(user.login_attempts, 0);
    }

    #[test]
    fn test_full_name() {
        let request = create_test_user_request();
        let user = User::new(request, "hash".to_string());
        assert_eq!(user.full_name(), "John Doe");
    }

    #[test]
    fn test_account_locking() {
        let mut user = User::new(create_test_user_request(), "hash".to_string());
        
        assert!(!user.is_locked());
        
        // Lock account for 1 hour
        user.record_failed_login(3, 1);
        user.record_failed_login(3, 1);
        user.record_failed_login(3, 1);
        
        assert!(user.is_locked());
    }

    #[test]
    fn test_email_verification_token() {
        let mut user = User::new(create_test_user_request(), "hash".to_string());
        let token = "verification_token_123".to_string();
        
        user.set_email_verification_token(token.clone(), 24);
        
        assert!(user.is_verification_token_valid(&token));
        assert!(!user.is_verification_token_valid("wrong_token"));
        
        user.verify_email();
        assert!(user.email_verified);
        assert!(user.email_verification_token.is_none());
    }

    #[test]
    fn test_password_reset_token() {
        let mut user = User::new(create_test_user_request(), "hash".to_string());
        let token = "reset_token_123".to_string();
        
        user.set_password_reset_token(token.clone(), 2);
        
        assert!(user.is_password_reset_token_valid(&token));
        assert!(!user.is_password_reset_token_valid("wrong_token"));
        
        user.clear_password_reset_token();
        assert!(user.password_reset_token.is_none());
    }

    #[test]
    fn test_login_recording() {
        let mut user = User::new(create_test_user_request(), "hash".to_string());
        
        assert!(user.last_login.is_none());
        
        user.record_login();
        assert!(user.last_login.is_some());
        assert_eq!(user.login_attempts, 0);
    }

    #[test]
    fn test_user_update() {
        let mut user = User::new(create_test_user_request(), "hash".to_string());
        
        let update_request = UpdateUserRequest {
            email: Some("newemail@example.com".to_string()),
            first_name: Some("Jane".to_string()),
            last_name: None,
            role: Some(UserRole::Admin),
            is_active: Some(false),
            metadata: None,
        };
        
        user.update(update_request);
        
        assert_eq!(user.email, "newemail@example.com");
        assert_eq!(user.first_name, "Jane");
        assert_eq!(user.last_name, "Doe"); // Unchanged
        assert_eq!(user.role, UserRole::Admin);
        assert!(!user.is_active);
    }

    #[test]
    fn test_user_response_conversion() {
        let user = User::new(create_test_user_request(), "hash".to_string());
        let response = user.to_response();
        
        assert_eq!(response.email, user.email);
        assert_eq!(response.first_name, user.first_name);
        assert_eq!(response.role, user.role);
        // password_hash should not be in response
    }

    #[test]
    fn test_user_role_string_conversion() {
        assert_eq!(UserRole::User.to_string(), "user");
        assert_eq!(UserRole::Admin.to_string(), "admin");
        
        assert_eq!("user".parse::<UserRole>().unwrap(), UserRole::User);
        assert_eq!("ADMIN".parse::<UserRole>().unwrap(), UserRole::Admin);
        assert!("invalid".parse::<UserRole>().is_err());
    }
}