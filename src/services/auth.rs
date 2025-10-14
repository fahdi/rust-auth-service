use anyhow::Result;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use crate::config::Config;
use crate::database::AuthDatabase;
use crate::models::user::{
    AuthResponse, CreateUserRequest, EmailVerificationRequest, PasswordChangeRequest,
    PasswordResetRequest, UpdateUserRequest, User, UserError, UserResponse,
};
use crate::utils::{JwtManager, TokenValidationResult};

/// Authentication service handling all auth operations
#[derive(Clone)]
pub struct AuthService {
    database: Arc<dyn AuthDatabase>,
    config: Arc<Config>,
    jwt_manager: Arc<std::sync::Mutex<JwtManager>>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthServiceError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Email already exists")]
    EmailAlreadyExists,
    
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
    
    #[error("Invalid JWT token: {0}")]
    InvalidToken(String),
    
    #[error("Database error: {0}")]
    Database(#[from] UserError),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

impl AuthService {
    pub fn new(database: Arc<dyn AuthDatabase>, config: Arc<Config>) -> Self {
        let jwt_manager = JwtManager::new(
            &config.auth.jwt.secret,
            (config.auth.jwt.expiration_days * 24 * 3600) as i64, // Convert days to seconds
            (config.auth.jwt.expiration_days * 7 * 24 * 3600) as i64, // Refresh token: 7x longer
        );
        Self { 
            database, 
            config,
            jwt_manager: Arc::new(std::sync::Mutex::new(jwt_manager)),
        }
    }

    /// Register a new user with email verification
    pub async fn register(&self, request: CreateUserRequest) -> Result<UserResponse, AuthServiceError> {
        // Validate the request
        request.validate()
            .map_err(|e| AuthServiceError::Validation(format!("Registration validation failed: {}", e)))?;

        // Check if user already exists
        if self.database.user_exists_by_email(&request.email).await? {
            return Err(AuthServiceError::EmailAlreadyExists);
        }

        // Hash the password  
        let password_hash = bcrypt::hash(&request.password, self.config.auth.password.bcrypt_rounds)
            .map_err(|e| AuthServiceError::Internal(format!("Password hashing failed: {}", e)))?;

        // Create user
        let user = User::new(request, password_hash);
        let created_user = self.database.create_user(user).await?;

        // Generate email verification token
        let verification_token = Uuid::new_v4().to_string();
        self.database.set_email_verification_token(
            &created_user.user_id,
            &verification_token,
            24, // 24 hours expiration
        ).await?;

        // TODO: Send verification email
        // self.email_service.send_verification_email(&created_user.email, &verification_token).await?;

        Ok(created_user.to_response())
    }

    /// Login user and return JWT tokens
    pub async fn login(&self, email: &str, password: &str) -> Result<AuthResponse, AuthServiceError> {
        // Find user by email
        let user = self.database.find_user_by_email(email).await?
            .ok_or(AuthServiceError::InvalidCredentials)?;

        // Check if account is locked
        if user.is_locked() {
            return Err(AuthServiceError::AccountLocked);
        }

        // Verify password
        if !bcrypt::verify(password, &user.password_hash)
            .map_err(|e| AuthServiceError::Internal(format!("Password verification failed: {}", e)))? {
            // Record failed login attempt
            self.database.record_failed_login(
                email,
                5, // max_login_attempts (TODO: add to config)
                1, // lockout_hours (TODO: add to config)
            ).await?;
            return Err(AuthServiceError::InvalidCredentials);
        }

        // Check if email is verified (optional based on config)
        if self.config.auth.verification.required && !user.email_verified {
            return Err(AuthServiceError::EmailNotVerified);
        }

        // Record successful login
        self.database.record_login(&user.user_id).await?;

        // Generate JWT tokens
        let jwt_manager = self.jwt_manager.lock().unwrap();
        let (access_token, refresh_token) = jwt_manager.generate_token_pair(
            &user.user_id,
            &user.email,
            &user.role.to_string(),
        ).map_err(|e| AuthServiceError::Internal(format!("Token generation failed: {}", e)))?;
        drop(jwt_manager);

        Ok(AuthResponse {
            user: user.to_response(),
            access_token,
            refresh_token,
            expires_in: (self.config.auth.jwt.expiration_days * 24 * 3600) as i64, // Convert days to seconds
        })
    }

    /// Verify email with verification token
    pub async fn verify_email(&self, request: EmailVerificationRequest) -> Result<UserResponse, AuthServiceError> {
        let user_id = self.database.verify_email(&request.token).await
            .map_err(|e| match e {
                UserError::InvalidVerificationToken => AuthServiceError::InvalidVerificationToken,
                UserError::VerificationTokenExpired => AuthServiceError::VerificationTokenExpired,
                _ => AuthServiceError::Database(e),
            })?;

        let user = self.database.find_user_by_id(&user_id).await?
            .ok_or(AuthServiceError::UserNotFound)?;

        Ok(user.to_response())
    }

    /// Request password reset
    pub async fn forgot_password(&self, request: PasswordResetRequest) -> Result<(), AuthServiceError> {
        // Validate email format
        request.validate()
            .map_err(|e| AuthServiceError::Validation(format!("Password reset validation failed: {}", e)))?;

        // Check if user exists (don't reveal if email exists for security)
        if let Ok(Some(_)) = self.database.find_user_by_email(&request.email).await {
            let reset_token = Uuid::new_v4().to_string();
            self.database.set_password_reset_token(
                &request.email,
                &reset_token,
                2, // 2 hours expiration
            ).await?;

            // TODO: Send password reset email
            // self.email_service.send_password_reset_email(&request.email, &reset_token).await?;
        }

        // Always return success for security (don't reveal if email exists)
        Ok(())
    }

    /// Reset password with token
    pub async fn reset_password(&self, request: PasswordChangeRequest) -> Result<(), AuthServiceError> {
        // Validate the request
        request.validate()
            .map_err(|e| AuthServiceError::Validation(format!("Password change validation failed: {}", e)))?;

        // Verify reset token
        let user_id = self.database.verify_password_reset_token(&request.token).await
            .map_err(|e| match e {
                UserError::InvalidPasswordResetToken => AuthServiceError::InvalidPasswordResetToken,
                UserError::PasswordResetTokenExpired => AuthServiceError::PasswordResetTokenExpired,
                _ => AuthServiceError::Database(e),
            })?;

        // Hash new password
        let password_hash = bcrypt::hash(&request.new_password, self.config.auth.password.bcrypt_rounds)
            .map_err(|e| AuthServiceError::Internal(format!("Password hashing failed: {}", e)))?;

        // Update password
        self.database.update_password(&user_id, &password_hash).await?;

        // Clear reset token
        self.database.clear_password_reset_token(&user_id).await?;

        Ok(())
    }

    /// Refresh access token using refresh token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AuthResponse, AuthServiceError> {
        // Validate refresh token and generate new access token
        let jwt_manager = self.jwt_manager.lock().unwrap();
        let new_access_token = jwt_manager.refresh_access_token(refresh_token)
            .map_err(|e| AuthServiceError::InvalidToken(e.to_string()))?;
        
        // Extract user_id from the refresh token
        let user_id = jwt_manager.extract_user_id(refresh_token)
            .map_err(|e| AuthServiceError::InvalidToken(e.to_string()))?;
        drop(jwt_manager);

        // Find user
        let user = self.database.find_user_by_id(&user_id).await?
            .ok_or(AuthServiceError::UserNotFound)?;

        // Check if account is still active
        if !user.is_active {
            return Err(AuthServiceError::InvalidCredentials);
        }

        Ok(AuthResponse {
            user: user.to_response(),
            access_token: new_access_token,
            refresh_token: refresh_token.to_string(), // Return same refresh token
            expires_in: (self.config.auth.jwt.expiration_days * 24 * 3600) as i64,
        })
    }

    /// Get current user profile
    pub async fn get_profile(&self, user_id: &str) -> Result<UserResponse, AuthServiceError> {
        let user = self.database.find_user_by_id(user_id).await?
            .ok_or(AuthServiceError::UserNotFound)?;
        
        Ok(user.to_response())
    }

    /// Update user profile
    pub async fn update_profile(&self, user_id: &str, request: UpdateUserRequest) -> Result<UserResponse, AuthServiceError> {
        // Validate the request
        request.validate()
            .map_err(|e| AuthServiceError::Validation(format!("Profile update validation failed: {}", e)))?;

        // If email is being changed, check if it's already taken
        if let Some(ref email) = request.email {
            if let Ok(Some(existing_user)) = self.database.find_user_by_email(email).await {
                if existing_user.user_id != user_id {
                    return Err(AuthServiceError::EmailAlreadyExists);
                }
            }
        }

        let updated_user = self.database.update_user(user_id, request).await?;
        Ok(updated_user.to_response())
    }

    /// Logout user (revoke tokens)
    pub async fn logout(&self, access_token: &str) -> Result<(), AuthServiceError> {
        // Blacklist the token
        let mut jwt_manager = self.jwt_manager.lock().unwrap();
        jwt_manager.blacklist_token(access_token)
            .map_err(|e| AuthServiceError::Internal(format!("Failed to blacklist token: {}", e)))?;
        Ok(())
    }

    /// Validate access token and return user info
    pub async fn validate_access_token(&self, access_token: &str) -> Result<UserResponse, AuthServiceError> {
        let jwt_manager = self.jwt_manager.lock().unwrap();
        
        // Check if token is blacklisted first
        if jwt_manager.is_token_blacklisted(access_token) {
            return Err(AuthServiceError::InvalidToken("Token has been revoked".to_string()));
        }
        
        let validation_result = jwt_manager.validate_token_detailed(access_token);
        drop(jwt_manager);
        
        match validation_result {
            TokenValidationResult::Valid(claims) => {
                let user = self.database.find_user_by_id(&claims.sub).await?
                    .ok_or(AuthServiceError::UserNotFound)?;

                if !user.is_active {
                    return Err(AuthServiceError::InvalidCredentials);
                }

                Ok(user.to_response())
            }
            TokenValidationResult::Invalid => Err(AuthServiceError::InvalidToken("Invalid token".to_string())),
            TokenValidationResult::Blacklisted => Err(AuthServiceError::InvalidToken("Token has been revoked".to_string())),
            TokenValidationResult::Expired => Err(AuthServiceError::InvalidToken("Token expired".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::config::auth::{AuthConfig, JwtConfig, PasswordConfig, VerificationConfig};
    use crate::config::database::{DatabaseConfig, PoolConfig};
    use crate::models::user::UserRole;
    use crate::database::AuthDatabase;
    use async_trait::async_trait;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Mock database for testing
    #[derive(Debug)]
    struct MockDatabase {
        users: Arc<Mutex<HashMap<String, User>>>,
        users_by_email: Arc<Mutex<HashMap<String, String>>>, // email -> user_id
    }

    impl MockDatabase {
        fn new() -> Self {
            Self {
                users: Arc::new(Mutex::new(HashMap::new())),
                users_by_email: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl AuthDatabase for MockDatabase {
        async fn create_user(&self, mut user: User) -> Result<User, UserError> {
            let mut users = self.users.lock().unwrap();
            let mut users_by_email = self.users_by_email.lock().unwrap();

            if users_by_email.contains_key(&user.email) {
                return Err(UserError::EmailAlreadyExists);
            }

            user.id = Some(format!("mock_id_{}", user.user_id));
            users.insert(user.user_id.clone(), user.clone());
            users_by_email.insert(user.email.clone(), user.user_id.clone());
            Ok(user)
        }

        async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
            let users_by_email = self.users_by_email.lock().unwrap();
            let users = self.users.lock().unwrap();

            if let Some(user_id) = users_by_email.get(email) {
                Ok(users.get(user_id).cloned())
            } else {
                Ok(None)
            }
        }

        async fn find_user_by_id(&self, user_id: &str) -> Result<Option<User>, UserError> {
            let users = self.users.lock().unwrap();
            Ok(users.get(user_id).cloned())
        }

        async fn update_user(&self, user_id: &str, updates: UpdateUserRequest) -> Result<User, UserError> {
            let mut users = self.users.lock().unwrap();
            let mut user = users.get_mut(user_id).ok_or(UserError::NotFound)?.clone();
            user.update(updates);
            users.insert(user_id.to_string(), user.clone());
            Ok(user)
        }

        async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<(), UserError> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.get_mut(user_id) {
                user.password_hash = password_hash.to_string();
                user.updated_at = Utc::now();
                Ok(())
            } else {
                Err(UserError::NotFound)
            }
        }

        async fn set_email_verification_token(&self, user_id: &str, token: &str, expires_hours: u64) -> Result<(), UserError> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.get_mut(user_id) {
                user.set_email_verification_token(token.to_string(), expires_hours);
                Ok(())
            } else {
                Err(UserError::NotFound)
            }
        }

        async fn verify_email(&self, token: &str) -> Result<String, UserError> {
            let mut users = self.users.lock().unwrap();
            for user in users.values_mut() {
                if user.is_verification_token_valid(token) {
                    user.verify_email();
                    return Ok(user.user_id.clone());
                }
            }
            Err(UserError::InvalidVerificationToken)
        }

        async fn set_password_reset_token(&self, email: &str, token: &str, expires_hours: u64) -> Result<(), UserError> {
            let users_by_email = self.users_by_email.lock().unwrap();
            let mut users = self.users.lock().unwrap();

            if let Some(user_id) = users_by_email.get(email) {
                if let Some(user) = users.get_mut(user_id) {
                    user.set_password_reset_token(token.to_string(), expires_hours);
                    return Ok(());
                }
            }
            Err(UserError::NotFound)
        }

        async fn verify_password_reset_token(&self, token: &str) -> Result<String, UserError> {
            let users = self.users.lock().unwrap();
            for user in users.values() {
                if user.is_password_reset_token_valid(token) {
                    return Ok(user.user_id.clone());
                }
            }
            Err(UserError::InvalidPasswordResetToken)
        }

        async fn clear_password_reset_token(&self, user_id: &str) -> Result<(), UserError> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.get_mut(user_id) {
                user.clear_password_reset_token();
                Ok(())
            } else {
                Err(UserError::NotFound)
            }
        }

        async fn record_login(&self, user_id: &str) -> Result<(), UserError> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.get_mut(user_id) {
                user.record_login();
                Ok(())
            } else {
                Err(UserError::NotFound)
            }
        }

        async fn record_failed_login(&self, email: &str, max_attempts: u32, lockout_hours: u64) -> Result<(), UserError> {
            let users_by_email = self.users_by_email.lock().unwrap();
            let mut users = self.users.lock().unwrap();

            if let Some(user_id) = users_by_email.get(email) {
                if let Some(user) = users.get_mut(user_id) {
                    user.record_failed_login(max_attempts, lockout_hours);
                    return Ok(());
                }
            }
            Err(UserError::NotFound)
        }

        async fn user_exists_by_email(&self, email: &str) -> Result<bool, UserError> {
            let users_by_email = self.users_by_email.lock().unwrap();
            Ok(users_by_email.contains_key(email))
        }

        async fn deactivate_user(&self, user_id: &str) -> Result<(), UserError> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.get_mut(user_id) {
                user.is_active = false;
                user.updated_at = Utc::now();
                Ok(())
            } else {
                Err(UserError::NotFound)
            }
        }

        async fn health_check(&self) -> Result<crate::database::DatabaseHealth> {
            Ok(crate::database::DatabaseHealth {
                status: "healthy".to_string(),
                database_type: "mock".to_string(),
                connected: true,
                response_time_ms: 1,
                details: Some("Mock database".to_string()),
            })
        }

        async fn initialize(&self) -> Result<()> {
            Ok(())
        }
    }

    fn create_test_config() -> Config {
        use crate::config::auth::{AuthConfig, JwtConfig, PasswordConfig, VerificationConfig};
        
        Config {
            server: crate::config::server::ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                workers: 4,
            },
            database: crate::config::database::DatabaseConfig {
                r#type: "mock".to_string(),
                url: "mock://localhost".to_string(),
                pool: crate::config::database::PoolConfig::default(),
            },
            auth: AuthConfig {
                jwt: JwtConfig {
                    secret: "test_secret_key_for_testing_only".to_string(),
                    expiration_days: 7,
                },
                password: PasswordConfig {
                    bcrypt_rounds: 4, // Lower for testing
                    min_length: 6,
                },
                verification: VerificationConfig {
                    token_expiry_hours: 24,
                    required: false,
                },
            },
            cache: crate::config::cache::CacheConfig::default(),
            email: crate::config::email::EmailConfig::default(),
            monitoring: crate::config::MonitoringConfig::default(),
        }
    }

    fn create_test_auth_service() -> AuthService {
        let database = Arc::new(MockDatabase::new());
        let config = Arc::new(create_test_config());
        AuthService::new(database, config)
    }

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

    #[tokio::test]
    async fn test_user_registration() {
        let service = create_test_auth_service();
        let request = create_test_user_request();
        
        let result = service.register(request).await;
        assert!(result.is_ok());
        
        let user_response = result.unwrap();
        assert_eq!(user_response.email, "test@example.com");
        assert_eq!(user_response.first_name, "John");
        assert!(!user_response.email_verified);
    }

    #[tokio::test]
    async fn test_duplicate_email_registration() {
        let service = create_test_auth_service();
        let request = create_test_user_request();
        
        // Register first user
        service.register(request.clone()).await.unwrap();
        
        // Try to register with same email
        let result = service.register(request).await;
        assert!(matches!(result, Err(AuthServiceError::EmailAlreadyExists)));
    }

    #[tokio::test]
    async fn test_successful_login() {
        let service = create_test_auth_service();
        let request = create_test_user_request();
        
        // Register user first
        service.register(request.clone()).await.unwrap();
        
        // Login
        let result = service.login(&request.email, &request.password).await;
        assert!(result.is_ok());
        
        let auth_response = result.unwrap();
        assert_eq!(auth_response.user.email, request.email);
        assert!(!auth_response.access_token.is_empty());
        assert!(!auth_response.refresh_token.is_empty());
    }

    #[tokio::test]
    async fn test_invalid_login_credentials() {
        let service = create_test_auth_service();
        let request = create_test_user_request();
        
        // Register user first
        service.register(request.clone()).await.unwrap();
        
        // Try login with wrong password
        let result = service.login(&request.email, "wrongpassword").await;
        assert!(matches!(result, Err(AuthServiceError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_login_nonexistent_user() {
        let service = create_test_auth_service();
        
        let result = service.login("nonexistent@example.com", "password").await;
        assert!(matches!(result, Err(AuthServiceError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_email_verification() {
        let service = create_test_auth_service();
        let request = create_test_user_request();
        
        // Register user
        let user_response = service.register(request).await.unwrap();
        assert!(!user_response.email_verified);
        
        // Set verification token manually (since we're using mock database)
        let token = "verification_token_123";
        service.database.set_email_verification_token(&user_response.user_id, token, 24).await.unwrap();
        
        // Verify email
        let verify_request = EmailVerificationRequest {
            token: token.to_string(),
        };
        let result = service.verify_email(verify_request).await;
        assert!(result.is_ok());
        
        let verified_user = result.unwrap();
        assert!(verified_user.email_verified);
    }

    #[tokio::test]
    async fn test_password_reset_flow() {
        let service = create_test_auth_service();
        let request = create_test_user_request();
        
        // Register user
        service.register(request.clone()).await.unwrap();
        
        // Request password reset
        let reset_request = PasswordResetRequest {
            email: request.email.clone(),
        };
        let result = service.forgot_password(reset_request).await;
        assert!(result.is_ok());
        
        // Change password with token
        let token = "reset_token_123";
        service.database.set_password_reset_token(&request.email, token, 2).await.unwrap();
        
        let change_request = PasswordChangeRequest {
            token: token.to_string(),
            new_password: "newpassword123".to_string(),
        };
        let result = service.reset_password(change_request).await;
        assert!(result.is_ok());
        
        // Try login with new password
        let login_result = service.login(&request.email, "newpassword123").await;
        assert!(login_result.is_ok());
    }

    #[tokio::test]
    async fn test_token_refresh() {
        let service = create_test_auth_service();
        let request = create_test_user_request();
        
        // Register and login user
        service.register(request.clone()).await.unwrap();
        let auth_response = service.login(&request.email, &request.password).await.unwrap();
        
        // Refresh token
        let result = service.refresh_token(&auth_response.refresh_token).await;
        assert!(result.is_ok());
        
        let new_auth_response = result.unwrap();
        assert_eq!(new_auth_response.user.email, request.email);
        assert!(!new_auth_response.access_token.is_empty());
    }

    #[tokio::test]
    async fn test_get_profile() {
        let service = create_test_auth_service();
        let request = create_test_user_request();
        
        // Register user
        let user_response = service.register(request.clone()).await.unwrap();
        
        // Get profile
        let result = service.get_profile(&user_response.user_id).await;
        assert!(result.is_ok());
        
        let profile = result.unwrap();
        assert_eq!(profile.email, request.email);
        assert_eq!(profile.first_name, request.first_name);
    }

    #[tokio::test]
    async fn test_update_profile() {
        let service = create_test_auth_service();
        let request = create_test_user_request();
        
        // Register user
        let user_response = service.register(request).await.unwrap();
        
        // Update profile
        let update_request = UpdateUserRequest {
            first_name: Some("Jane".to_string()),
            last_name: Some("Smith".to_string()),
            ..Default::default()
        };
        
        let result = service.update_profile(&user_response.user_id, update_request).await;
        assert!(result.is_ok());
        
        let updated_user = result.unwrap();
        assert_eq!(updated_user.first_name, "Jane");
        assert_eq!(updated_user.last_name, "Smith");
    }

    #[tokio::test]
    async fn test_validate_access_token() {
        let service = create_test_auth_service();
        let request = create_test_user_request();
        
        // Register and login user
        service.register(request.clone()).await.unwrap();
        let auth_response = service.login(&request.email, &request.password).await.unwrap();
        
        // Validate access token
        let result = service.validate_access_token(&auth_response.access_token).await;
        assert!(result.is_ok());
        
        let user_info = result.unwrap();
        assert_eq!(user_info.email, request.email);
    }
}