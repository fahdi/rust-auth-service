use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod mongodb;
pub mod postgresql;
pub mod mysql;

use crate::config::database::DatabaseConfig;
use crate::models::user::{User, CreateUserRequest, UpdateUserRequest, UserError};

/// Database health status
#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseHealth {
    pub status: String,
    pub database_type: String,
    pub connected: bool,
    pub response_time_ms: u64,
    pub details: Option<String>,
}

/// Database trait for authentication operations
#[async_trait]
pub trait AuthDatabase: Send + Sync {
    /// Create a new user
    async fn create_user(&self, user: User) -> Result<User, UserError>;
    
    /// Find user by email address
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, UserError>;
    
    /// Find user by user ID
    async fn find_user_by_id(&self, user_id: &str) -> Result<Option<User>, UserError>;
    
    /// Update user information
    async fn update_user(&self, user_id: &str, updates: UpdateUserRequest) -> Result<User, UserError>;
    
    /// Update user password hash
    async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<(), UserError>;
    
    /// Set email verification token
    async fn set_email_verification_token(&self, user_id: &str, token: &str, expires_hours: u64) -> Result<(), UserError>;
    
    /// Verify email with token
    async fn verify_email(&self, token: &str) -> Result<String, UserError>; // Returns user_id
    
    /// Set password reset token
    async fn set_password_reset_token(&self, email: &str, token: &str, expires_hours: u64) -> Result<(), UserError>;
    
    /// Verify password reset token
    async fn verify_password_reset_token(&self, token: &str) -> Result<String, UserError>; // Returns user_id
    
    /// Clear password reset token
    async fn clear_password_reset_token(&self, user_id: &str) -> Result<(), UserError>;
    
    /// Record successful login
    async fn record_login(&self, user_id: &str) -> Result<(), UserError>;
    
    /// Record failed login attempt
    async fn record_failed_login(&self, email: &str, max_attempts: u32, lockout_hours: u64) -> Result<(), UserError>;
    
    /// Check if user exists by email
    async fn user_exists_by_email(&self, email: &str) -> Result<bool, UserError>;
    
    /// Soft delete user (mark as inactive)
    async fn deactivate_user(&self, user_id: &str) -> Result<(), UserError>;
    
    /// Get database health status
    async fn health_check(&self) -> Result<DatabaseHealth>;
    
    /// Initialize database (create indexes, etc.)
    async fn initialize(&self) -> Result<()>;
}

/// Create database instance based on configuration
pub async fn create_database(config: &DatabaseConfig) -> Result<Box<dyn AuthDatabase>> {
    match config.r#type.as_str() {
        "mongodb" => {
            let db = mongodb::MongoDatabase::new(&config.url, &config.pool).await?;
            db.initialize().await?;
            Ok(Box::new(db))
        }
        "postgresql" => {
            let db = postgresql::PostgresDatabase::new(&config.url, &config.pool).await?;
            db.initialize().await?;
            Ok(Box::new(db))
        }
        "mysql" => {
            let db = mysql::MySqlDatabase::new(&config.url, &config.pool).await?;
            db.initialize().await?;
            Ok(Box::new(db))
        }
        _ => Err(anyhow::anyhow!("Unsupported database type: {}", config.r#type)),
    }
}