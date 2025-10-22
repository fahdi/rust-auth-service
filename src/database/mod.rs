use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod mongodb;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "postgresql")]
pub mod postgresql;

use crate::config::database::DatabaseConfig;
use crate::models::user::{LoginAttempt, User, UserError};

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
    async fn update_user(&self, user: &User) -> Result<User, UserError>;

    /// Update user password hash
    async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<(), UserError>;

    /// Set email verification token
    async fn set_email_verification_token(
        &self,
        user_id: &str,
        token: &str,
        expires_hours: u64,
    ) -> Result<(), UserError>;

    /// Verify email with token
    async fn verify_email(&self, token: &str) -> Result<String, UserError>; // Returns user_id

    /// Set password reset token
    async fn set_password_reset_token(
        &self,
        email: &str,
        token: &str,
        expires_hours: u64,
    ) -> Result<(), UserError>;

    /// Verify password reset token
    async fn verify_password_reset_token(&self, token: &str) -> Result<String, UserError>; // Returns user_id

    /// Clear password reset token
    async fn clear_password_reset_token(&self, user_id: &str) -> Result<(), UserError>;

    /// Record successful login
    async fn record_login(&self, user_id: &str) -> Result<(), UserError>;

    /// Record failed login attempt
    async fn record_failed_login(
        &self,
        email: &str,
        max_attempts: u32,
        lockout_hours: u64,
    ) -> Result<(), UserError>;

    /// Check if user exists by email
    async fn user_exists_by_email(&self, email: &str) -> Result<bool, UserError>;

    /// Soft delete user (mark as inactive)
    async fn deactivate_user(&self, user_id: &str) -> Result<(), UserError>;

    /// Get database health status
    async fn health_check(&self) -> Result<DatabaseHealth>;

    /// Find user by verification token
    async fn get_user_by_verification_token(&self, token: &str) -> Result<Option<User>, UserError>;

    /// Find user by password reset token  
    async fn get_user_by_reset_token(&self, token: &str) -> Result<Option<User>, UserError>;

    /// Verify user email (mark as verified)
    async fn verify_user_email(&self, user_id: &str) -> Result<(), UserError>;

    /// Update login attempts and lock status
    async fn update_login_attempts(
        &self,
        user_id: &str,
        attempts: u32,
        locked_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), UserError>;

    /// Update last login timestamp
    async fn update_last_login(&self, user_id: &str) -> Result<(), UserError>;

    /// Record login attempt
    async fn record_login_attempt(&self, attempt: &LoginAttempt) -> Result<(), UserError>;

    /// Initialize database (create indexes, etc.)
    async fn initialize(&self) -> Result<()>;

    // Admin dashboard methods
    /// Count total number of users
    async fn count_users(&self) -> Result<u64, UserError>;

    /// Count verified users
    async fn count_verified_users(&self) -> Result<u64, UserError>;

    /// Count active users (recent activity)
    async fn count_active_users(&self) -> Result<u64, UserError>;

    /// Count admin users
    async fn count_admin_users(&self) -> Result<u64, UserError>;

    /// List users with pagination
    async fn list_users(&self, page: u32, limit: u32) -> Result<Vec<User>, UserError>;

    /// Search users by email or name
    async fn search_users(
        &self,
        query: &str,
        page: u32,
        limit: u32,
    ) -> Result<Vec<User>, UserError>;

    /// Get user by ID for admin purposes
    async fn get_user_for_admin(&self, user_id: &str) -> Result<Option<User>, UserError>;

    /// Update user role (admin operation)
    async fn update_user_role(&self, user_id: &str, role: &str) -> Result<(), UserError>;

    /// Lock/unlock user account
    async fn set_user_lock_status(&self, user_id: &str, locked: bool) -> Result<(), UserError>;

    /// Force verify user email (admin operation)
    async fn admin_verify_email(&self, user_id: &str) -> Result<(), UserError>;
}

/// Create database instance based on configuration
pub async fn create_database(config: &DatabaseConfig) -> Result<Box<dyn AuthDatabase>> {
    match config.r#type.as_str() {
        "mongodb" => {
            let db = mongodb::MongoDatabase::new(&config.url, &config.pool).await?;
            db.initialize().await?;
            Ok(Box::new(db))
        }
        #[cfg(feature = "postgresql")]
        "postgresql" => {
            let db = postgresql::PostgresDatabase::new(&config.url, &config.pool).await?;
            db.initialize().await?;
            Ok(Box::new(db))
        }
        #[cfg(not(feature = "postgresql"))]
        "postgresql" => Err(anyhow::anyhow!(
            "PostgreSQL support not enabled. Compile with --features postgresql"
        )),
        #[cfg(feature = "mysql")]
        "mysql" => {
            let db = mysql::MySqlDatabase::new(&config.url, &config.pool).await?;
            db.initialize().await?;
            Ok(Box::new(db))
        }
        #[cfg(not(feature = "mysql"))]
        "mysql" => Err(anyhow::anyhow!(
            "MySQL support not enabled. Compile with --features mysql"
        )),
        _ => {
            #[cfg(all(feature = "postgresql", feature = "mysql"))]
            let available_types = ["mongodb", "postgresql", "mysql"];
            #[cfg(all(feature = "postgresql", not(feature = "mysql")))]
            let available_types = ["mongodb", "postgresql"];
            #[cfg(all(not(feature = "postgresql"), feature = "mysql"))]
            let available_types = ["mongodb", "mysql"];
            #[cfg(all(not(feature = "postgresql"), not(feature = "mysql")))]
            let available_types = ["mongodb"];

            Err(anyhow::anyhow!(
                "Unsupported database type: {}. Available types: {}",
                config.r#type,
                available_types.join(", ")
            ))
        }
    }
}

// Re-export pool creation functions for migrations
// Note: These are needed for migration tools
#[allow(unused_imports)]
pub use mongodb::create_database as create_mongo_database;
#[cfg(feature = "mysql")]
pub use mysql::create_pool as create_mysql_pool;
#[cfg(feature = "postgresql")]
pub use postgresql::create_pool as create_pg_pool;
