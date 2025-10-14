use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{
    postgres::{PgPoolOptions, PgRow},
    Pool, Postgres, Row,
};
use std::time::Instant;

use crate::config::database::PoolConfig;
use crate::models::user::{User, UpdateUserRequest, UserError, UserRole, UserMetadata};
use super::{AuthDatabase, DatabaseHealth};

pub struct PostgresDatabase {
    pool: Pool<Postgres>,
}

impl PostgresDatabase {
    pub async fn new(connection_string: &str, pool_config: &PoolConfig) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(pool_config.max_connections)
            .min_connections(pool_config.min_connections)
            .idle_timeout(std::time::Duration::from_secs(pool_config.idle_timeout))
            .connect(connection_string)
            .await
            .context("Failed to connect to PostgreSQL database")?;

        Ok(Self { pool })
    }

    /// Convert PostgreSQL row to User model
    fn row_to_user(row: &PgRow) -> Result<User, UserError> {
        let metadata_json: serde_json::Value = row.try_get("metadata")
            .map_err(|e| UserError::Database(format!("Failed to get metadata: {}", e)))?;
        
        let metadata: UserMetadata = serde_json::from_value(metadata_json)
            .map_err(|e| UserError::Database(format!("Failed to deserialize metadata: {}", e)))?;

        let role_str: String = row.try_get("role")
            .map_err(|e| UserError::Database(format!("Failed to get role: {}", e)))?;
        
        let role: UserRole = role_str.parse()
            .map_err(|e| UserError::Database(format!("Invalid role: {}", e)))?;

        Ok(User {
            id: Some(row.try_get::<i64, _>("id")
                .map_err(|e| UserError::Database(format!("Failed to get id: {}", e)))?.to_string()),
            user_id: row.try_get("user_id")
                .map_err(|e| UserError::Database(format!("Failed to get user_id: {}", e)))?,
            email: row.try_get("email")
                .map_err(|e| UserError::Database(format!("Failed to get email: {}", e)))?,
            password_hash: row.try_get("password_hash")
                .map_err(|e| UserError::Database(format!("Failed to get password_hash: {}", e)))?,
            first_name: row.try_get("first_name")
                .map_err(|e| UserError::Database(format!("Failed to get first_name: {}", e)))?,
            last_name: row.try_get("last_name")
                .map_err(|e| UserError::Database(format!("Failed to get last_name: {}", e)))?,
            role,
            is_active: row.try_get("is_active")
                .map_err(|e| UserError::Database(format!("Failed to get is_active: {}", e)))?,
            email_verified: row.try_get("email_verified")
                .map_err(|e| UserError::Database(format!("Failed to get email_verified: {}", e)))?,
            email_verification_token: row.try_get("email_verification_token")
                .map_err(|e| UserError::Database(format!("Failed to get email_verification_token: {}", e)))?,
            email_verification_expires: row.try_get("email_verification_expires")
                .map_err(|e| UserError::Database(format!("Failed to get email_verification_expires: {}", e)))?,
            password_reset_token: row.try_get("password_reset_token")
                .map_err(|e| UserError::Database(format!("Failed to get password_reset_token: {}", e)))?,
            password_reset_expires: row.try_get("password_reset_expires")
                .map_err(|e| UserError::Database(format!("Failed to get password_reset_expires: {}", e)))?,
            last_login: row.try_get("last_login")
                .map_err(|e| UserError::Database(format!("Failed to get last_login: {}", e)))?,
            login_attempts: row.try_get::<i32, _>("login_attempts")
                .map_err(|e| UserError::Database(format!("Failed to get login_attempts: {}", e)))? as u32,
            locked_until: row.try_get("locked_until")
                .map_err(|e| UserError::Database(format!("Failed to get locked_until: {}", e)))?,
            created_at: row.try_get("created_at")
                .map_err(|e| UserError::Database(format!("Failed to get created_at: {}", e)))?,
            updated_at: row.try_get("updated_at")
                .map_err(|e| UserError::Database(format!("Failed to get updated_at: {}", e)))?,
            metadata,
        })
    }
}

#[async_trait]
impl AuthDatabase for PostgresDatabase {
    async fn create_user(&self, user: User) -> Result<User, UserError> {
        if self.user_exists_by_email(&user.email).await? {
            return Err(UserError::EmailAlreadyExists);
        }

        let metadata_json = serde_json::to_value(&user.metadata)
            .map_err(|e| UserError::Database(format!("Failed to serialize metadata: {}", e)))?;

        let query = r#"
            INSERT INTO users (
                user_id, email, password_hash, first_name, last_name, role,
                is_active, email_verified, email_verification_token, email_verification_expires,
                password_reset_token, password_reset_expires, last_login, login_attempts,
                locked_until, created_at, updated_at, metadata
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
            ) RETURNING *
        "#;

        let row = sqlx::query(query)
            .bind(&user.user_id)
            .bind(&user.email)
            .bind(&user.password_hash)
            .bind(&user.first_name)
            .bind(&user.last_name)
            .bind(&user.role.to_string())
            .bind(user.is_active)
            .bind(user.email_verified)
            .bind(&user.email_verification_token)
            .bind(&user.email_verification_expires)
            .bind(&user.password_reset_token)
            .bind(&user.password_reset_expires)
            .bind(&user.last_login)
            .bind(user.login_attempts as i32)
            .bind(&user.locked_until)
            .bind(&user.created_at)
            .bind(&user.updated_at)
            .bind(&metadata_json)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                if e.to_string().contains("duplicate key") || e.to_string().contains("unique constraint") {
                    UserError::EmailAlreadyExists
                } else {
                    UserError::Database(format!("Failed to create user: {}", e))
                }
            })?;

        Self::row_to_user(&row)
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        let query = "SELECT * FROM users WHERE email = $1";
        
        let row = sqlx::query(query)
            .bind(email.to_lowercase())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to find user by email: {}", e)))?;

        match row {
            Some(row) => Ok(Some(Self::row_to_user(&row)?)),
            None => Ok(None),
        }
    }

    async fn find_user_by_id(&self, user_id: &str) -> Result<Option<User>, UserError> {
        let query = "SELECT * FROM users WHERE user_id = $1";
        
        let row = sqlx::query(query)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to find user by ID: {}", e)))?;

        match row {
            Some(row) => Ok(Some(Self::row_to_user(&row)?)),
            None => Ok(None),
        }
    }

    async fn update_user(&self, user_id: &str, updates: UpdateUserRequest) -> Result<User, UserError> {
        let query = r#"
            UPDATE users SET 
                first_name = COALESCE($2, first_name),
                last_name = COALESCE($3, last_name),
                role = COALESCE($4, role),
                is_active = COALESCE($5, is_active),
                updated_at = $6
            WHERE user_id = $1 
            RETURNING *
        "#;

        let row = sqlx::query(query)
            .bind(user_id)
            .bind(&updates.first_name)
            .bind(&updates.last_name)
            .bind(updates.role.as_ref().map(|r| r.to_string()))
            .bind(&updates.is_active)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to update user: {}", e)))?;

        match row {
            Some(row) => Ok(Self::row_to_user(&row)?),
            None => Err(UserError::NotFound),
        }
    }

    async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<(), UserError> {
        let query = "UPDATE users SET password_hash = $2, updated_at = $3 WHERE user_id = $1";
        
        let result = sqlx::query(query)
            .bind(user_id)
            .bind(password_hash)
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to update password: {}", e)))?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn set_email_verification_token(&self, user_id: &str, token: &str, expires_hours: u64) -> Result<(), UserError> {
        let expires_at = Utc::now() + chrono::Duration::hours(expires_hours as i64);
        let query = r#"
            UPDATE users SET 
                email_verification_token = $2, 
                email_verification_expires = $3,
                updated_at = $4
            WHERE user_id = $1
        "#;

        let result = sqlx::query(query)
            .bind(user_id)
            .bind(token)
            .bind(expires_at)
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to set verification token: {}", e)))?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn verify_email(&self, token: &str) -> Result<String, UserError> {
        let query = r#"
            SELECT user_id FROM users 
            WHERE email_verification_token = $1 
            AND email_verification_expires > $2
        "#;

        let row = sqlx::query(query)
            .bind(token)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to find verification token: {}", e)))?;

        let user_id: String = match row {
            Some(row) => row.try_get("user_id")
                .map_err(|e| UserError::Database(format!("Failed to get user_id: {}", e)))?,
            None => return Err(UserError::InvalidVerificationToken),
        };

        let update_query = r#"
            UPDATE users SET 
                email_verified = true,
                email_verification_token = NULL,
                email_verification_expires = NULL,
                updated_at = $2
            WHERE user_id = $1
        "#;

        sqlx::query(update_query)
            .bind(&user_id)
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to verify email: {}", e)))?;

        Ok(user_id)
    }

    async fn set_password_reset_token(&self, email: &str, token: &str, expires_hours: u64) -> Result<(), UserError> {
        let expires_at = Utc::now() + chrono::Duration::hours(expires_hours as i64);
        let query = r#"
            UPDATE users SET 
                password_reset_token = $2, 
                password_reset_expires = $3,
                updated_at = $4
            WHERE email = $1
        "#;

        let result = sqlx::query(query)
            .bind(email.to_lowercase())
            .bind(token)
            .bind(expires_at)
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to set password reset token: {}", e)))?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn verify_password_reset_token(&self, token: &str) -> Result<String, UserError> {
        let query = r#"
            SELECT user_id FROM users 
            WHERE password_reset_token = $1 
            AND password_reset_expires > $2
        "#;

        let row = sqlx::query(query)
            .bind(token)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to find reset token: {}", e)))?;

        match row {
            Some(row) => {
                let user_id: String = row.try_get("user_id")
                    .map_err(|e| UserError::Database(format!("Failed to get user_id: {}", e)))?;
                Ok(user_id)
            }
            None => Err(UserError::InvalidPasswordResetToken),
        }
    }

    async fn clear_password_reset_token(&self, user_id: &str) -> Result<(), UserError> {
        let query = r#"
            UPDATE users SET 
                password_reset_token = NULL,
                password_reset_expires = NULL,
                updated_at = $2
            WHERE user_id = $1
        "#;

        let result = sqlx::query(query)
            .bind(user_id)
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to clear reset token: {}", e)))?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn record_login(&self, user_id: &str) -> Result<(), UserError> {
        let query = r#"
            UPDATE users SET 
                last_login = $2,
                login_attempts = 0,
                locked_until = NULL,
                updated_at = $2
            WHERE user_id = $1
        "#;

        let result = sqlx::query(query)
            .bind(user_id)
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to record login: {}", e)))?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn record_failed_login(&self, email: &str, max_attempts: u32, lockout_hours: u64) -> Result<(), UserError> {
        let increment_query = r#"
            UPDATE users SET 
                login_attempts = login_attempts + 1,
                updated_at = $2
            WHERE email = $1
            RETURNING login_attempts
        "#;

        let row = sqlx::query(increment_query)
            .bind(email.to_lowercase())
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to increment login attempts: {}", e)))?;

        let login_attempts: i32 = match row {
            Some(row) => row.try_get("login_attempts")
                .map_err(|e| UserError::Database(format!("Failed to get login_attempts: {}", e)))?,
            None => return Err(UserError::NotFound),
        };

        if login_attempts >= max_attempts as i32 {
            let locked_until = Utc::now() + chrono::Duration::hours(lockout_hours as i64);
            let lock_query = r#"
                UPDATE users SET 
                    locked_until = $2,
                    updated_at = $2
                WHERE email = $1
            "#;

            sqlx::query(lock_query)
                .bind(email.to_lowercase())
                .bind(locked_until)
                .execute(&self.pool)
                .await
                .map_err(|e| UserError::Database(format!("Failed to lock account: {}", e)))?;
        }

        Ok(())
    }

    async fn user_exists_by_email(&self, email: &str) -> Result<bool, UserError> {
        let query = "SELECT COUNT(*) as count FROM users WHERE email = $1";
        
        let row = sqlx::query(query)
            .bind(email.to_lowercase())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to check user existence: {}", e)))?;

        let count: i64 = row.try_get("count")
            .map_err(|e| UserError::Database(format!("Failed to get count: {}", e)))?;

        Ok(count > 0)
    }

    async fn deactivate_user(&self, user_id: &str) -> Result<(), UserError> {
        let query = "UPDATE users SET is_active = false, updated_at = $2 WHERE user_id = $1";
        
        let result = sqlx::query(query)
            .bind(user_id)
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to deactivate user: {}", e)))?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn health_check(&self) -> Result<DatabaseHealth> {
        let start = Instant::now();
        
        let result = sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await;
        
        let response_time_ms = start.elapsed().as_millis() as u64;
        
        match result {
            Ok(_) => Ok(DatabaseHealth {
                status: "healthy".to_string(),
                database_type: "postgresql".to_string(),
                connected: true,
                response_time_ms,
                details: Some("Connected to PostgreSQL database".to_string()),
            }),
            Err(e) => Ok(DatabaseHealth {
                status: "unhealthy".to_string(),
                database_type: "postgresql".to_string(),
                connected: false,
                response_time_ms,
                details: Some(format!("Connection error: {}", e)),
            }),
        }
    }

    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
}