use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{
    mysql::{MySqlPoolOptions, MySqlRow},
    MySql, Pool, Row,
};
use std::time::Instant;

use super::{AuthDatabase, DatabaseHealth};
use crate::config::database::PoolConfig;
use crate::models::user::{
    CreateUserRequest, LoginAttempt, UpdateUserRequest, User, UserError, UserMetadata, UserRole,
};

pub struct MySqlDatabase {
    pool: Pool<MySql>,
}

impl MySqlDatabase {
    pub async fn new(connection_string: &str, pool_config: &PoolConfig) -> Result<Self> {
        let pool = MySqlPoolOptions::new()
            .max_connections(pool_config.max_connections)
            .min_connections(pool_config.min_connections)
            .idle_timeout(std::time::Duration::from_secs(pool_config.idle_timeout))
            .connect(connection_string)
            .await
            .context("Failed to connect to MySQL database")?;

        Ok(Self { pool })
    }

    /// Convert MySQL row to User model
    fn row_to_user(row: &MySqlRow) -> Result<User, UserError> {
        let metadata_json: String = row
            .try_get("metadata")
            .map_err(|e| UserError::Database(format!("Failed to get metadata: {}", e)))?;

        let metadata: UserMetadata = serde_json::from_str(&metadata_json)
            .map_err(|e| UserError::Database(format!("Failed to deserialize metadata: {}", e)))?;

        let role_str: String = row
            .try_get("role")
            .map_err(|e| UserError::Database(format!("Failed to get role: {}", e)))?;

        let role: UserRole = role_str
            .parse()
            .map_err(|e| UserError::Database(format!("Invalid role: {}", e)))?;

        Ok(User {
            id: None, // MySQL uses auto-increment, not ObjectId
            user_id: row
                .try_get("user_id")
                .map_err(|e| UserError::Database(format!("Failed to get user_id: {}", e)))?,
            email: row
                .try_get("email")
                .map_err(|e| UserError::Database(format!("Failed to get email: {}", e)))?,
            password_hash: row
                .try_get("password_hash")
                .map_err(|e| UserError::Database(format!("Failed to get password_hash: {}", e)))?,
            first_name: row
                .try_get("first_name")
                .map_err(|e| UserError::Database(format!("Failed to get first_name: {}", e)))?,
            last_name: row
                .try_get("last_name")
                .map_err(|e| UserError::Database(format!("Failed to get last_name: {}", e)))?,
            role,
            is_active: row
                .try_get::<i8, _>("is_active")
                .map_err(|e| UserError::Database(format!("Failed to get is_active: {}", e)))?
                != 0,
            email_verified: row
                .try_get::<i8, _>("email_verified")
                .map_err(|e| UserError::Database(format!("Failed to get email_verified: {}", e)))?
                != 0,
            email_verification_token: row.try_get("email_verification_token").map_err(|e| {
                UserError::Database(format!("Failed to get email_verification_token: {}", e))
            })?,
            email_verification_expires: row.try_get("email_verification_expires").map_err(|e| {
                UserError::Database(format!("Failed to get email_verification_expires: {}", e))
            })?,
            password_reset_token: row.try_get("password_reset_token").map_err(|e| {
                UserError::Database(format!("Failed to get password_reset_token: {}", e))
            })?,
            password_reset_expires: row.try_get("password_reset_expires").map_err(|e| {
                UserError::Database(format!("Failed to get password_reset_expires: {}", e))
            })?,
            last_login: row
                .try_get("last_login")
                .map_err(|e| UserError::Database(format!("Failed to get last_login: {}", e)))?,
            login_attempts: row
                .try_get::<u32, _>("login_attempts")
                .map_err(|e| UserError::Database(format!("Failed to get login_attempts: {}", e)))?,
            locked_until: row
                .try_get("locked_until")
                .map_err(|e| UserError::Database(format!("Failed to get locked_until: {}", e)))?,
            created_at: row
                .try_get("created_at")
                .map_err(|e| UserError::Database(format!("Failed to get created_at: {}", e)))?,
            updated_at: row
                .try_get("updated_at")
                .map_err(|e| UserError::Database(format!("Failed to get updated_at: {}", e)))?,
            metadata,
        })
    }
}

#[async_trait]
impl AuthDatabase for MySqlDatabase {
    async fn create_user(&self, user: User) -> Result<User, UserError> {
        if self.user_exists_by_email(&user.email).await? {
            return Err(UserError::EmailAlreadyExists);
        }

        let metadata_json = serde_json::to_string(&user.metadata)
            .map_err(|e| UserError::Database(format!("Failed to serialize metadata: {}", e)))?;

        let query = r#"
            INSERT INTO users (
                user_id, email, password_hash, first_name, last_name, role,
                is_active, email_verified, email_verification_token, email_verification_expires,
                password_reset_token, password_reset_expires, last_login, login_attempts,
                locked_until, created_at, updated_at, metadata
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        "#;

        let result = sqlx::query(query)
            .bind(&user.user_id)
            .bind(&user.email)
            .bind(&user.password_hash)
            .bind(&user.first_name)
            .bind(&user.last_name)
            .bind(user.role.to_string())
            .bind(user.is_active)
            .bind(user.email_verified)
            .bind(&user.email_verification_token)
            .bind(user.email_verification_expires)
            .bind(&user.password_reset_token)
            .bind(user.password_reset_expires)
            .bind(user.last_login)
            .bind(user.login_attempts)
            .bind(user.locked_until)
            .bind(user.created_at)
            .bind(user.updated_at)
            .bind(&metadata_json)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                if e.to_string().contains("Duplicate entry")
                    || e.to_string().contains("UNIQUE constraint")
                {
                    UserError::EmailAlreadyExists
                } else {
                    UserError::Database(format!("Failed to create user: {}", e))
                }
            })?;

        // Fetch the created user
        let user_id = result.last_insert_id();
        let fetch_query = "SELECT * FROM users WHERE id = ?";
        let row = sqlx::query(fetch_query)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to fetch created user: {}", e)))?;

        Self::row_to_user(&row)
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        let query = "SELECT * FROM users WHERE email = ?";

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
        let query = "SELECT * FROM users WHERE user_id = ?";

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

    async fn update_user(&self, user: &User) -> Result<User, UserError> {
        let query = r#"
            UPDATE users SET 
                email = ?,
                password_hash = ?,
                first_name = ?,
                last_name = ?,
                role = ?,
                is_active = ?,
                email_verified = ?,
                email_verification_token = ?,
                email_verification_expires = ?,
                password_reset_token = ?,
                password_reset_expires = ?,
                last_login = ?,
                login_attempts = ?,
                locked_until = ?,
                updated_at = ?
            WHERE user_id = ?
        "#;

        let result = sqlx::query(query)
            .bind(&user.email)
            .bind(&user.password_hash)
            .bind(&user.first_name)
            .bind(&user.last_name)
            .bind(user.role.to_string())
            .bind(user.is_active)
            .bind(user.email_verified)
            .bind(&user.email_verification_token)
            .bind(user.email_verification_expires)
            .bind(&user.password_reset_token)
            .bind(user.password_reset_expires)
            .bind(user.last_login)
            .bind(user.login_attempts as i32)
            .bind(user.locked_until)
            .bind(user.updated_at)
            .bind(&user.user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to update user: {}", e)))?;

        if result.rows_affected() == 0 {
            return Err(UserError::NotFound);
        }

        // Fetch the updated user
        self.find_user_by_id(&user.user_id)
            .await?
            .ok_or(UserError::NotFound)
    }

    async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<(), UserError> {
        let query = "UPDATE users SET password_hash = ?, updated_at = ? WHERE user_id = ?";

        let result = sqlx::query(query)
            .bind(password_hash)
            .bind(Utc::now())
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to update password: {}", e)))?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn set_email_verification_token(
        &self,
        user_id: &str,
        token: &str,
        expires_hours: u64,
    ) -> Result<(), UserError> {
        let expires_at = Utc::now() + chrono::Duration::hours(expires_hours as i64);
        let query = r#"
            UPDATE users SET 
                email_verification_token = ?, 
                email_verification_expires = ?,
                updated_at = ?
            WHERE user_id = ?
        "#;

        let result = sqlx::query(query)
            .bind(token)
            .bind(expires_at)
            .bind(Utc::now())
            .bind(user_id)
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
            WHERE email_verification_token = ? 
            AND email_verification_expires > ?
        "#;

        let row = sqlx::query(query)
            .bind(token)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                UserError::Database(format!("Failed to find verification token: {}", e))
            })?;

        let user_id: String = match row {
            Some(row) => row
                .try_get("user_id")
                .map_err(|e| UserError::Database(format!("Failed to get user_id: {}", e)))?,
            None => return Err(UserError::InvalidVerificationToken),
        };

        let update_query = r#"
            UPDATE users SET 
                email_verified = 1,
                email_verification_token = NULL,
                email_verification_expires = NULL,
                updated_at = ?
            WHERE user_id = ?
        "#;

        sqlx::query(update_query)
            .bind(Utc::now())
            .bind(&user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to verify email: {}", e)))?;

        Ok(user_id)
    }

    async fn set_password_reset_token(
        &self,
        email: &str,
        token: &str,
        expires_hours: u64,
    ) -> Result<(), UserError> {
        let expires_at = Utc::now() + chrono::Duration::hours(expires_hours as i64);
        let query = r#"
            UPDATE users SET 
                password_reset_token = ?, 
                password_reset_expires = ?,
                updated_at = ?
            WHERE email = ?
        "#;

        let result = sqlx::query(query)
            .bind(token)
            .bind(expires_at)
            .bind(Utc::now())
            .bind(email.to_lowercase())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                UserError::Database(format!("Failed to set password reset token: {}", e))
            })?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn verify_password_reset_token(&self, token: &str) -> Result<String, UserError> {
        let query = r#"
            SELECT user_id FROM users 
            WHERE password_reset_token = ? 
            AND password_reset_expires > ?
        "#;

        let row = sqlx::query(query)
            .bind(token)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to find reset token: {}", e)))?;

        match row {
            Some(row) => {
                let user_id: String = row
                    .try_get("user_id")
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
                updated_at = ?
            WHERE user_id = ?
        "#;

        let result = sqlx::query(query)
            .bind(Utc::now())
            .bind(user_id)
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
                last_login = ?,
                login_attempts = 0,
                locked_until = NULL,
                updated_at = ?
            WHERE user_id = ?
        "#;

        let now = Utc::now();
        let result = sqlx::query(query)
            .bind(now)
            .bind(now)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to record login: {}", e)))?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn record_failed_login(
        &self,
        email: &str,
        max_attempts: u32,
        lockout_hours: u64,
    ) -> Result<(), UserError> {
        let increment_query = r#"
            UPDATE users SET 
                login_attempts = login_attempts + 1,
                updated_at = ?
            WHERE email = ?
        "#;

        sqlx::query(increment_query)
            .bind(Utc::now())
            .bind(email.to_lowercase())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                UserError::Database(format!("Failed to increment login attempts: {}", e))
            })?;

        // Get current login attempts
        let check_query = "SELECT login_attempts FROM users WHERE email = ?";
        let row = sqlx::query(check_query)
            .bind(email.to_lowercase())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to check login attempts: {}", e)))?;

        let login_attempts: u32 = match row {
            Some(row) => row
                .try_get("login_attempts")
                .map_err(|e| UserError::Database(format!("Failed to get login_attempts: {}", e)))?,
            None => return Err(UserError::NotFound),
        };

        if login_attempts >= max_attempts {
            let locked_until = Utc::now() + chrono::Duration::hours(lockout_hours as i64);
            let lock_query = r#"
                UPDATE users SET 
                    locked_until = ?,
                    updated_at = ?
                WHERE email = ?
            "#;

            sqlx::query(lock_query)
                .bind(locked_until)
                .bind(Utc::now())
                .bind(email.to_lowercase())
                .execute(&self.pool)
                .await
                .map_err(|e| UserError::Database(format!("Failed to lock account: {}", e)))?;
        }

        Ok(())
    }

    async fn user_exists_by_email(&self, email: &str) -> Result<bool, UserError> {
        let query = "SELECT COUNT(*) as count FROM users WHERE email = ?";

        let row = sqlx::query(query)
            .bind(email.to_lowercase())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to check user existence: {}", e)))?;

        let count: i64 = row
            .try_get("count")
            .map_err(|e| UserError::Database(format!("Failed to get count: {}", e)))?;

        Ok(count > 0)
    }

    async fn deactivate_user(&self, user_id: &str) -> Result<(), UserError> {
        let query = "UPDATE users SET is_active = 0, updated_at = ? WHERE user_id = ?";

        let result = sqlx::query(query)
            .bind(Utc::now())
            .bind(user_id)
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

        let result = sqlx::query("SELECT 1").fetch_one(&self.pool).await;

        let response_time_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(_) => Ok(DatabaseHealth {
                status: "healthy".to_string(),
                database_type: "mysql".to_string(),
                connected: true,
                response_time_ms,
                details: Some("Connected to MySQL database".to_string()),
            }),
            Err(e) => Ok(DatabaseHealth {
                status: "unhealthy".to_string(),
                database_type: "mysql".to_string(),
                connected: false,
                response_time_ms,
                details: Some(format!("Connection error: {}", e)),
            }),
        }
    }

    async fn get_user_by_verification_token(&self, token: &str) -> Result<Option<User>, UserError> {
        let query = "SELECT * FROM users WHERE email_verification_token = ?";

        let row = sqlx::query(query)
            .bind(token)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                UserError::Database(format!("Failed to find user by verification token: {}", e))
            })?;

        match row {
            Some(row) => Ok(Some(Self::row_to_user(&row)?)),
            None => Ok(None),
        }
    }

    async fn get_user_by_reset_token(&self, token: &str) -> Result<Option<User>, UserError> {
        let query = "SELECT * FROM users WHERE password_reset_token = ?";

        let row = sqlx::query(query)
            .bind(token)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                UserError::Database(format!("Failed to find user by reset token: {}", e))
            })?;

        match row {
            Some(row) => Ok(Some(Self::row_to_user(&row)?)),
            None => Ok(None),
        }
    }

    async fn verify_user_email(&self, user_id: &str) -> Result<(), UserError> {
        let query = r#"
            UPDATE users SET 
                email_verified = true,
                email_verification_token = NULL,
                email_verification_expires = NULL,
                updated_at = ?
            WHERE user_id = ?
        "#;

        let result = sqlx::query(query)
            .bind(Utc::now())
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to verify email: {}", e)))?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn update_login_attempts(
        &self,
        user_id: &str,
        attempts: u32,
        locked_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), UserError> {
        let query = r#"
            UPDATE users SET 
                login_attempts = ?,
                locked_until = ?,
                updated_at = ?
            WHERE user_id = ?
        "#;

        let result = sqlx::query(query)
            .bind(attempts as i32)
            .bind(locked_until)
            .bind(Utc::now())
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to update login attempts: {}", e)))?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn update_last_login(&self, user_id: &str) -> Result<(), UserError> {
        let query = r#"
            UPDATE users SET 
                last_login = ?,
                updated_at = ?
            WHERE user_id = ?
        "#;

        let result = sqlx::query(query)
            .bind(Utc::now())
            .bind(Utc::now())
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to update last login: {}", e)))?;

        if result.rows_affected() == 0 {
            Err(UserError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn record_login_attempt(&self, attempt: &LoginAttempt) -> Result<(), UserError> {
        let query = r#"
            INSERT INTO login_attempts (user_id, ip_address, user_agent, success, attempted_at)
            VALUES (?, ?, ?, ?, ?)
        "#;

        sqlx::query(query)
            .bind(&attempt.user_id)
            .bind(&attempt.ip_address)
            .bind(&attempt.user_agent)
            .bind(attempt.success)
            .bind(attempt.attempted_at)
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::Database(format!("Failed to record login attempt: {}", e)))?;

        Ok(())
    }

    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
}

/// Create a MySQL connection pool for migrations
#[allow(dead_code)]
pub async fn create_pool(
    config: &crate::config::database::DatabaseConfig,
) -> Result<sqlx::MySqlPool> {
    use sqlx::mysql::MySqlPoolOptions;

    MySqlPoolOptions::new()
        .max_connections(config.pool.max_connections)
        .min_connections(config.pool.min_connections)
        .idle_timeout(std::time::Duration::from_secs(config.pool.idle_timeout))
        .connect(&config.url)
        .await
        .context("Failed to connect to MySQL database")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::database::PoolConfig;
    use crate::models::user::{CreateUserRequest, UserRole};

    // Note: These tests require a running MySQL instance
    // Run with: docker run -d -p 3306:3306 -e MYSQL_ROOT_PASSWORD=password -e MYSQL_DATABASE=auth_service_test mysql:8.0

    async fn create_test_database() -> MySqlDatabase {
        let pool_config = PoolConfig::default();
        MySqlDatabase::new(
            "mysql://root:password@localhost:3306/auth_service_test",
            &pool_config,
        )
        .await
        .expect("Failed to create test database")
    }

    fn create_test_user() -> User {
        let request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            role: Some(UserRole::User),
            metadata: None,
        };
        User::new(request, "hashed_password".to_string())
    }

    #[tokio::test]
    #[ignore] // Requires MySQL instance and schema
    async fn test_database_health_check() {
        let db = create_test_database().await;
        let health = db.health_check().await.unwrap();
        assert_eq!(health.database_type, "mysql");
    }

    #[tokio::test]
    #[ignore] // Requires MySQL instance and schema
    async fn test_user_crud_operations() {
        let db = create_test_database().await;
        db.initialize().await.unwrap();

        let user = create_test_user();
        let email = user.email.clone();
        let user_id = user.user_id.clone();

        // Create user
        let created_user = db.create_user(user).await.unwrap();
        assert_eq!(created_user.email, email);

        // Find by email
        let found_user = db.find_user_by_email(&email).await.unwrap();
        assert!(found_user.is_some());
        assert_eq!(found_user.unwrap().user_id, user_id);

        // Find by ID
        let found_user = db.find_user_by_id(&user_id).await.unwrap();
        assert!(found_user.is_some());

        // Update user
        let mut user_to_update = db.get_user_by_id(&user_id).await.unwrap().unwrap();
        user_to_update.first_name = "Updated".to_string();
        let updated_user = db.update_user(&user_to_update).await.unwrap();
        assert_eq!(updated_user.first_name, "Updated");

        // Clean up
        db.deactivate_user(&user_id).await.unwrap();
    }
}
