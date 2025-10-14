use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mongodb::{
    bson::{doc, Document, Bson},
    options::{ClientOptions, IndexOptions},
    Client, Collection, Database, IndexModel,
};
use std::time::Instant;

use crate::config::database::PoolConfig;
use crate::models::user::{User, UserError, LoginAttempt};
use super::{AuthDatabase, DatabaseHealth};

const USERS_COLLECTION: &str = "users";
const DATABASE_NAME: &str = "auth_service";

pub struct MongoDatabase {
    database: Database,
    users: Collection<User>,
}

impl MongoDatabase {
    pub async fn new(connection_string: &str, _pool_config: &PoolConfig) -> Result<Self> {
        let client_options = ClientOptions::parse(connection_string)
            .await
            .context("Failed to parse MongoDB connection string")?;

        let client = Client::with_options(client_options)
            .context("Failed to create MongoDB client")?;

        let database = client.database(DATABASE_NAME);
        let users = database.collection::<User>(USERS_COLLECTION);

        Ok(Self { database, users })
    }

    async fn create_indexes(&self) -> Result<()> {
        let email_index = IndexModel::builder()
            .keys(doc! { "email": 1 })
            .options(
                IndexOptions::builder()
                    .unique(true)
                    .name("email_unique".to_string())
                    .build(),
            )
            .build();

        let user_id_index = IndexModel::builder()
            .keys(doc! { "user_id": 1 })
            .options(
                IndexOptions::builder()
                    .unique(true)
                    .name("user_id_unique".to_string())
                    .build(),
            )
            .build();

        let verification_token_index = IndexModel::builder()
            .keys(doc! { "email_verification_token": 1 })
            .options(
                IndexOptions::builder()
                    .sparse(true)
                    .name("email_verification_token".to_string())
                    .build(),
            )
            .build();

        let reset_token_index = IndexModel::builder()
            .keys(doc! { "password_reset_token": 1 })
            .options(
                IndexOptions::builder()
                    .sparse(true)
                    .name("password_reset_token".to_string())
                    .build(),
            )
            .build();

        let created_at_index = IndexModel::builder()
            .keys(doc! { "created_at": 1 })
            .options(
                IndexOptions::builder()
                    .name("created_at".to_string())
                    .build(),
            )
            .build();

        self.users
            .create_indexes(
                vec![
                    email_index,
                    user_id_index,
                    verification_token_index,
                    reset_token_index,
                    created_at_index,
                ],
                None,
            )
            .await
            .context("Failed to create database indexes")?;

        Ok(())
    }
}

#[async_trait]
impl AuthDatabase for MongoDatabase {
    async fn create_user(&self, user: User) -> Result<User, UserError> {
        // Check if user already exists
        if self.user_exists_by_email(&user.email).await? {
            return Err(UserError::EmailAlreadyExists);
        }

        let result = self.users.insert_one(&user, None).await;

        match result {
            Ok(insert_result) => {
                let mut created_user = user;
                if let Some(object_id) = insert_result.inserted_id.as_object_id() {
                    created_user.id = Some(object_id);
                }
                Ok(created_user)
            }
            Err(e) => {
                if e.to_string().contains("duplicate key") {
                    Err(UserError::EmailAlreadyExists)
                } else {
                    Err(UserError::Database(format!("Failed to create user: {}", e)))
                }
            }
        }
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        let filter = doc! { "email": email.to_lowercase() };
        
        match self.users.find_one(filter, None).await {
            Ok(user) => Ok(user),
            Err(e) => Err(UserError::Database(format!("Failed to find user by email: {}", e))),
        }
    }

    async fn find_user_by_id(&self, user_id: &str) -> Result<Option<User>, UserError> {
        let filter = doc! { "user_id": user_id };
        
        match self.users.find_one(filter, None).await {
            Ok(user) => Ok(user),
            Err(e) => Err(UserError::Database(format!("Failed to find user by ID: {}", e))),
        }
    }

    async fn update_user(&self, user: &User) -> Result<User, UserError> {
        let user_doc = mongodb::bson::to_document(user)
            .map_err(|e| UserError::Database(format!("Failed to serialize user: {}", e)))?;

        let filter = doc! { "user_id": &user.user_id };
        let update = doc! { "$set": user_doc };

        match self.users.update_one(filter.clone(), update, None).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    // Fetch and return updated user
                    self.find_user_by_id(&user.user_id).await?
                        .ok_or(UserError::NotFound)
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to update user: {}", e))),
        }
    }

    async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = doc! {
            "$set": {
                "password_hash": password_hash,
                "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
            }
        };

        match self.users.update_one(filter, update, None).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to update password: {}", e))),
        }
    }

    async fn set_email_verification_token(&self, user_id: &str, token: &str, expires_hours: u64) -> Result<(), UserError> {
        let expires_at = Utc::now() + chrono::Duration::hours(expires_hours as i64);
        
        let filter = doc! { "user_id": user_id };
        let update = doc! {
            "$set": {
                "email_verification_token": token,
                "email_verification_expires": mongodb::bson::DateTime::from_system_time(expires_at.into()),
                "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
            }
        };

        match self.users.update_one(filter, update, None).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to set verification token: {}", e))),
        }
    }

    async fn verify_email(&self, token: &str) -> Result<String, UserError> {
        let filter = doc! {
            "email_verification_token": token,
            "email_verification_expires": { "$gt": mongodb::bson::DateTime::from_system_time(Utc::now().into()) }
        };

        let user = self.users.find_one(filter, None).await
            .map_err(|e| UserError::Database(format!("Failed to find verification token: {}", e)))?;

        let user = user.ok_or(UserError::InvalidVerificationToken)?;

        // Update user to mark email as verified
        let update_filter = doc! { "user_id": &user.user_id };
        let update = doc! {
            "$set": {
                "email_verified": true,
                "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
            },
            "$unset": {
                "email_verification_token": "",
                "email_verification_expires": ""
            }
        };

        self.users.update_one(update_filter, update, None).await
            .map_err(|e| UserError::Database(format!("Failed to verify email: {}", e)))?;

        Ok(user.user_id)
    }

    async fn set_password_reset_token(&self, email: &str, token: &str, expires_hours: u64) -> Result<(), UserError> {
        let expires_at = Utc::now() + chrono::Duration::hours(expires_hours as i64);
        
        let filter = doc! { "email": email.to_lowercase() };
        let update = doc! {
            "$set": {
                "password_reset_token": token,
                "password_reset_expires": mongodb::bson::DateTime::from_system_time(expires_at.into()),
                "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
            }
        };

        match self.users.update_one(filter, update, None).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to set password reset token: {}", e))),
        }
    }

    async fn verify_password_reset_token(&self, token: &str) -> Result<String, UserError> {
        let filter = doc! {
            "password_reset_token": token,
            "password_reset_expires": { "$gt": mongodb::bson::DateTime::from_system_time(Utc::now().into()) }
        };

        let user = self.users.find_one(filter, None).await
            .map_err(|e| UserError::Database(format!("Failed to find reset token: {}", e)))?;

        let user = user.ok_or(UserError::InvalidPasswordResetToken)?;
        Ok(user.user_id)
    }

    async fn clear_password_reset_token(&self, user_id: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = doc! {
            "$unset": {
                "password_reset_token": "",
                "password_reset_expires": ""
            },
            "$set": {
                "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
            }
        };

        match self.users.update_one(filter, update, None).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to clear reset token: {}", e))),
        }
    }

    async fn record_login(&self, user_id: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = doc! {
            "$set": {
                "last_login": mongodb::bson::DateTime::from_system_time(Utc::now().into()),
                "login_attempts": 0,
                "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
            },
            "$unset": {
                "locked_until": ""
            }
        };

        match self.users.update_one(filter, update, None).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to record login: {}", e))),
        }
    }

    async fn record_failed_login(&self, email: &str, max_attempts: u32, lockout_hours: u64) -> Result<(), UserError> {
        let filter = doc! { "email": email.to_lowercase() };
        
        // First, increment login attempts
        let update = doc! {
            "$inc": { "login_attempts": 1 },
            "$set": { "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into()) }
        };

        self.users.update_one(filter.clone(), update, None).await
            .map_err(|e| UserError::Database(format!("Failed to increment login attempts: {}", e)))?;

        // Check if we need to lock the account
        let user = self.find_user_by_email(email).await?;
        if let Some(user) = user {
            if user.login_attempts >= max_attempts {
                let locked_until = Utc::now() + chrono::Duration::hours(lockout_hours as i64);
                let lock_update = doc! {
                    "$set": {
                        "locked_until": mongodb::bson::DateTime::from_system_time(locked_until.into()),
                        "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
                    }
                };

                self.users.update_one(filter, lock_update, None).await
                    .map_err(|e| UserError::Database(format!("Failed to lock account: {}", e)))?;
            }
        }

        Ok(())
    }

    async fn user_exists_by_email(&self, email: &str) -> Result<bool, UserError> {
        let filter = doc! { "email": email.to_lowercase() };
        
        match self.users.count_documents(filter, None).await {
            Ok(count) => Ok(count > 0),
            Err(e) => Err(UserError::Database(format!("Failed to check user existence: {}", e))),
        }
    }

    async fn deactivate_user(&self, user_id: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = doc! {
            "$set": {
                "is_active": false,
                "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
            }
        };

        match self.users.update_one(filter, update, None).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to deactivate user: {}", e))),
        }
    }

    async fn health_check(&self) -> Result<DatabaseHealth> {
        let start = Instant::now();
        
        let result = self.database.run_command(doc! { "ping": 1 }, None).await;
        
        let response_time_ms = start.elapsed().as_millis() as u64;
        
        match result {
            Ok(_) => Ok(DatabaseHealth {
                status: "healthy".to_string(),
                database_type: "mongodb".to_string(),
                connected: true,
                response_time_ms,
                details: Some(format!("Connected to database: {}", DATABASE_NAME)),
            }),
            Err(e) => Ok(DatabaseHealth {
                status: "unhealthy".to_string(),
                database_type: "mongodb".to_string(),
                connected: false,
                response_time_ms,
                details: Some(format!("Connection error: {}", e)),
            }),
        }
    }

    async fn get_user_by_verification_token(&self, token: &str) -> Result<Option<User>, UserError> {
        let filter = doc! { "email_verification_token": token };
        
        match self.users.find_one(filter, None).await {
            Ok(user) => Ok(user),
            Err(e) => Err(UserError::Database(format!("Failed to find user by verification token: {}", e))),
        }
    }
    
    async fn get_user_by_reset_token(&self, token: &str) -> Result<Option<User>, UserError> {
        let filter = doc! { "password_reset_token": token };
        
        match self.users.find_one(filter, None).await {
            Ok(user) => Ok(user),
            Err(e) => Err(UserError::Database(format!("Failed to find user by reset token: {}", e))),
        }
    }
    
    async fn verify_user_email(&self, user_id: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = doc! {
            "$set": {
                "email_verified": true,
                "email_verification_token": Bson::Null,
                "email_verification_expires": Bson::Null,
                "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
            }
        };

        match self.users.update_one(filter, update, None).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to verify email: {}", e))),
        }
    }
    
    async fn update_login_attempts(&self, user_id: &str, attempts: u32, locked_until: Option<chrono::DateTime<chrono::Utc>>) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let mut update_doc = doc! {
            "login_attempts": attempts as i32,
            "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
        };
        
        if let Some(locked_time) = locked_until {
            update_doc.insert("locked_until", mongodb::bson::DateTime::from_system_time(locked_time.into()));
        } else {
            update_doc.insert("locked_until", Bson::Null);
        }
        
        let update = doc! { "$set": update_doc };

        match self.users.update_one(filter, update, None).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to update login attempts: {}", e))),
        }
    }
    
    async fn update_last_login(&self, user_id: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = doc! {
            "$set": {
                "last_login": mongodb::bson::DateTime::from_system_time(Utc::now().into()),
                "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
            }
        };

        match self.users.update_one(filter, update, None).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to update last login: {}", e))),
        }
    }
    
    async fn record_login_attempt(&self, attempt: &LoginAttempt) -> Result<(), UserError> {
        let login_attempt_doc = doc! {
            "user_id": &attempt.user_id,
            "ip_address": &attempt.ip_address,
            "user_agent": &attempt.user_agent,
            "success": attempt.success,
            "attempted_at": mongodb::bson::DateTime::from_system_time(attempt.attempted_at.into())
        };

        match self.database.collection::<Document>("login_attempts").insert_one(login_attempt_doc, None).await {
            Ok(_) => Ok(()),
            Err(e) => Err(UserError::Database(format!("Failed to record login attempt: {}", e))),
        }
    }

    async fn initialize(&self) -> Result<()> {
        self.create_indexes().await
            .context("Failed to initialize database indexes")?;
        Ok(())
    }
}

/// Create a MongoDB database connection for migrations
pub async fn create_database(config: &crate::config::database::DatabaseConfig) -> Result<mongodb::Database> {
    use mongodb::{Client, options::ClientOptions};
    
    let client_options = ClientOptions::parse(&config.url).await
        .context("Failed to parse MongoDB connection string")?;
    
    let client = Client::with_options(client_options)
        .context("Failed to create MongoDB client")?;
        
    Ok(client.database(DATABASE_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::database::PoolConfig;
    use crate::models::user::{CreateUserRequest, UserRole};

    // Note: These tests require a running MongoDB instance
    // Run with: docker run -d -p 27017:27017 mongo:latest

    async fn create_test_database() -> MongoDatabase {
        let pool_config = PoolConfig::default();
        MongoDatabase::new("mongodb://localhost:27017", &pool_config)
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
    #[ignore] // Requires MongoDB instance
    async fn test_database_health_check() {
        let db = create_test_database().await;
        let health = db.health_check().await.unwrap();
        assert_eq!(health.database_type, "mongodb");
    }

    #[tokio::test]
    #[ignore] // Requires MongoDB instance
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
        let update_request = UpdateUserRequest {
            first_name: Some("Updated".to_string()),
            ..Default::default()
        };
        let updated_user = db.update_user(&user_id, update_request).await.unwrap();
        assert_eq!(updated_user.first_name, "Updated");

        // Clean up
        db.deactivate_user(&user_id).await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Requires MongoDB instance
    async fn test_email_verification_flow() {
        let db = create_test_database().await;
        db.initialize().await.unwrap();

        let user = create_test_user();
        let user_id = user.user_id.clone();
        
        let created_user = db.create_user(user).await.unwrap();
        assert!(!created_user.email_verified);

        // Set verification token
        let token = "verification_token_123";
        db.set_email_verification_token(&user_id, token, 24).await.unwrap();

        // Verify email
        let verified_user_id = db.verify_email(token).await.unwrap();
        assert_eq!(verified_user_id, user_id);

        // Check user is now verified
        let verified_user = db.find_user_by_id(&user_id).await.unwrap().unwrap();
        assert!(verified_user.email_verified);

        // Clean up
        db.deactivate_user(&user_id).await.unwrap();
    }
}