use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use futures::stream::TryStreamExt;
use mongodb::{
    bson::{doc, Bson, Document},
    options::{ClientOptions, IndexOptions},
    Client, Collection, Database, IndexModel,
};
use std::time::Instant;

use super::{AuthDatabase, DatabaseHealth};
use crate::config::database::PoolConfig;
use crate::models::user::{LoginAttempt, User, UserError};
// use crate::oauth2::{
//     AccessToken, AuthorizationCode, DeviceAuthorization, OAuth2Client, OAuth2Service, RefreshToken,
//     TokenIntrospection,
// };

const USERS_COLLECTION: &str = "users";
// OAuth2 collections constants disabled until module is re-enabled
// const OAUTH2_CLIENTS_COLLECTION: &str = "oauth2_clients";
// const OAUTH2_AUTH_CODES_COLLECTION: &str = "oauth2_auth_codes";
// const OAUTH2_ACCESS_TOKENS_COLLECTION: &str = "oauth2_access_tokens";
// const OAUTH2_REFRESH_TOKENS_COLLECTION: &str = "oauth2_refresh_tokens";
// const OAUTH2_DEVICE_AUTHORIZATIONS_COLLECTION: &str = "oauth2_device_authorizations";
const DATABASE_NAME: &str = "auth_service";

pub struct MongoDatabase {
    database: Database,
    users: Collection<User>,
    // OAuth2 collections disabled until module is re-enabled
    // oauth2_clients: Collection<OAuth2Client>,
    // oauth2_auth_codes: Collection<AuthorizationCode>,
    // oauth2_access_tokens: Collection<AccessToken>,
    // oauth2_refresh_tokens: Collection<RefreshToken>,
    // oauth2_device_authorizations: Collection<DeviceAuthorization>,
}

impl MongoDatabase {
    pub async fn new(connection_string: &str, _pool_config: &PoolConfig) -> Result<Self> {
        let client_options = ClientOptions::parse(connection_string)
            .await
            .context("Failed to parse MongoDB connection string")?;

        let client =
            Client::with_options(client_options).context("Failed to create MongoDB client")?;

        let database = client.database(DATABASE_NAME);
        let users = database.collection::<User>(USERS_COLLECTION);
        // OAuth2 collections disabled until module is re-enabled
        // let oauth2_clients = database.collection::<OAuth2Client>(OAUTH2_CLIENTS_COLLECTION);
        // let oauth2_auth_codes =
        //     database.collection::<AuthorizationCode>(OAUTH2_AUTH_CODES_COLLECTION);
        // let oauth2_access_tokens =
        //     database.collection::<AccessToken>(OAUTH2_ACCESS_TOKENS_COLLECTION);
        // let oauth2_refresh_tokens =
        //     database.collection::<RefreshToken>(OAUTH2_REFRESH_TOKENS_COLLECTION);
        // let oauth2_device_authorizations =
        //     database.collection::<DeviceAuthorization>(OAUTH2_DEVICE_AUTHORIZATIONS_COLLECTION);

        Ok(Self {
            database,
            users,
            // oauth2_clients,
            // oauth2_auth_codes,
            // oauth2_access_tokens,
            // oauth2_refresh_tokens,
            // oauth2_device_authorizations,
        })
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
            .create_indexes(vec![
                email_index,
                user_id_index,
                verification_token_index,
                reset_token_index,
                created_at_index,
            ])
            .await
            .context("Failed to create database indexes")?;

        Ok(())
    }

    /// Helper function to perform update operations with consistent error handling
    async fn update_user_by_filter(
        &self,
        filter: Document,
        update: Document,
        operation_name: &str,
    ) -> Result<(), UserError> {
        match self.users.update_one(filter, update).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!(
                "Failed to {operation_name}: {e}"
            ))),
        }
    }

    /// Helper function to create consistent update documents with updated_at timestamp
    fn create_update_doc(fields: Document) -> Document {
        let mut update_fields = fields;
        update_fields.insert(
            "updated_at",
            mongodb::bson::DateTime::from_system_time(Utc::now().into()),
        );
        doc! { "$set": update_fields }
    }

    /// Helper function to create update documents with both set and unset operations
    fn create_update_doc_with_unset(set_fields: Document, unset_fields: Document) -> Document {
        let mut update_fields = set_fields;
        update_fields.insert(
            "updated_at",
            mongodb::bson::DateTime::from_system_time(Utc::now().into()),
        );
        doc! {
            "$set": update_fields,
            "$unset": unset_fields
        }
    }
}

#[async_trait]
impl AuthDatabase for MongoDatabase {
    async fn create_user(&self, user: User) -> Result<User, UserError> {
        // Check if user already exists
        if self.user_exists_by_email(&user.email).await? {
            return Err(UserError::EmailAlreadyExists);
        }

        let result = self.users.insert_one(&user).await;

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
                    Err(UserError::Database(format!("Failed to create user: {e}")))
                }
            }
        }
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        let filter = doc! { "email": email.to_lowercase() };

        match self.users.find_one(filter).await {
            Ok(user) => Ok(user),
            Err(e) => Err(UserError::Database(format!(
                "Failed to find user by email: {e}"
            ))),
        }
    }

    async fn find_user_by_id(&self, user_id: &str) -> Result<Option<User>, UserError> {
        let filter = doc! { "user_id": user_id };

        match self.users.find_one(filter).await {
            Ok(user) => Ok(user),
            Err(e) => Err(UserError::Database(format!(
                "Failed to find user by ID: {e}"
            ))),
        }
    }

    async fn update_user(&self, user: &User) -> Result<User, UserError> {
        let user_doc = mongodb::bson::to_document(user)
            .map_err(|e| UserError::Database(format!("Failed to serialize user: {e}")))?;

        let filter = doc! { "user_id": &user.user_id };
        let update = doc! { "$set": user_doc };

        match self.users.update_one(filter.clone(), update).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    // Fetch and return updated user
                    self.find_user_by_id(&user.user_id)
                        .await?
                        .ok_or(UserError::NotFound)
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to update user: {e}"))),
        }
    }

    async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = Self::create_update_doc(doc! {
            "password_hash": password_hash
        });

        self.update_user_by_filter(filter, update, "update password")
            .await
    }

    async fn set_email_verification_token(
        &self,
        user_id: &str,
        token: &str,
        expires_hours: u64,
    ) -> Result<(), UserError> {
        let expires_at = Utc::now() + chrono::Duration::hours(expires_hours as i64);
        let filter = doc! { "user_id": user_id };
        let update = Self::create_update_doc(doc! {
            "email_verification_token": token,
            "email_verification_expires": mongodb::bson::DateTime::from_system_time(expires_at.into())
        });

        self.update_user_by_filter(filter, update, "set verification token")
            .await
    }

    async fn verify_email(&self, token: &str) -> Result<String, UserError> {
        let filter = doc! {
            "email_verification_token": token,
            "email_verification_expires": { "$gt": mongodb::bson::DateTime::from_system_time(Utc::now().into()) }
        };

        let user =
            self.users.find_one(filter).await.map_err(|e| {
                UserError::Database(format!("Failed to find verification token: {e}"))
            })?;

        let user = user.ok_or(UserError::InvalidVerificationToken)?;

        // Update user to mark email as verified
        let update_filter = doc! { "user_id": &user.user_id };
        let set_fields = doc! { "email_verified": true };
        let unset_fields = doc! {
            "email_verification_token": "",
            "email_verification_expires": ""
        };
        let update = Self::create_update_doc_with_unset(set_fields, unset_fields);

        self.users
            .update_one(update_filter, update)
            .await
            .map_err(|e| UserError::Database(format!("Failed to verify email: {e}")))?;

        Ok(user.user_id)
    }

    async fn set_password_reset_token(
        &self,
        email: &str,
        token: &str,
        expires_hours: u64,
    ) -> Result<(), UserError> {
        let expires_at = Utc::now() + chrono::Duration::hours(expires_hours as i64);
        let filter = doc! { "email": email.to_lowercase() };
        let update = Self::create_update_doc(doc! {
            "password_reset_token": token,
            "password_reset_expires": mongodb::bson::DateTime::from_system_time(expires_at.into())
        });

        self.update_user_by_filter(filter, update, "set password reset token")
            .await
    }

    async fn verify_password_reset_token(&self, token: &str) -> Result<String, UserError> {
        let filter = doc! {
            "password_reset_token": token,
            "password_reset_expires": { "$gt": mongodb::bson::DateTime::from_system_time(Utc::now().into()) }
        };

        let user = self
            .users
            .find_one(filter)
            .await
            .map_err(|e| UserError::Database(format!("Failed to find reset token: {e}")))?;

        let user = user.ok_or(UserError::InvalidPasswordResetToken)?;
        Ok(user.user_id)
    }

    async fn clear_password_reset_token(&self, user_id: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let unset_fields = doc! {
            "password_reset_token": "",
            "password_reset_expires": ""
        };
        let update = Self::create_update_doc_with_unset(doc! {}, unset_fields);

        self.update_user_by_filter(filter, update, "clear reset token")
            .await
    }

    async fn record_login(&self, user_id: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let set_fields = doc! {
            "last_login": mongodb::bson::DateTime::from_system_time(Utc::now().into()),
            "login_attempts": 0
        };
        let unset_fields = doc! { "locked_until": "" };
        let update = Self::create_update_doc_with_unset(set_fields, unset_fields);

        self.update_user_by_filter(filter, update, "record login")
            .await
    }

    async fn record_failed_login(
        &self,
        email: &str,
        max_attempts: u32,
        lockout_hours: u64,
    ) -> Result<(), UserError> {
        let filter = doc! { "email": email.to_lowercase() };

        // First, increment login attempts
        let update = doc! {
            "$inc": { "login_attempts": 1 },
            "$set": { "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into()) }
        };

        self.users
            .update_one(filter.clone(), update)
            .await
            .map_err(|e| UserError::Database(format!("Failed to increment login attempts: {e}")))?;

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

                self.users
                    .update_one(filter, lock_update)
                    .await
                    .map_err(|e| UserError::Database(format!("Failed to lock account: {e}")))?;
            }
        }

        Ok(())
    }

    async fn user_exists_by_email(&self, email: &str) -> Result<bool, UserError> {
        let filter = doc! { "email": email.to_lowercase() };

        match self.users.count_documents(filter).await {
            Ok(count) => Ok(count > 0),
            Err(e) => Err(UserError::Database(format!(
                "Failed to check user existence: {e}"
            ))),
        }
    }

    async fn deactivate_user(&self, user_id: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = Self::create_update_doc(doc! {
            "is_active": false
        });

        self.update_user_by_filter(filter, update, "deactivate user")
            .await
    }

    async fn health_check(&self) -> Result<DatabaseHealth> {
        let start = Instant::now();

        let result = self.database.run_command(doc! { "ping": 1 }).await;

        let response_time_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(_) => Ok(DatabaseHealth {
                status: "healthy".to_string(),
                database_type: "mongodb".to_string(),
                connected: true,
                response_time_ms,
                details: Some(format!("Connected to database: {DATABASE_NAME}")),
            }),
            Err(e) => Ok(DatabaseHealth {
                status: "unhealthy".to_string(),
                database_type: "mongodb".to_string(),
                connected: false,
                response_time_ms,
                details: Some(format!("Connection error: {e}")),
            }),
        }
    }

    async fn get_user_by_verification_token(&self, token: &str) -> Result<Option<User>, UserError> {
        let filter = doc! { "email_verification_token": token };

        match self.users.find_one(filter).await {
            Ok(user) => Ok(user),
            Err(e) => Err(UserError::Database(format!(
                "Failed to find user by verification token: {e}"
            ))),
        }
    }

    async fn get_user_by_reset_token(&self, token: &str) -> Result<Option<User>, UserError> {
        let filter = doc! { "password_reset_token": token };

        match self.users.find_one(filter).await {
            Ok(user) => Ok(user),
            Err(e) => Err(UserError::Database(format!(
                "Failed to find user by reset token: {e}"
            ))),
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

        match self.users.update_one(filter, update).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!("Failed to verify email: {e}"))),
        }
    }

    async fn update_login_attempts(
        &self,
        user_id: &str,
        attempts: u32,
        locked_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let mut update_doc = doc! {
            "login_attempts": attempts as i32,
            "updated_at": mongodb::bson::DateTime::from_system_time(Utc::now().into())
        };

        if let Some(locked_time) = locked_until {
            update_doc.insert(
                "locked_until",
                mongodb::bson::DateTime::from_system_time(locked_time.into()),
            );
        } else {
            update_doc.insert("locked_until", Bson::Null);
        }

        let update = doc! { "$set": update_doc };

        match self.users.update_one(filter, update).await {
            Ok(result) => {
                if result.matched_count == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(UserError::Database(format!(
                "Failed to update login attempts: {e}"
            ))),
        }
    }

    async fn update_last_login(&self, user_id: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = Self::create_update_doc(doc! {
            "last_login": mongodb::bson::DateTime::from_system_time(Utc::now().into())
        });

        self.update_user_by_filter(filter, update, "update last login")
            .await
    }

    async fn record_login_attempt(&self, attempt: &LoginAttempt) -> Result<(), UserError> {
        let login_attempt_doc = doc! {
            "user_id": &attempt.user_id,
            "ip_address": &attempt.ip_address,
            "user_agent": &attempt.user_agent,
            "success": attempt.success,
            "attempted_at": mongodb::bson::DateTime::from_system_time(attempt.attempted_at.into())
        };

        match self
            .database
            .collection::<Document>("login_attempts")
            .insert_one(login_attempt_doc)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(UserError::Database(format!(
                "Failed to record login attempt: {e}"
            ))),
        }
    }

    async fn initialize(&self) -> Result<()> {
        self.create_indexes()
            .await
            .context("Failed to initialize database indexes")?;
        Ok(())
    }

    // Admin dashboard methods
    async fn count_users(&self) -> Result<u64, UserError> {
        match self.users.count_documents(doc! {}).await {
            Ok(count) => Ok(count),
            Err(e) => Err(UserError::Database(format!("Failed to count users: {e}"))),
        }
    }

    async fn count_verified_users(&self) -> Result<u64, UserError> {
        let filter = doc! { "email_verified": true };
        match self.users.count_documents(filter).await {
            Ok(count) => Ok(count),
            Err(e) => Err(UserError::Database(format!(
                "Failed to count verified users: {e}"
            ))),
        }
    }

    async fn count_active_users(&self) -> Result<u64, UserError> {
        // Consider users active if they logged in within the last 30 days
        let thirty_days_ago = Utc::now() - chrono::Duration::days(30);
        let filter = doc! {
            "last_login": { "$gte": mongodb::bson::DateTime::from_system_time(thirty_days_ago.into()) },
            "is_active": true
        };
        match self.users.count_documents(filter).await {
            Ok(count) => Ok(count),
            Err(e) => Err(UserError::Database(format!(
                "Failed to count active users: {e}"
            ))),
        }
    }

    async fn count_admin_users(&self) -> Result<u64, UserError> {
        let filter = doc! { "role": "admin" };
        match self.users.count_documents(filter).await {
            Ok(count) => Ok(count),
            Err(e) => Err(UserError::Database(format!(
                "Failed to count admin users: {e}"
            ))),
        }
    }

    async fn list_users(&self, page: u32, limit: u32) -> Result<Vec<User>, UserError> {
        let skip = ((page - 1) * limit) as u64;
        let find_options = mongodb::options::FindOptions::builder()
            .skip(skip)
            .limit(limit as i64)
            .sort(doc! { "created_at": -1 })
            .build();

        match self.users.find(doc! {}).with_options(find_options).await {
            Ok(cursor) => match cursor.try_collect().await {
                Ok(users) => Ok(users),
                Err(e) => Err(UserError::Database(format!("Failed to collect users: {e}"))),
            },
            Err(e) => Err(UserError::Database(format!("Failed to list users: {e}"))),
        }
    }

    async fn search_users(
        &self,
        query: &str,
        page: u32,
        limit: u32,
    ) -> Result<Vec<User>, UserError> {
        let skip = ((page - 1) * limit) as u64;
        let find_options = mongodb::options::FindOptions::builder()
            .skip(skip)
            .limit(limit as i64)
            .sort(doc! { "created_at": -1 })
            .build();

        // Search in email, first_name, and last_name fields
        let filter = doc! {
            "$or": [
                { "email": { "$regex": query, "$options": "i" } },
                { "first_name": { "$regex": query, "$options": "i" } },
                { "last_name": { "$regex": query, "$options": "i" } }
            ]
        };

        match self.users.find(filter).with_options(find_options).await {
            Ok(cursor) => match cursor.try_collect().await {
                Ok(users) => Ok(users),
                Err(e) => Err(UserError::Database(format!(
                    "Failed to collect search results: {e}"
                ))),
            },
            Err(e) => Err(UserError::Database(format!("Failed to search users: {e}"))),
        }
    }

    async fn get_user_for_admin(&self, user_id: &str) -> Result<Option<User>, UserError> {
        self.find_user_by_id(user_id).await
    }

    async fn update_user_role(&self, user_id: &str, role: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = Self::create_update_doc(doc! {
            "role": role
        });

        self.update_user_by_filter(filter, update, "update user role")
            .await
    }

    async fn set_user_lock_status(&self, user_id: &str, locked: bool) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = if locked {
            let lock_until = Utc::now() + chrono::Duration::hours(24);
            Self::create_update_doc(doc! {
                "is_locked": true,
                "locked_until": mongodb::bson::DateTime::from_system_time(lock_until.into())
            })
        } else {
            Self::create_update_doc(doc! {
                "is_locked": false,
                "locked_until": Bson::Null
            })
        };

        self.update_user_by_filter(filter, update, "update user lock status")
            .await
    }

    async fn admin_verify_email(&self, user_id: &str) -> Result<(), UserError> {
        let filter = doc! { "user_id": user_id };
        let update = Self::create_update_doc(doc! {
            "email_verified": true,
            "email_verification_token": Bson::Null,
            "email_verification_expires": Bson::Null
        });

        self.update_user_by_filter(filter, update, "admin verify email")
            .await
    }
}

/// Create a MongoDB database connection for migrations
#[allow(dead_code)]
pub async fn create_database(
    config: &crate::config::database::DatabaseConfig,
) -> Result<mongodb::Database> {
    use mongodb::{options::ClientOptions, Client};

    let client_options = ClientOptions::parse(&config.url)
        .await
        .context("Failed to parse MongoDB connection string")?;

    let client = Client::with_options(client_options).context("Failed to create MongoDB client")?;

    Ok(client.database(DATABASE_NAME))
}

// Temporarily disabled OAuth2Service implementation until OAuth2 module is re-enabled
/*
#[async_trait]
impl OAuth2Service for MongoDatabase {
    // Client management
    async fn create_client(&self, client: OAuth2Client) -> Result<OAuth2Client> {
        self.oauth2_clients
            .insert_one(&client)
            .await
            .context("Failed to create OAuth2 client")?;
        Ok(client)
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<OAuth2Client>> {
        let filter = doc! { "client_id": client_id };
        self.oauth2_clients
            .find_one(filter)
            .await
            .context("Failed to get OAuth2 client")
    }

    async fn update_client(&self, client: OAuth2Client) -> Result<OAuth2Client> {
        let filter = doc! { "client_id": &client.client_id };
        self.oauth2_clients
            .replace_one(filter, &client)
            .await
            .context("Failed to update OAuth2 client")?;
        Ok(client)
    }

    async fn delete_client(&self, client_id: &str) -> Result<bool> {
        let filter = doc! { "client_id": client_id };
        let result = self
            .oauth2_clients
            .delete_one(filter)
            .await
            .context("Failed to delete OAuth2 client")?;
        Ok(result.deleted_count > 0)
    }

    async fn list_clients(
        &self,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> Result<Vec<OAuth2Client>> {
        let mut cursor = self
            .oauth2_clients
            .find(doc! {})
            .await
            .context("Failed to list OAuth2 clients")?;

        let mut clients = Vec::new();
        let skip = offset.unwrap_or(0);
        let limit = limit.unwrap_or(100);

        let mut count = 0;
        while cursor.advance().await.context("Failed to advance cursor")? {
            if count < skip {
                count += 1;
                continue;
            }
            if clients.len() >= limit as usize {
                break;
            }

            let client = cursor
                .deserialize_current()
                .context("Failed to deserialize OAuth2 client")?;
            clients.push(client);
        }

        Ok(clients)
    }

    // Authorization codes
    async fn create_auth_code(&self, code: AuthorizationCode) -> Result<AuthorizationCode> {
        self.oauth2_auth_codes
            .insert_one(&code)
            .await
            .context("Failed to create authorization code")?;
        Ok(code)
    }

    async fn get_auth_code(&self, code: &str) -> Result<Option<AuthorizationCode>> {
        let filter = doc! { "code": code };
        self.oauth2_auth_codes
            .find_one(filter)
            .await
            .context("Failed to get authorization code")
    }

    async fn use_auth_code(&self, code: &str) -> Result<bool> {
        let filter = doc! { "code": code };
        let update = doc! { "$set": { "used": true } };
        let result = self
            .oauth2_auth_codes
            .update_one(filter, update)
            .await
            .context("Failed to mark authorization code as used")?;
        Ok(result.modified_count > 0)
    }

    async fn cleanup_expired_codes(&self) -> Result<u64> {
        let filter = doc! { "expires_at": { "$lt": mongodb::bson::DateTime::now() } };
        let result = self
            .oauth2_auth_codes
            .delete_many(filter)
            .await
            .context("Failed to cleanup expired authorization codes")?;
        Ok(result.deleted_count)
    }

    // Access tokens
    async fn create_access_token(&self, token: AccessToken) -> Result<AccessToken> {
        self.oauth2_access_tokens
            .insert_one(&token)
            .await
            .context("Failed to create access token")?;
        Ok(token)
    }

    async fn get_access_token(&self, token: &str) -> Result<Option<AccessToken>> {
        let filter = doc! { "token": token };
        self.oauth2_access_tokens
            .find_one(filter)
            .await
            .context("Failed to get access token")
    }

    async fn revoke_access_token(&self, token: &str) -> Result<bool> {
        let filter = doc! { "token": token };
        let update = doc! { "$set": { "revoked": true } };
        let result = self
            .oauth2_access_tokens
            .update_one(filter, update)
            .await
            .context("Failed to revoke access token")?;
        Ok(result.modified_count > 0)
    }

    async fn cleanup_expired_tokens(&self) -> Result<u64> {
        let filter = doc! { "expires_at": { "$lt": mongodb::bson::DateTime::now() } };
        let result = self
            .oauth2_access_tokens
            .delete_many(filter)
            .await
            .context("Failed to cleanup expired access tokens")?;
        Ok(result.deleted_count)
    }

    // Refresh tokens
    async fn create_refresh_token(&self, token: RefreshToken) -> Result<RefreshToken> {
        self.oauth2_refresh_tokens
            .insert_one(&token)
            .await
            .context("Failed to create refresh token")?;
        Ok(token)
    }

    async fn get_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>> {
        let filter = doc! { "token": token };
        self.oauth2_refresh_tokens
            .find_one(filter)
            .await
            .context("Failed to get refresh token")
    }

    async fn use_refresh_token(&self, token: &str) -> Result<bool> {
        let filter = doc! { "token": token };
        let update = doc! { "$set": { "used": true } };
        let result = self
            .oauth2_refresh_tokens
            .update_one(filter, update)
            .await
            .context("Failed to mark refresh token as used")?;
        Ok(result.modified_count > 0)
    }

    async fn revoke_refresh_token(&self, token: &str) -> Result<bool> {
        let filter = doc! { "token": token };
        let result = self
            .oauth2_refresh_tokens
            .delete_one(filter)
            .await
            .context("Failed to revoke refresh token")?;
        Ok(result.deleted_count > 0)
    }

    // Device authorization
    async fn create_device_authorization(
        &self,
        auth: DeviceAuthorization,
    ) -> Result<DeviceAuthorization> {
        self.oauth2_device_authorizations
            .insert_one(&auth)
            .await
            .context("Failed to create device authorization")?;
        Ok(auth)
    }

    async fn get_device_authorization_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorization>> {
        let filter = doc! { "device_code": device_code };
        self.oauth2_device_authorizations
            .find_one(filter)
            .await
            .context("Failed to get device authorization")
    }

    async fn get_device_authorization_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceAuthorization>> {
        let filter = doc! { "user_code": user_code };
        self.oauth2_device_authorizations
            .find_one(filter)
            .await
            .context("Failed to get device authorization")
    }

    async fn authorize_device(&self, user_code: &str, user_id: &str) -> Result<bool> {
        let filter = doc! { "user_code": user_code };
        let update = doc! {
            "$set": {
                "authorized": true,
                "user_id": user_id
            }
        };
        let result = self
            .oauth2_device_authorizations
            .update_one(filter, update)
            .await
            .context("Failed to authorize device")?;
        Ok(result.modified_count > 0)
    }

    async fn cleanup_expired_device_authorizations(&self) -> Result<u64> {
        let filter = doc! { "expires_at": { "$lt": mongodb::bson::DateTime::now() } };
        let result = self
            .oauth2_device_authorizations
            .delete_many(filter)
            .await
            .context("Failed to cleanup expired device authorizations")?;
        Ok(result.deleted_count)
    }

    // Token introspection
    async fn introspect_token(&self, token: &str) -> Result<TokenIntrospection> {
        let filter = doc! { "token": token };
        if let Some(access_token) = self
            .oauth2_access_tokens
            .find_one(filter)
            .await
            .context("Failed to introspect token")?
        {
            Ok(TokenIntrospection {
                active: !access_token.revoked && access_token.expires_at > Utc::now(),
                scope: Some(access_token.scopes.join(" ")),
                client_id: Some(access_token.client_id),
                username: access_token.user_id.clone(),
                token_type: Some(access_token.token_type),
                exp: Some(access_token.expires_at.timestamp()),
                iat: Some(access_token.created_at.timestamp()),
                nbf: None,
                sub: access_token.user_id,
                aud: None,
                iss: None,
                jti: None,
            })
        } else {
            Ok(TokenIntrospection {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                exp: None,
                iat: None,
                nbf: None,
                sub: None,
                aud: None,
                iss: None,
                jti: None,
            })
        }
    }

    // Utility methods
    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<u64> {
        let filter = doc! { "user_id": user_id };
        let update = doc! { "$set": { "revoked": true } };
        let result = self
            .oauth2_access_tokens
            .update_many(filter, update)
            .await
            .context("Failed to revoke all user tokens")?;
        Ok(result.modified_count)
    }

    async fn revoke_all_client_tokens(&self, client_id: &str) -> Result<u64> {
        let filter = doc! { "client_id": client_id };
        let update = doc! { "$set": { "revoked": true } };
        let result = self
            .oauth2_access_tokens
            .update_many(filter, update)
            .await
            .context("Failed to revoke all client tokens")?;
        Ok(result.modified_count)
    }

    async fn get_user_tokens(&self, user_id: &str) -> Result<Vec<AccessToken>> {
        let filter = doc! { "user_id": user_id, "revoked": false };
        let mut cursor = self
            .oauth2_access_tokens
            .find(filter)
            .await
            .context("Failed to get user tokens")?;

        let mut tokens = Vec::new();
        while cursor.advance().await.context("Failed to advance cursor")? {
            let token = cursor
                .deserialize_current()
                .context("Failed to deserialize access token")?;
            tokens.push(token);
        }

        Ok(tokens)
    }

    async fn get_client_tokens(&self, client_id: &str) -> Result<Vec<AccessToken>> {
        let filter = doc! { "client_id": client_id, "revoked": false };
        let mut cursor = self
            .oauth2_access_tokens
            .find(filter)
            .await
            .context("Failed to get client tokens")?;

        let mut tokens = Vec::new();
        while cursor.advance().await.context("Failed to advance cursor")? {
            let token = cursor
                .deserialize_current()
                .context("Failed to deserialize access token")?;
            tokens.push(token);
        }

        Ok(tokens)
    }
}
*/

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
        let mut user_to_update = db.find_user_by_id(&user_id).await.unwrap().unwrap();
        user_to_update.first_name = "Updated".to_string();
        let updated_user = db.update_user(&user_to_update).await.unwrap();
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
        db.set_email_verification_token(&user_id, token, 24)
            .await
            .unwrap();

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
