use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use tracing::{info, debug, error};

use rust_auth_service::{
    config::{Config, DatabaseConfig, PoolConfig},
    database::{AuthDatabase, create_database},
    models::user::{User, UserError, LoginAttempt},
};

/// Test database wrapper with cleanup capabilities
pub struct TestDatabase {
    pub instance: Arc<dyn AuthDatabase>,
    pub database_type: String,
    pub test_id: String,
    pub cleanup_data: Vec<String>, // Track created user IDs for cleanup
}

impl TestDatabase {
    pub async fn new(database_type: &str, test_id: &str) -> Result<Self> {
        let config = create_test_database_config(database_type, test_id).await?;
        let instance = create_database(&config).await?;
        
        Ok(Self {
            instance,
            database_type: database_type.to_string(),
            test_id: test_id.to_string(),
            cleanup_data: Vec::new(),
        })
    }

    /// Track user for cleanup
    pub fn track_user(&mut self, user_id: &str) {
        self.cleanup_data.push(user_id.to_string());
    }

    /// Clean up test data
    pub async fn cleanup(&self) -> Result<()> {
        debug!("Cleaning up test database: {}", self.test_id);
        
        for user_id in &self.cleanup_data {
            if let Err(e) = self.instance.deactivate_user(user_id).await {
                error!("Failed to cleanup user {}: {}", user_id, e);
            }
        }
        
        info!("Test database cleanup completed: {}", self.test_id);
        Ok(())
    }
}

/// Manages multiple test database instances
pub struct TestDatabaseManager {
    databases: Arc<Mutex<HashMap<String, Arc<TestDatabase>>>>,
}

impl TestDatabaseManager {
    pub async fn new() -> Result<Self> {
        info!("Initializing test database manager");
        
        Ok(Self {
            databases: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Create isolated test database
    pub async fn create_test_database(&self, database_type: &str) -> Result<Arc<TestDatabase>> {
        let test_id = format!("test_{}_{}", database_type, Uuid::new_v4());
        debug!("Creating test database: {}", test_id);
        
        let test_db = Arc::new(TestDatabase::new(database_type, &test_id).await?);
        
        {
            let mut databases = self.databases.lock().await;
            databases.insert(test_id.clone(), test_db.clone());
        }
        
        info!("Test database created: {}", test_id);
        Ok(test_db)
    }

    /// Cleanup all test databases
    pub async fn cleanup_all(&self) -> Result<()> {
        info!("Cleaning up all test databases");
        
        let databases = {
            let mut dbs = self.databases.lock().await;
            let current = dbs.clone();
            dbs.clear();
            current
        };

        for (test_id, test_db) in databases {
            if let Err(e) = test_db.cleanup().await {
                error!("Failed to cleanup test database {}: {}", test_id, e);
            }
        }
        
        info!("All test databases cleaned up");
        Ok(())
    }
}

/// Create test database configuration
async fn create_test_database_config(database_type: &str, test_id: &str) -> Result<DatabaseConfig> {
    let base_config = Config::from_env_and_file()?;
    
    let mut config = base_config.database.clone();
    config.r#type = database_type.to_string();
    
    // Modify database name/collection for isolation
    match database_type {
        "mongodb" => {
            // Append test ID to database name
            if let Some(pos) = config.url.rfind('/') {
                let (base, db_name) = config.url.split_at(pos + 1);
                config.url = format!("{}{}_test_{}", base, db_name, test_id);
            }
        }
        "postgresql" => {
            // Append test ID to database name
            if let Some(pos) = config.url.rfind('/') {
                let (base, db_name) = config.url.split_at(pos + 1);
                config.url = format!("{}{}_test_{}", base, db_name, test_id);
            }
        }
        _ => return Err(anyhow::anyhow!("Unsupported test database type: {}", database_type)),
    }
    
    // Use smaller connection pools for tests
    config.pool = PoolConfig {
        max_connections: 5,
        min_connections: 1,
        acquire_timeout_seconds: 10,
        idle_timeout_seconds: 300,
        max_lifetime_seconds: 1800,
    };
    
    debug!("Test database config created for {}: {}", database_type, config.url);
    Ok(config)
}

/// Database operation test helpers
pub struct DatabaseTestHelpers;

impl DatabaseTestHelpers {
    /// Create test user with random data
    pub fn create_test_user(suffix: &str) -> User {
        User {
            id: None,
            email: format!("test_{}@example.com", suffix),
            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmyMcLOVAzk8VqK".to_string(), // "password123"
            full_name: format!("Test User {}", suffix),
            role: "user".to_string(),
            is_active: true,
            email_verified: false,
            email_verification_token: None,
            email_verification_expires: None,
            password_reset_token: None,
            password_reset_expires: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// Create test login attempt
    pub fn create_test_login_attempt(email: &str, success: bool) -> LoginAttempt {
        LoginAttempt {
            id: None,
            email: email.to_string(),
            ip_address: "192.168.1.100".to_string(),
            user_agent: Some("Test User Agent".to_string()),
            success,
            failure_reason: if success { None } else { Some("Invalid password".to_string()) },
            timestamp: chrono::Utc::now(),
        }
    }

    /// Verify user creation across databases
    pub async fn verify_user_creation(
        database: &Arc<dyn AuthDatabase>,
        user: &User,
    ) -> Result<User> {
        // Create user
        let created_user = database.create_user(user.clone()).await
            .map_err(|e| anyhow::anyhow!("Failed to create user: {:?}", e))?;
        
        // Verify user has ID
        assert!(created_user.id.is_some(), "Created user should have an ID");
        
        // Verify user can be found by email
        let found_user = database.find_user_by_email(&user.email).await
            .map_err(|e| anyhow::anyhow!("Failed to find user by email: {:?}", e))?;
        assert!(found_user.is_some(), "User should be found by email");
        
        let found_user = found_user.unwrap();
        assert_eq!(found_user.email, user.email);
        assert_eq!(found_user.full_name, user.full_name);
        
        // Verify user can be found by ID
        if let Some(user_id) = &created_user.id {
            let found_by_id = database.find_user_by_id(user_id).await
                .map_err(|e| anyhow::anyhow!("Failed to find user by ID: {:?}", e))?;
            assert!(found_by_id.is_some(), "User should be found by ID");
            
            let found_by_id = found_by_id.unwrap();
            assert_eq!(found_by_id.email, user.email);
        }
        
        info!("User creation verification passed for: {}", user.email);
        Ok(created_user)
    }

    /// Verify authentication flow
    pub async fn verify_authentication_flow(
        database: &Arc<dyn AuthDatabase>,
        user: &User,
    ) -> Result<()> {
        // Test successful login recording
        if let Some(user_id) = &user.id {
            database.record_login(user_id).await
                .map_err(|e| anyhow::anyhow!("Failed to record login: {:?}", e))?;
            
            // Update last login
            database.update_last_login(user_id).await
                .map_err(|e| anyhow::anyhow!("Failed to update last login: {:?}", e))?;
        }
        
        // Test failed login recording
        database.record_failed_login(&user.email, 3, 24).await
            .map_err(|e| anyhow::anyhow!("Failed to record failed login: {:?}", e))?;
        
        info!("Authentication flow verification passed for: {}", user.email);
        Ok(())
    }

    /// Verify email verification flow
    pub async fn verify_email_verification_flow(
        database: &Arc<dyn AuthDatabase>,
        user: &User,
    ) -> Result<()> {
        if let Some(user_id) = &user.id {
            let token = "test_verification_token_123";
            
            // Set verification token
            database.set_email_verification_token(user_id, token, 24).await
                .map_err(|e| anyhow::anyhow!("Failed to set verification token: {:?}", e))?;
            
            // Verify with token
            let verified_user_id = database.verify_email(token).await
                .map_err(|e| anyhow::anyhow!("Failed to verify email: {:?}", e))?;
            
            assert_eq!(verified_user_id, *user_id);
            
            // Verify user email is marked as verified
            database.verify_user_email(user_id).await
                .map_err(|e| anyhow::anyhow!("Failed to mark email as verified: {:?}", e))?;
        }
        
        info!("Email verification flow passed for: {}", user.email);
        Ok(())
    }

    /// Verify password reset flow
    pub async fn verify_password_reset_flow(
        database: &Arc<dyn AuthDatabase>,
        user: &User,
    ) -> Result<()> {
        let token = "test_reset_token_456";
        
        // Set password reset token
        database.set_password_reset_token(&user.email, token, 24).await
            .map_err(|e| anyhow::anyhow!("Failed to set reset token: {:?}", e))?;
        
        // Verify reset token
        let user_id = database.verify_password_reset_token(token).await
            .map_err(|e| anyhow::anyhow!("Failed to verify reset token: {:?}", e))?;
        
        // Update password
        let new_password_hash = "$2b$12$NEW_HASH_FOR_TESTING";
        database.update_password(&user_id, new_password_hash).await
            .map_err(|e| anyhow::anyhow!("Failed to update password: {:?}", e))?;
        
        // Clear reset token
        database.clear_password_reset_token(&user_id).await
            .map_err(|e| anyhow::anyhow!("Failed to clear reset token: {:?}", e))?;
        
        info!("Password reset flow passed for: {}", user.email);
        Ok(())
    }
}