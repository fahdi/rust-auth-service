#![allow(unused_imports, dead_code, unused_variables, clippy::all)]

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::OnceCell;
use tracing::info;

pub mod cache;
pub mod database;
pub mod fixtures;
pub mod utils;

use crate::common::database::{TestDatabase, TestDatabaseManager};

static TEST_MANAGER: OnceCell<TestDatabaseManager> = OnceCell::const_new();

/// Initialize test environment
pub async fn init_test_environment() -> Result<()> {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("Test environment initialized");
    Ok(())
}

/// Get or create test database manager
pub async fn get_test_manager() -> &'static TestDatabaseManager {
    TEST_MANAGER
        .get_or_init(|| async {
            TestDatabaseManager::new()
                .await
                .expect("Failed to create test manager")
        })
        .await
}

/// Create isolated test database instance
pub async fn create_test_database(database_type: &str) -> Result<Arc<TestDatabase>> {
    let manager = get_test_manager().await;
    manager.create_test_database(database_type).await
}

/// Cleanup test databases
pub async fn cleanup_test_databases() -> Result<()> {
    if let Some(manager) = TEST_MANAGER.get() {
        manager.cleanup_all().await?;
    }
    Ok(())
}

/// Test result assertion helpers
pub mod assertions {
    use rust_auth_service::models::user::{User, UserError};

    pub fn assert_user_equals(actual: &User, expected: &User) {
        assert_eq!(actual.email, expected.email);
        assert_eq!(actual.full_name, expected.full_name);
        assert_eq!(actual.role, expected.role);
        assert_eq!(actual.is_active, expected.is_active);
        assert_eq!(actual.email_verified, expected.email_verified);
    }

    pub fn assert_user_error_type(error: &UserError, expected_type: &str) {
        match (error, expected_type) {
            (UserError::NotFound, "not_found") => {}
            (UserError::AlreadyExists, "already_exists") => {}
            (UserError::InvalidCredentials, "invalid_credentials") => {}
            (UserError::Locked, "locked") => {}
            (UserError::DatabaseError(_), "database_error") => {}
            _ => panic!(
                "Unexpected error type: {:?}, expected: {}",
                error, expected_type
            ),
        }
    }
}
