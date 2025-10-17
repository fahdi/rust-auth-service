// Library exports for rust-auth-service
pub mod cache;
pub mod config;
pub mod database;
pub mod email;
pub mod errors;
pub mod handlers;
pub mod mfa;
pub mod migrations;
pub mod models;
// Temporarily disabled modules until fully integrated
// pub mod oauth2;
// pub mod session;
// pub mod social;
// pub mod user_management;
pub mod utils;

use std::sync::Arc;

// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::Config>,
    pub database: Arc<dyn database::AuthDatabase>,
    pub cache: Arc<cache::CacheService>,
    pub email: Arc<email::EmailService>,
    // pub oauth2_server: Arc<oauth2::server::OAuth2Server>,
    // pub token_manager: Arc<oauth2::tokens::TokenManager>,
}

// Re-export commonly used types
pub use cache::{create_cache_provider, CacheProvider, CacheService};
pub use config::Config;
pub use database::AuthDatabase;
pub use migrations::runner::MigrationRunner;
pub use migrations::{Migration, MigrationProvider, MigrationRecord};
// pub use oauth2::{server::OAuth2Server, OAuth2Service};
// pub use session::{DeviceInfo, SecurityLevel, Session, SessionConfig, SessionService};
// pub use user_management::{Permission, UserGroup, UserManagementService, UserProfile, UserRole};
