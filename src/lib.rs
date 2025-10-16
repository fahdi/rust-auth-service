// Library exports for rust-auth-service
pub mod cache;
pub mod config;
pub mod database;
pub mod errors;
pub mod mfa;
pub mod migrations;
pub mod models;
pub mod oauth2;
pub mod session;
pub mod social;
pub mod user_management;
pub mod utils;

// Re-export commonly used types
pub use cache::{create_cache_provider, CacheProvider, CacheService};
pub use config::Config;
pub use database::AuthDatabase;
pub use migrations::runner::MigrationRunner;
pub use migrations::{Migration, MigrationProvider, MigrationRecord};
pub use oauth2::{OAuth2Service, server::OAuth2Server};
pub use session::{SessionService, Session, SessionConfig, DeviceInfo, SecurityLevel};
pub use user_management::{UserManagementService, UserRole, Permission, UserGroup, UserProfile};
