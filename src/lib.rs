// Library exports for rust-auth-service
pub mod config;
pub mod database;
pub mod migrations;
pub mod models;
pub mod errors;
pub mod utils;

// Re-export commonly used types
pub use config::Config;
pub use database::AuthDatabase;
pub use migrations::{MigrationProvider, Migration, MigrationRecord};
pub use migrations::runner::MigrationRunner;