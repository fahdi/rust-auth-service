use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;

pub mod auth;
pub mod cache;
pub mod database;
pub mod email;
pub mod server;

use auth::AuthConfig;
use cache::CacheConfig;
use database::DatabaseConfig;
use email::EmailConfig;
use server::ServerConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub cache: CacheConfig,
    pub email: EmailConfig,
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub metrics: bool,
    pub prometheus_port: u16,
    pub health_check_interval: u64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics: true,
            prometheus_port: 9090,
            health_check_interval: 30,
        }
    }
}

impl Config {
    pub fn from_env_and_file() -> Result<Self> {
        // Load from config.yml if it exists
        let mut config = if std::path::Path::new("config.yml").exists() {
            let config_str = std::fs::read_to_string("config.yml")
                .context("Failed to read config.yml")?;
            serde_yaml::from_str::<Config>(&config_str)
                .context("Failed to parse config.yml")?
        } else {
            // Use default configuration
            Config::default()
        };

        // Override with environment variables
        if let Ok(host) = env::var("SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = env::var("SERVER_PORT") {
            config.server.port = port.parse().context("Invalid SERVER_PORT")?;
        }
        if let Ok(workers) = env::var("SERVER_WORKERS") {
            config.server.workers = workers.parse().context("Invalid SERVER_WORKERS")?;
        }

        if let Ok(db_type) = env::var("DATABASE_TYPE") {
            config.database.r#type = db_type;
        }
        if let Ok(db_url) = env::var("DATABASE_URL") {
            config.database.url = db_url;
        }

        if let Ok(jwt_secret) = env::var("JWT_SECRET") {
            config.auth.jwt.secret = jwt_secret;
        }
        if let Ok(bcrypt_rounds) = env::var("BCRYPT_ROUNDS") {
            config.auth.password.bcrypt_rounds = bcrypt_rounds.parse().context("Invalid BCRYPT_ROUNDS")?;
        }

        if let Ok(cache_type) = env::var("CACHE_TYPE") {
            config.cache.r#type = cache_type;
        }
        if let Ok(cache_url) = env::var("CACHE_URL") {
            config.cache.url = Some(cache_url);
        }

        if let Ok(email_provider) = env::var("EMAIL_PROVIDER") {
            config.email.provider = email_provider;
        }
        if let Ok(brevo_key) = env::var("BREVO_API_KEY") {
            config.email.brevo.as_mut().unwrap().api_key = brevo_key;
        }

        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            email: EmailConfig::default(),
            monitoring: MonitoringConfig::default(),
        }
    }
}
