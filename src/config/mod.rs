use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;

pub mod auth;
pub mod cache;
pub mod database;
pub mod email;
pub mod rate_limit;
pub mod server;
pub mod validator;

use auth::AuthConfig;
use cache::CacheConfig;
use database::DatabaseConfig;
use email::EmailConfig;
use rate_limit::RateLimitConfig;
use server::ServerConfig;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub cache: CacheConfig,
    pub email: EmailConfig,
    pub rate_limit: RateLimitConfig,
    pub monitoring: MonitoringConfig,
    pub environment: EnvironmentConfig,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub metrics: bool,
    pub prometheus_port: u16,
    pub health_check_interval: u64,
    pub prometheus: PrometheusConfig,
    pub tracing: TracingConfig,
    pub health_checks: HealthChecksConfig,
    pub audit_logging: AuditLoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthChecksConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLoggingConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub level: String,
    pub jaeger_endpoint: String,
    pub sample_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    pub cors: CorsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            name: "development".to_string(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics: true,
            prometheus_port: 9090,
            health_check_interval: 30,
            prometheus: PrometheusConfig::default(),
            tracing: TracingConfig::default(),
            health_checks: HealthChecksConfig::default(),
            audit_logging: AuditLoggingConfig::default(),
        }
    }
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            jaeger_endpoint: "http://localhost:14268/api/traces".to_string(),
            sample_rate: 0.1,
        }
    }
}

impl Default for HealthChecksConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for AuditLoggingConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["http://localhost:3000".to_string()],
        }
    }
}

impl Config {
    /// Load configuration from environment-specific file and environment variables
    pub fn load() -> Result<Self> {
        // Determine environment
        let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

        // Load from environment-specific config file
        let config_file = format!("config/{}.yml", environment);
        let mut config = if std::path::Path::new(&config_file).exists() {
            let config_str = std::fs::read_to_string(&config_file)
                .with_context(|| format!("Failed to read {config_file}"))?;
            serde_yaml::from_str::<Config>(&config_str)
                .with_context(|| format!("Failed to parse {config_file}"))?
        } else {
            // Fallback to config.yml or default
            Self::from_env_and_file()?
        };

        // Override with environment variables
        Self::apply_env_overrides(&mut config)?;

        // Validate configuration
        validator::ConfigValidator::validate_basic(&config)
            .context("Configuration validation failed")?;

        // Validate environment variables
        validator::ConfigValidator::validate_environment_variables()
            .context("Environment variable validation failed")?;

        // Additional validation for production
        if environment == "production" {
            validator::ConfigValidator::validate_production(&config)
                .context("Production configuration validation failed")?;
        }

        // Validate email configuration
        validator::ConfigValidator::validate_email_config(&config)
            .context("Email configuration validation failed")?;

        // Security audit (warnings only)
        let warnings = validator::ConfigValidator::security_audit(&config);
        if !warnings.is_empty() {
            eprintln!("Security warnings:");
            for warning in warnings {
                eprintln!("  - {}", warning);
            }
        }

        Ok(config)
    }

    /// Legacy method for backward compatibility
    pub fn from_env_and_file() -> Result<Self> {
        // Load from config.yml if it exists
        let mut config = if std::path::Path::new("config.yml").exists() {
            let config_str =
                std::fs::read_to_string("config.yml").context("Failed to read config.yml")?;
            serde_yaml::from_str::<Config>(&config_str).context("Failed to parse config.yml")?
        } else {
            // Use default configuration
            Config::default()
        };

        // Override with environment variables
        Self::apply_env_overrides(&mut config)?;

        Ok(config)
    }

    /// Apply environment variable overrides to configuration
    fn apply_env_overrides(config: &mut Config) -> Result<()> {
        // Server overrides
        if let Ok(host) = env::var("SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = env::var("SERVER_PORT") {
            config.server.port = port.parse().context("Invalid SERVER_PORT")?;
        }
        if let Ok(workers) = env::var("SERVER_WORKERS") {
            config.server.workers = workers.parse().context("Invalid SERVER_WORKERS")?;
        }

        // Database overrides
        if let Ok(db_type) = env::var("DATABASE_TYPE") {
            config.database.r#type = db_type;
        }
        if let Ok(db_url) = env::var("DATABASE_URL") {
            config.database.url = db_url;
        }

        // MongoDB specific
        if let Ok(mongodb_url) = env::var("MONGODB_URL") {
            if let Some(ref mut mongodb) = config.database.mongodb {
                mongodb.url = mongodb_url;
            }
        }

        // PostgreSQL specific
        if let Ok(postgresql_url) = env::var("POSTGRESQL_URL") {
            if let Some(ref mut postgresql) = config.database.postgresql {
                postgresql.url = postgresql_url;
            }
        }

        // MySQL specific
        if let Ok(mysql_url) = env::var("MYSQL_URL") {
            if let Some(ref mut mysql) = config.database.mysql {
                mysql.url = mysql_url;
            }
        }

        // Authentication overrides
        if let Ok(jwt_secret) = env::var("JWT_SECRET") {
            config.auth.jwt_secret = jwt_secret;
        }
        if let Ok(bcrypt_rounds) = env::var("BCRYPT_ROUNDS") {
            config.auth.password_hash_rounds =
                bcrypt_rounds.parse().context("Invalid BCRYPT_ROUNDS")?;
        }

        // Cache overrides
        if let Ok(cache_type) = env::var("CACHE_TYPE") {
            config.cache.r#type = cache_type;
        }
        if let Ok(redis_url) = env::var("REDIS_URL") {
            if let Some(ref mut redis) = config.cache.redis {
                redis.url = redis_url;
            }
        }

        // Email overrides
        if let Ok(email_provider) = env::var("EMAIL_PROVIDER") {
            config.email.provider = email_provider;
        }
        if let Ok(brevo_key) = env::var("BREVO_API_KEY") {
            if let Some(ref mut brevo) = config.email.brevo {
                brevo.api_key = brevo_key;
            }
        }
        if let Ok(sendgrid_key) = env::var("SENDGRID_API_KEY") {
            if let Some(ref mut sendgrid) = config.email.sendgrid {
                sendgrid.api_key = sendgrid_key;
            }
        }
        if let Ok(email_from) = env::var("EMAIL_FROM") {
            if let Some(ref mut brevo) = config.email.brevo {
                brevo.from_email = email_from.clone();
            }
            if let Some(ref mut sendgrid) = config.email.sendgrid {
                sendgrid.from_email = email_from.clone();
            }
            if let Some(ref mut smtp) = config.email.smtp {
                smtp.from_email = email_from;
            }
        }

        // Rate limiting overrides
        if let Ok(rate_limit_enabled) = env::var("RATE_LIMIT_ENABLED") {
            config.rate_limit.enabled = rate_limit_enabled.parse().unwrap_or(true);
        }

        // CORS overrides
        if let Ok(cors_origins) = env::var("CORS_ALLOWED_ORIGINS") {
            config.security.cors.allowed_origins = cors_origins
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Monitoring overrides
        if let Ok(prometheus_enabled) = env::var("PROMETHEUS_ENABLED") {
            config.monitoring.prometheus.enabled = prometheus_enabled.parse().unwrap_or(true);
        }
        if let Ok(tracing_level) = env::var("TRACING_LEVEL") {
            config.monitoring.tracing.level = tracing_level;
        }
        if let Ok(jaeger_endpoint) = env::var("JAEGER_ENDPOINT") {
            config.monitoring.tracing.jaeger_endpoint = jaeger_endpoint;
        }

        Ok(())
    }

    /// Get configuration for the current environment
    pub fn for_environment(env: &str) -> Result<Self> {
        std::env::set_var("ENVIRONMENT", env);
        Self::load()
    }

    /// Reload configuration (useful for hot-reloading)
    pub fn reload(&mut self) -> Result<()> {
        let new_config = Self::load()?;
        *self = new_config;
        Ok(())
    }
}

// Config Default implementation is now derived
