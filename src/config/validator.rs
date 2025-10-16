use anyhow::{anyhow, Result};
use crate::config::Config;

/// Configuration validator for ensuring production readiness and security
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate configuration for production environment
    pub fn validate_production(config: &Config) -> Result<()> {
        let mut errors = Vec::new();

        // Security validations
        Self::validate_security(config, &mut errors);
        
        // Database validations
        Self::validate_database(config, &mut errors);
        
        // Authentication validations
        Self::validate_auth(config, &mut errors);
        
        // Performance validations
        Self::validate_performance(config, &mut errors);
        
        // Monitoring validations
        Self::validate_monitoring(config, &mut errors);

        if !errors.is_empty() {
            return Err(anyhow!("Configuration validation failed:\n{}", errors.join("\n")));
        }

        Ok(())
    }

    /// Validate configuration for any environment
    pub fn validate_basic(config: &Config) -> Result<()> {
        let mut errors = Vec::new();

        // Basic structure validations
        if config.server.port == 0 && config.environment.name != "testing" {
            errors.push("Server port must be specified (non-zero)".to_string());
        }

        if config.server.workers == 0 {
            errors.push("Server workers must be at least 1".to_string());
        }

        if config.auth.jwt_secret.is_empty() {
            errors.push("JWT secret cannot be empty".to_string());
        }

        if config.auth.password_hash_rounds < 4 {
            errors.push("Password hash rounds must be at least 4".to_string());
        }

        if !errors.is_empty() {
            return Err(anyhow!("Basic configuration validation failed:\n{}", errors.join("\n")));
        }

        Ok(())
    }

    fn validate_security(config: &Config, errors: &mut Vec<String>) {
        // JWT secret strength
        if config.auth.jwt_secret.len() < 32 {
            errors.push("JWT secret should be at least 32 characters for production".to_string());
        }

        if config.auth.jwt_secret.contains("secret") || 
           config.auth.jwt_secret.contains("password") ||
           config.auth.jwt_secret.contains("key") {
            errors.push("JWT secret appears to contain common words - use a cryptographically random string".to_string());
        }

        // Password hashing
        if config.auth.password_hash_rounds < 10 {
            errors.push("Password hash rounds should be at least 10 for production".to_string());
        }

        // CORS validation
        if config.security.cors.allowed_origins.contains(&"*".to_string()) {
            errors.push("CORS should not allow all origins (*) in production".to_string());
        }

        // SSL/TLS validation for production
        if config.environment.name == "production" {
            match config.database.r#type.as_str() {
                "mongodb" => {
                    if let Some(mongodb) = &config.database.mongodb {
                        if !mongodb.ssl {
                            errors.push("MongoDB SSL should be enabled in production".to_string());
                        }
                    }
                }
                "postgresql" => {
                    if let Some(postgresql) = &config.database.postgresql {
                        if postgresql.ssl_mode != "require" {
                            errors.push("PostgreSQL SSL mode should be 'require' in production".to_string());
                        }
                    }
                }
                "mysql" => {
                    if let Some(mysql) = &config.database.mysql {
                        if mysql.ssl_mode != "REQUIRED" {
                            errors.push("MySQL SSL mode should be 'REQUIRED' in production".to_string());
                        }
                    }
                }
            }

            // Redis SSL
            if let Some(redis) = &config.cache.redis {
                if !redis.ssl {
                    errors.push("Redis SSL should be enabled in production".to_string());
                }
            }
        }

        // Rate limiting
        if !config.rate_limiting.enabled && config.environment.name == "production" {
            errors.push("Rate limiting should be enabled in production".to_string());
        }
    }

    fn validate_database(config: &Config, errors: &mut Vec<String>) {
        // Pool size validation
        let min_pool = match config.environment.name.as_str() {
            "production" => 5,
            "staging" => 2,
            _ => 1,
        };

        match config.database.r#type.as_str() {
            "mongodb" => {
                if let Some(mongodb) = &config.database.mongodb {
                    if mongodb.pool_size < min_pool {
                        errors.push(format!("MongoDB pool size should be at least {} for {}", min_pool, config.environment.name));
                    }
                    if mongodb.url.is_empty() {
                        errors.push("MongoDB URL cannot be empty".to_string());
                    }
                }
            }
            "postgresql" => {
                if let Some(postgresql) = &config.database.postgresql {
                    if postgresql.pool_size < min_pool {
                        errors.push(format!("PostgreSQL pool size should be at least {} for {}", min_pool, config.environment.name));
                    }
                    if postgresql.url.is_empty() {
                        errors.push("PostgreSQL URL cannot be empty".to_string());
                    }
                }
            }
            "mysql" => {
                if let Some(mysql) = &config.database.mysql {
                    if mysql.pool_size < min_pool {
                        errors.push(format!("MySQL pool size should be at least {} for {}", min_pool, config.environment.name));
                    }
                    if mysql.url.is_empty() {
                        errors.push("MySQL URL cannot be empty".to_string());
                    }
                }
            }
        }
    }

    fn validate_auth(config: &Config, errors: &mut Vec<String>) {
        // Token expiration validation
        if config.auth.jwt_expiration > 86400 {  // 24 hours
            errors.push("JWT token expiration should not exceed 24 hours for security".to_string());
        }

        if config.auth.jwt_refresh_expiration > 2592000 {  // 30 days
            errors.push("JWT refresh token expiration should not exceed 30 days".to_string());
        }

        // Lockout settings
        if config.auth.max_failed_attempts > 10 {
            errors.push("Max failed attempts should not exceed 10".to_string());
        }

        if config.auth.lockout_duration < 60 && config.environment.name == "production" {
            errors.push("Lockout duration should be at least 60 seconds in production".to_string());
        }
    }

    fn validate_performance(config: &Config, errors: &mut Vec<String>) {
        // Worker thread validation
        let max_workers = num_cpus::get();
        if config.server.workers > max_workers {
            errors.push(format!("Server workers ({}) should not exceed CPU count ({})", config.server.workers, max_workers));
        }

        // Connection limits
        if config.server.max_connections < config.server.workers * 10 {
            errors.push("Max connections should be at least 10x the number of workers".to_string());
        }

        // Timeout validation
        if config.server.timeout > 300 {  // 5 minutes
            errors.push("Server timeout should not exceed 300 seconds".to_string());
        }

        // Cache size validation
        if config.cache.memory.max_size > 100000 && config.environment.name != "production" {
            errors.push("Memory cache size seems very large for non-production environment".to_string());
        }
    }

    fn validate_monitoring(config: &Config, errors: &mut Vec<String>) {
        if config.environment.name == "production" {
            if !config.monitoring.prometheus.enabled {
                errors.push("Prometheus monitoring should be enabled in production".to_string());
            }

            if !config.monitoring.health_checks.enabled {
                errors.push("Health checks should be enabled in production".to_string());
            }

            if !config.monitoring.audit_logging.enabled {
                errors.push("Audit logging should be enabled in production".to_string());
            }

            if config.monitoring.tracing.sample_rate > 0.2 {
                errors.push("Tracing sample rate should not exceed 20% in production for performance".to_string());
            }
        }
    }

    /// Validate required environment variables are set
    pub fn validate_environment_variables() -> Result<()> {
        let mut missing = Vec::new();
        let env = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

        // Always required
        let required_vars = match env.as_str() {
            "production" => vec![
                "JWT_SECRET",
                "DATABASE_URL", 
                "MONGODB_URL",
                "REDIS_URL",
                "EMAIL_FROM",
            ],
            "staging" => vec![
                "JWT_SECRET_STAGING",
                "MONGODB_STAGING_URL",
                "REDIS_STAGING_URL",
            ],
            _ => vec![], // Development doesn't require env vars
        };

        for var in required_vars {
            if std::env::var(var).is_err() {
                missing.push(var.to_string());
            }
        }

        if !missing.is_empty() {
            return Err(anyhow!("Missing required environment variables for {} environment: {}", env, missing.join(", ")));
        }

        Ok(())
    }

    /// Validate email provider configuration
    pub fn validate_email_config(config: &Config) -> Result<()> {
        match config.email.provider.as_str() {
            "brevo" => {
                if let Some(brevo) = &config.email.brevo {
                    if brevo.api_key.is_empty() {
                        return Err(anyhow!("Brevo API key is required when using Brevo provider"));
                    }
                    if brevo.from_email.is_empty() {
                        return Err(anyhow!("From email is required when using Brevo provider"));
                    }
                } else {
                    return Err(anyhow!("Brevo configuration is required when using Brevo provider"));
                }
            }
            "sendgrid" => {
                if let Some(sendgrid) = &config.email.sendgrid {
                    if sendgrid.api_key.is_empty() {
                        return Err(anyhow!("SendGrid API key is required when using SendGrid provider"));
                    }
                    if sendgrid.from_email.is_empty() {
                        return Err(anyhow!("From email is required when using SendGrid provider"));
                    }
                } else {
                    return Err(anyhow!("SendGrid configuration is required when using SendGrid provider"));
                }
            }
            "smtp" => {
                if let Some(smtp) = &config.email.smtp {
                    if smtp.host.is_empty() {
                        return Err(anyhow!("SMTP host is required when using SMTP provider"));
                    }
                    if smtp.from_email.is_empty() {
                        return Err(anyhow!("From email is required when using SMTP provider"));
                    }
                } else {
                    return Err(anyhow!("SMTP configuration is required when using SMTP provider"));
                }
            }
            _ => {
                return Err(anyhow!("Invalid email provider: {}", config.email.provider));
            }
        }

        Ok(())
    }

    /// Check for common security misconfigurations
    pub fn security_audit(config: &Config) -> Vec<String> {
        let mut warnings = Vec::new();

        // Check for default passwords or keys
        if config.auth.jwt_secret.to_lowercase().contains("default") ||
           config.auth.jwt_secret.to_lowercase().contains("example") {
            warnings.push("JWT secret appears to contain default/example values".to_string());
        }

        // Check CORS configuration
        if config.security.cors.allowed_origins.len() > 5 {
            warnings.push("Large number of allowed CORS origins may indicate overly permissive configuration".to_string());
        }

        // Check rate limiting
        if config.rate_limiting.requests_per_minute > 1000 {
            warnings.push("Very high rate limiting threshold may not provide adequate protection".to_string());
        }

        // Check session timeouts
        if config.auth.session_timeout > 28800 {  // 8 hours
            warnings.push("Session timeout is very long, consider shorter timeouts for better security".to_string());
        }

        // Check logging configuration
        if config.logging.level == "debug" && config.environment.name == "production" {
            warnings.push("Debug logging is enabled in production, this may leak sensitive information".to_string());
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ServerConfig, AuthConfig, DatabaseConfig, DatabaseType};

    fn create_test_config() -> Config {
        Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8090,
                workers: 2,
                max_connections: 100,
                keep_alive: 60,
                timeout: 30,
            },
            auth: AuthConfig {
                jwt_secret: "test-secret-key-with-sufficient-length".to_string(),
                jwt_expiration: 3600,
                jwt_refresh_expiration: 604800,
                password_hash_rounds: 10,
                max_failed_attempts: 5,
                lockout_duration: 300,
                require_email_verification: true,
                allow_password_reset: true,
                session_timeout: 7200,
            },
            database: DatabaseConfig {
                r#type: "mongodb".to_string(),
                mongodb: Some(crate::config::MongoDBConfig {
                    url: "mongodb://localhost:27017".to_string(),
                    database: "test".to_string(),
                    pool_size: 10,
                    timeout: 30,
                    ssl: true,
                    ssl_verify_certificate: Some(true),
                    ssl_ca_file: None,
                }),
                postgresql: None,
                mysql: None,
            },
            // ... other fields with default values
            ..Default::default()
        }
    }

    #[test]
    fn test_basic_validation_success() {
        let config = create_test_config();
        assert!(ConfigValidator::validate_basic(&config).is_ok());
    }

    #[test]
    fn test_basic_validation_empty_jwt_secret() {
        let mut config = create_test_config();
        config.auth.jwt_secret = "".to_string();
        
        let result = ConfigValidator::validate_basic(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("JWT secret cannot be empty"));
    }

    #[test]
    fn test_production_validation_weak_jwt() {
        let mut config = create_test_config();
        config.auth.jwt_secret = "weak".to_string();
        config.environment.name = "production".to_string();
        
        let result = ConfigValidator::validate_production(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_security_audit() {
        let mut config = create_test_config();
        config.auth.jwt_secret = "default-secret".to_string();
        
        let warnings = ConfigValidator::security_audit(&config);
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("default")));
    }
}