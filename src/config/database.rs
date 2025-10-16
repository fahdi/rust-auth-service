use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub r#type: String, // mongodb, postgresql, mysql
    pub url: String,
    pub pool: PoolConfig,
    pub mongodb: Option<MongoDBConfig>,
    pub postgresql: Option<PostgreSQLConfig>,
    pub mysql: Option<MySQLConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoDBConfig {
    pub url: String,
    pub database: String,
    pub pool_size: u32,
    pub timeout: u64,
    pub ssl: bool,
    pub ssl_verify_certificate: Option<bool>,
    pub ssl_ca_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgreSQLConfig {
    pub url: String,
    pub pool_size: u32,
    pub ssl_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MySQLConfig {
    pub url: String,
    pub pool_size: u32,
    pub ssl_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    pub min_connections: u32,
    pub max_connections: u32,
    pub idle_timeout: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            r#type: "mongodb".to_string(),
            url: "mongodb://localhost:27017/auth".to_string(),
            pool: PoolConfig::default(),
            mongodb: None,
            postgresql: None,
            mysql: None,
        }
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_connections: 10,
            max_connections: 50,
            idle_timeout: 180,
        }
    }
}
