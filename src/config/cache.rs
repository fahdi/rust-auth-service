use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub r#type: String, // redis, memory, none
    pub url: Option<String>,
    pub ttl: u64,
    pub lru_size: usize,
    pub redis: Option<RedisConfig>,
    pub memory: MemoryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    pub max_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub ssl: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            r#type: "redis".to_string(),
            url: Some("redis://localhost:6379".to_string()),
            ttl: 3600,
            lru_size: 1000,
            redis: None,
            memory: MemoryConfig::default(),
        }
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_size: 1000,
        }
    }
}
