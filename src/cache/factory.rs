use super::memory_cache::MemoryCacheWithCleanup;
use super::redis_cache::RedisCache;
use super::{CacheProvider, MultiLevelCache};
use crate::config::cache::CacheConfig;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Create cache provider based on configuration
pub async fn create_cache_provider(config: &CacheConfig) -> Result<Arc<dyn CacheProvider>> {
    match config.r#type.as_str() {
        "redis" => {
            if let Some(redis_url) = &config.url {
                match RedisCache::new(redis_url).await {
                    Ok(redis_cache) => {
                        info!("Using Redis cache at: {}", redis_url);
                        Ok(Arc::new(redis_cache))
                    }
                    Err(e) => {
                        warn!(
                            "Failed to connect to Redis: {}. Falling back to memory cache",
                            e
                        );
                        let memory_cache = MemoryCacheWithCleanup::new(
                            config.lru_size,
                            Duration::from_secs(300), // Clean every 5 minutes
                        );
                        Ok(Arc::new(memory_cache))
                    }
                }
            } else {
                warn!("Redis URL not configured. Using memory cache");
                let memory_cache =
                    MemoryCacheWithCleanup::new(config.lru_size, Duration::from_secs(300));
                Ok(Arc::new(memory_cache))
            }
        }
        "memory" => {
            info!("Using memory cache with LRU size: {}", config.lru_size);
            let memory_cache =
                MemoryCacheWithCleanup::new(config.lru_size, Duration::from_secs(300));
            Ok(Arc::new(memory_cache))
        }
        "none" => {
            info!("Cache disabled");
            Ok(Arc::new(NoOpCache))
        }
        "multi" => create_multi_level_cache(config).await,
        _ => {
            warn!("Unknown cache type '{}'. Using memory cache", config.r#type);
            let memory_cache =
                MemoryCacheWithCleanup::new(config.lru_size, Duration::from_secs(300));
            Ok(Arc::new(memory_cache))
        }
    }
}

/// Create multi-level cache with Redis primary and memory fallback
pub async fn create_multi_level_cache(config: &CacheConfig) -> Result<Arc<dyn CacheProvider>> {
    // Always create memory cache as fallback
    let memory_cache = Arc::new(MemoryCacheWithCleanup::new(
        config.lru_size,
        Duration::from_secs(300),
    ));

    // Try to create Redis cache as primary
    let redis_cache = if let Some(redis_url) = &config.url {
        match RedisCache::new(redis_url).await {
            Ok(redis) => {
                info!("Multi-level cache: Redis primary + Memory fallback");
                Some(Arc::new(redis) as Arc<dyn CacheProvider>)
            }
            Err(e) => {
                warn!(
                    "Failed to connect to Redis for multi-level cache: {}. Using memory only",
                    e
                );
                None
            }
        }
    } else {
        warn!("Redis URL not configured for multi-level cache. Using memory only");
        None
    };

    let multi_cache = MultiLevelCache::new(redis_cache, memory_cache);
    Ok(Arc::new(multi_cache))
}

/// No-op cache implementation for when caching is disabled
pub struct NoOpCache;

#[async_trait::async_trait]
impl CacheProvider for NoOpCache {
    async fn get(&self, _key: &str) -> Result<Option<String>> {
        Ok(None)
    }

    async fn set(&self, _key: &str, _value: &str, _ttl: Duration) -> Result<()> {
        Ok(())
    }

    async fn delete(&self, _key: &str) -> Result<()> {
        Ok(())
    }

    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        Ok(())
    }

    async fn stats(&self) -> Result<super::CacheStats> {
        Ok(super::CacheStats::new())
    }
}

/// Cache service for dependency injection
pub struct CacheService {
    provider: Arc<dyn CacheProvider>,
    default_ttl: Duration,
}

impl CacheService {
    pub fn new(provider: Arc<dyn CacheProvider>, default_ttl_seconds: u64) -> Self {
        Self {
            provider,
            default_ttl: Duration::from_secs(default_ttl_seconds),
        }
    }

    /// Get value from cache
    pub async fn get(&self, key: &str) -> Result<Option<String>> {
        self.provider.get(key).await
    }

    /// Set value in cache with default TTL
    pub async fn set(&self, key: &str, value: &str) -> Result<()> {
        self.provider.set(key, value, self.default_ttl).await
    }

    /// Set value in cache with custom TTL
    pub async fn set_with_ttl(&self, key: &str, value: &str, ttl: Duration) -> Result<()> {
        self.provider.set(key, value, ttl).await
    }

    /// Delete value from cache
    pub async fn delete(&self, key: &str) -> Result<()> {
        self.provider.delete(key).await
    }

    /// Check cache health
    pub async fn ping(&self) -> Result<()> {
        self.provider.ping().await
    }

    /// Clear all cache entries
    pub async fn clear(&self) -> Result<()> {
        self.provider.clear().await
    }

    /// Get cache statistics
    pub async fn stats(&self) -> Result<super::CacheStats> {
        self.provider.stats().await
    }

    /// Get or set pattern - common caching pattern
    pub async fn get_or_set<F, Fut>(&self, key: &str, factory: F) -> Result<String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<String>>,
    {
        // Try to get from cache first
        if let Some(cached_value) = self.get(key).await? {
            return Ok(cached_value);
        }

        // Not in cache, compute value
        let value = factory().await?;

        // Store in cache for next time
        self.set(key, &value).await?;

        Ok(value)
    }

    /// Get or set with custom TTL
    pub async fn get_or_set_with_ttl<F, Fut>(
        &self,
        key: &str,
        ttl: Duration,
        factory: F,
    ) -> Result<String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<String>>,
    {
        // Try to get from cache first
        if let Some(cached_value) = self.get(key).await? {
            return Ok(cached_value);
        }

        // Not in cache, compute value
        let value = factory().await?;

        // Store in cache for next time with custom TTL
        self.set_with_ttl(key, &value, ttl).await?;

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::cache::CacheConfig;

    #[tokio::test]
    async fn test_create_memory_cache() {
        let config = CacheConfig {
            r#type: "memory".to_string(),
            url: None,
            ttl: 3600,
            lru_size: 100,
        };

        let cache = create_cache_provider(&config).await.unwrap();

        // Test basic operations
        cache
            .set("test", "value", Duration::from_secs(60))
            .await
            .unwrap();
        let value = cache.get("test").await.unwrap();
        assert_eq!(value, Some("value".to_string()));
    }

    #[tokio::test]
    async fn test_create_noop_cache() {
        let config = CacheConfig {
            r#type: "none".to_string(),
            url: None,
            ttl: 3600,
            lru_size: 100,
        };

        let cache = create_cache_provider(&config).await.unwrap();

        // Test no-op behavior
        cache
            .set("test", "value", Duration::from_secs(60))
            .await
            .unwrap();
        let value = cache.get("test").await.unwrap();
        assert_eq!(value, None); // Should always return None
    }

    #[tokio::test]
    async fn test_cache_service() {
        let config = CacheConfig {
            r#type: "memory".to_string(),
            url: None,
            ttl: 3600,
            lru_size: 100,
        };

        let provider = create_cache_provider(&config).await.unwrap();
        let service = CacheService::new(provider, 3600);

        // Test get_or_set pattern
        let value = service
            .get_or_set("test_key", || async { Ok("computed_value".to_string()) })
            .await
            .unwrap();
        assert_eq!(value, "computed_value");

        // Second call should return cached value (not recompute)
        let cached_value = service
            .get_or_set("test_key", || async {
                Ok("should_not_be_called".to_string())
            })
            .await
            .unwrap();
        assert_eq!(cached_value, "computed_value");
    }
}
