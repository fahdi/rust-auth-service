use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

pub mod redis_cache;
pub mod memory_cache;
pub mod factory;

// Re-exports for convenience
pub use factory::{create_cache_provider, create_multi_level_cache, CacheService};
pub use memory_cache::MemoryCache;
pub use redis_cache::RedisCache;

#[async_trait]
pub trait CacheProvider: Send + Sync {
    /// Get a value from cache
    async fn get(&self, key: &str) -> Result<Option<String>>;
    
    /// Set a value in cache with TTL
    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<()>;
    
    /// Delete a value from cache
    async fn delete(&self, key: &str) -> Result<()>;
    
    /// Check if cache is healthy/connected
    async fn ping(&self) -> Result<()>;
    
    /// Clear all cache entries (for testing)
    async fn clear(&self) -> Result<()>;
    
    /// Get cache statistics
    async fn stats(&self) -> Result<CacheStats>;
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub size: usize,
    pub hit_rate: f64,
}

impl CacheStats {
    pub fn new() -> Self {
        Self {
            hits: 0,
            misses: 0,
            size: 0,
            hit_rate: 0.0,
        }
    }
    
    pub fn calculate_hit_rate(&mut self) {
        let total = self.hits + self.misses;
        if total > 0 {
            self.hit_rate = self.hits as f64 / total as f64;
        }
    }
}

/// Multi-level cache that tries Redis first, falls back to memory cache
pub struct MultiLevelCache {
    primary: Option<Arc<dyn CacheProvider>>,
    fallback: Arc<dyn CacheProvider>,
}

impl MultiLevelCache {
    pub fn new(
        primary: Option<Arc<dyn CacheProvider>>,
        fallback: Arc<dyn CacheProvider>,
    ) -> Self {
        Self { primary, fallback }
    }
}

#[async_trait]
impl CacheProvider for MultiLevelCache {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        // Try primary cache first (Redis)
        if let Some(primary) = &self.primary {
            match primary.get(key).await {
                Ok(Some(value)) => return Ok(Some(value)),
                Ok(None) => {
                    // Not found in primary, try fallback
                    if let Ok(Some(value)) = self.fallback.get(key).await {
                        // Found in fallback, promote to primary
                        let _ = primary.set(key, &value, Duration::from_secs(3600)).await;
                        return Ok(Some(value));
                    }
                }
                Err(_) => {
                    // Primary cache error, fall back to memory
                    return self.fallback.get(key).await;
                }
            }
        }
        
        // No primary cache or not found, use fallback
        self.fallback.get(key).await
    }

    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<()> {
        // Set in both caches
        if let Some(primary) = &self.primary {
            let _ = primary.set(key, value, ttl).await; // Don't fail if Redis is down
        }
        self.fallback.set(key, value, ttl).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        // Delete from both caches
        if let Some(primary) = &self.primary {
            let _ = primary.delete(key).await; // Don't fail if Redis is down
        }
        self.fallback.delete(key).await
    }

    async fn ping(&self) -> Result<()> {
        // Fallback must always work
        self.fallback.ping().await?;
        
        // Primary is optional
        if let Some(primary) = &self.primary {
            primary.ping().await?;
        }
        
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        if let Some(primary) = &self.primary {
            let _ = primary.clear().await;
        }
        self.fallback.clear().await
    }

    async fn stats(&self) -> Result<CacheStats> {
        // Return combined stats from both caches
        let fallback_stats = self.fallback.stats().await?;
        
        if let Some(primary) = &self.primary {
            if let Ok(primary_stats) = primary.stats().await {
                let mut combined = CacheStats {
                    hits: primary_stats.hits + fallback_stats.hits,
                    misses: primary_stats.misses + fallback_stats.misses,
                    size: primary_stats.size + fallback_stats.size,
                    hit_rate: 0.0,
                };
                combined.calculate_hit_rate();
                return Ok(combined);
            }
        }
        
        Ok(fallback_stats)
    }
}

/// Cache key utilities
pub struct CacheKey;

impl CacheKey {
    pub fn user_by_id(user_id: &str) -> String {
        format!("user:id:{}", user_id)
    }
    
    pub fn user_by_email(email: &str) -> String {
        format!("user:email:{}", email)
    }
    
    pub fn session(session_id: &str) -> String {
        format!("session:{}", session_id)
    }
    
    pub fn password_reset_token(token: &str) -> String {
        format!("reset_token:{}", token)
    }
    
    pub fn email_verification_token(token: &str) -> String {
        format!("verify_token:{}", token)
    }
    
    pub fn rate_limit(ip: &str) -> String {
        format!("rate_limit:{}", ip)
    }
    
    pub fn login_attempts(email: &str) -> String {
        format!("login_attempts:{}", email)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::memory_cache::MemoryCache;
    
    #[tokio::test]
    async fn test_cache_key_generation() {
        assert_eq!(CacheKey::user_by_id("123"), "user:id:123");
        assert_eq!(CacheKey::user_by_email("test@example.com"), "user:email:test@example.com");
        assert_eq!(CacheKey::session("sess_123"), "session:sess_123");
        assert_eq!(CacheKey::rate_limit("192.168.1.1"), "rate_limit:192.168.1.1");
    }
    
    #[tokio::test]
    async fn test_multi_level_cache_fallback() {
        let memory_cache = Arc::new(MemoryCache::new(100));
        let multi_cache = MultiLevelCache::new(None, memory_cache);
        
        // Test basic operations
        multi_cache.set("test_key", "test_value", Duration::from_secs(60)).await.unwrap();
        let value = multi_cache.get("test_key").await.unwrap();
        assert_eq!(value, Some("test_value".to_string()));
        
        // Test stats
        let stats = multi_cache.stats().await.unwrap();
        assert!(stats.hits > 0 || stats.misses > 0);
    }
}