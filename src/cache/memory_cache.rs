use super::{CacheProvider, CacheStats};
use anyhow::Result;
use async_trait::async_trait;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

#[derive(Clone)]
struct CacheEntry {
    value: String,
    expires_at: Option<Instant>,
}

impl CacheEntry {
    fn new(value: String, ttl: Duration) -> Self {
        let expires_at = if ttl.is_zero() {
            None // No expiration
        } else {
            Some(Instant::now() + ttl)
        };
        
        Self {
            value,
            expires_at,
        }
    }
    
    fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Instant::now() > expires_at
        } else {
            false
        }
    }
}

pub struct MemoryCache {
    cache: Arc<RwLock<LruCache<String, CacheEntry>>>,
    stats: Arc<RwLock<CacheStats>>,
}

impl MemoryCache {
    pub fn new(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1000).unwrap());
        
        Self {
            cache: Arc::new(RwLock::new(LruCache::new(capacity))),
            stats: Arc::new(RwLock::new(CacheStats::new())),
        }
    }
    
    async fn record_hit(&self) {
        let mut stats = self.stats.write().await;
        stats.hits += 1;
        stats.calculate_hit_rate();
    }
    
    async fn record_miss(&self) {
        let mut stats = self.stats.write().await;
        stats.misses += 1;
        stats.calculate_hit_rate();
    }
    
    /// Clean up expired entries
    async fn cleanup_expired(&self) {
        let mut cache = self.cache.write().await;
        let mut expired_keys = Vec::new();
        
        // Collect expired keys
        for (key, entry) in cache.iter() {
            if entry.is_expired() {
                expired_keys.push(key.clone());
            }
        }
        
        // Remove expired entries
        for key in expired_keys {
            cache.pop(&key);
            debug!("Removed expired cache entry: {}", key);
        }
    }
    
    /// Get cache size for statistics
    pub async fn size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }
    
    /// Get cache capacity
    pub async fn capacity(&self) -> usize {
        let cache = self.cache.read().await;
        cache.cap().get()
    }
}

#[async_trait]
impl CacheProvider for MemoryCache {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        // Clean up expired entries periodically
        if fastrand::f64() < 0.01 { // 1% chance to trigger cleanup
            self.cleanup_expired().await;
        }
        
        let mut cache = self.cache.write().await;
        
        if let Some(entry) = cache.get(key) {
            if entry.is_expired() {
                // Entry expired, remove it
                cache.pop(key);
                self.record_miss().await;
                Ok(None)
            } else {
                // Entry is valid
                self.record_hit().await;
                Ok(Some(entry.value.clone()))
            }
        } else {
            self.record_miss().await;
            Ok(None)
        }
    }

    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<()> {
        let entry = CacheEntry::new(value.to_string(), ttl);
        
        let mut cache = self.cache.write().await;
        cache.put(key.to_string(), entry);
        
        debug!("Set memory cache entry: {} (TTL: {:?})", key, ttl);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut cache = self.cache.write().await;
        
        if cache.pop(key).is_some() {
            debug!("Deleted memory cache entry: {}", key);
        } else {
            warn!("Memory cache key '{}' was not found during deletion", key);
        }
        
        Ok(())
    }

    async fn ping(&self) -> Result<()> {
        // Memory cache is always "healthy"
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        let mut cache = self.cache.write().await;
        cache.clear();
        
        // Reset stats
        let mut stats = self.stats.write().await;
        *stats = CacheStats::new();
        
        debug!("Cleared all memory cache entries");
        Ok(())
    }

    async fn stats(&self) -> Result<CacheStats> {
        let cache = self.cache.read().await;
        let stats = self.stats.read().await;
        
        Ok(CacheStats {
            hits: stats.hits,
            misses: stats.misses,
            size: cache.len(),
            hit_rate: stats.hit_rate,
        })
    }
}

/// Thread-safe wrapper for MemoryCache with background cleanup
pub struct MemoryCacheWithCleanup {
    cache: MemoryCache,
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl MemoryCacheWithCleanup {
    pub fn new(capacity: usize, cleanup_interval: Duration) -> Self {
        let cache = MemoryCache::new(capacity);
        let cache_clone = MemoryCache {
            cache: Arc::clone(&cache.cache),
            stats: Arc::clone(&cache.stats),
        };
        
        // Spawn background cleanup task
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                cache_clone.cleanup_expired().await;
            }
        });
        
        Self {
            cache,
            cleanup_handle: Some(cleanup_handle),
        }
    }
}

impl Drop for MemoryCacheWithCleanup {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
    }
}

#[async_trait]
impl CacheProvider for MemoryCacheWithCleanup {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        self.cache.get(key).await
    }

    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<()> {
        self.cache.set(key, value, ttl).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.cache.delete(key).await
    }

    async fn ping(&self) -> Result<()> {
        self.cache.ping().await
    }

    async fn clear(&self) -> Result<()> {
        self.cache.clear().await
    }

    async fn stats(&self) -> Result<CacheStats> {
        self.cache.stats().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_memory_cache_basic_operations() {
        let cache = MemoryCache::new(100);
        
        // Test set and get
        cache.set("test_key", "test_value", Duration::from_secs(60)).await.unwrap();
        let value = cache.get("test_key").await.unwrap();
        assert_eq!(value, Some("test_value".to_string()));
        
        // Test missing key
        let missing = cache.get("missing_key").await.unwrap();
        assert_eq!(missing, None);
        
        // Test delete
        cache.delete("test_key").await.unwrap();
        let deleted = cache.get("test_key").await.unwrap();
        assert_eq!(deleted, None);
        
        // Test ping
        cache.ping().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_memory_cache_expiration() {
        let cache = MemoryCache::new(100);
        
        // Set with short TTL
        cache.set("ttl_test", "value", Duration::from_millis(50)).await.unwrap();
        
        // Should exist immediately
        let value = cache.get("ttl_test").await.unwrap();
        assert_eq!(value, Some("value".to_string()));
        
        // Wait for expiration
        sleep(Duration::from_millis(100)).await;
        
        // Should be expired
        let expired = cache.get("ttl_test").await.unwrap();
        assert_eq!(expired, None);
    }
    
    #[tokio::test]
    async fn test_memory_cache_lru_eviction() {
        let cache = MemoryCache::new(2); // Small capacity
        
        // Fill cache
        cache.set("key1", "value1", Duration::from_secs(60)).await.unwrap();
        cache.set("key2", "value2", Duration::from_secs(60)).await.unwrap();
        
        // Both should exist
        assert_eq!(cache.get("key1").await.unwrap(), Some("value1".to_string()));
        assert_eq!(cache.get("key2").await.unwrap(), Some("value2".to_string()));
        
        // Add third key, should evict least recently used
        cache.set("key3", "value3", Duration::from_secs(60)).await.unwrap();
        
        // key1 should be evicted (was accessed first)
        assert_eq!(cache.get("key1").await.unwrap(), None);
        assert_eq!(cache.get("key2").await.unwrap(), Some("value2".to_string()));
        assert_eq!(cache.get("key3").await.unwrap(), Some("value3".to_string()));
    }
    
    #[tokio::test]
    async fn test_memory_cache_stats() {
        let cache = MemoryCache::new(100);
        
        // Generate some hits and misses
        cache.set("key1", "value1", Duration::from_secs(60)).await.unwrap();
        
        cache.get("key1").await.unwrap(); // hit
        cache.get("missing").await.unwrap(); // miss
        cache.get("key1").await.unwrap(); // hit
        
        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.size, 1);
        assert!((stats.hit_rate - 0.666).abs() < 0.01); // 2/3 ≈ 0.666
    }
    
    #[tokio::test]
    async fn test_memory_cache_with_cleanup() {
        let cache = MemoryCacheWithCleanup::new(100, Duration::from_millis(10));
        
        // Set entries with short TTL
        cache.set("key1", "value1", Duration::from_millis(20)).await.unwrap();
        cache.set("key2", "value2", Duration::from_millis(40)).await.unwrap();
        
        // Wait for cleanup to run
        sleep(Duration::from_millis(50)).await;
        
        // Both should be expired and cleaned up
        assert_eq!(cache.get("key1").await.unwrap(), None);
        assert_eq!(cache.get("key2").await.unwrap(), None);
    }
}