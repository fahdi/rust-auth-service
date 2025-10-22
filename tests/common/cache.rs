use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use rust_auth_service::cache::{
    CacheProvider, MemoryCache, MultiLevelCache,
    RedisCache,
};
use rust_auth_service::config::{CacheConfig, RedisConfig};

/// Test cache wrapper with cleanup capabilities
pub struct TestCache {
    pub provider: Arc<dyn CacheProvider>,
    pub cache_type: String,
    pub test_id: String,
    pub cleanup_keys: Arc<Mutex<Vec<String>>>,
}

impl TestCache {
    pub async fn new_memory(capacity: usize, test_id: &str) -> Self {
        let provider = Arc::new(MemoryCache::new(capacity));

        Self {
            provider,
            cache_type: "memory".to_string(),
            test_id: test_id.to_string(),
            cleanup_keys: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn new_redis(redis_url: &str, test_id: &str) -> Result<Self> {
        let provider = Arc::new(RedisCache::new(redis_url).await?);

        Ok(Self {
            provider,
            cache_type: "redis".to_string(),
            test_id: test_id.to_string(),
            cleanup_keys: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub async fn new_multi_level(
        redis_url: Option<&str>,
        memory_capacity: usize,
        test_id: &str,
    ) -> Result<Self> {
        let memory_cache = Arc::new(MemoryCache::new(memory_capacity));

        let redis_cache = if let Some(url) = redis_url {
            match RedisCache::new(url).await {
                Ok(redis) => Some(Arc::new(redis) as Arc<dyn CacheProvider>),
                Err(e) => {
                    warn!("Failed to connect to Redis for multi-level cache: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let provider = Arc::new(MultiLevelCache::new(redis_cache, memory_cache));

        Ok(Self {
            provider,
            cache_type: "multi_level".to_string(),
            test_id: test_id.to_string(),
            cleanup_keys: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Track a key for cleanup
    pub async fn track_key(&self, key: &str) {
        let mut keys = self.cleanup_keys.lock().await;
        keys.push(key.to_string());
    }

    /// Set a value and track the key for cleanup
    pub async fn set_and_track(&self, key: &str, value: &str, ttl: Duration) -> Result<()> {
        self.provider.set(key, value, ttl).await?;
        self.track_key(key).await;
        Ok(())
    }

    /// Clean up all tracked keys
    pub async fn cleanup(&self) -> Result<()> {
        debug!("Cleaning up test cache: {}", self.test_id);

        let keys = {
            let mut keys_guard = self.cleanup_keys.lock().await;
            let keys = keys_guard.clone();
            keys_guard.clear();
            keys
        };

        for key in keys {
            if let Err(e) = self.provider.delete(&key).await {
                warn!("Failed to cleanup key {}: {}", key, e);
            }
        }

        info!("Test cache cleanup completed: {}", self.test_id);
        Ok(())
    }
}

/// Cache test manager for coordinating multiple cache instances
pub struct CacheTestManager {
    redis_url: Option<String>,
    caches: Arc<Mutex<Vec<Arc<TestCache>>>>,
}

impl CacheTestManager {
    pub fn new() -> Self {
        // Try to get Redis URL from environment, fallback to default
        let redis_url = std::env::var("REDIS_URL")
            .or_else(|_| std::env::var("REDIS_TEST_URL"))
            .unwrap_or_else(|_| "redis://localhost:6379".to_string());

        // Check if Redis is available
        let redis_url = if Self::is_redis_available(&redis_url) {
            Some(redis_url)
        } else {
            warn!("Redis not available for testing, using memory cache only");
            None
        };

        Self {
            redis_url,
            caches: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn is_redis_available(redis_url: &str) -> bool {
        tokio::runtime::Handle::try_current()
            .map(|_| {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(async { RedisCache::new(redis_url).await.is_ok() })
                })
            })
            .unwrap_or(false)
    }

    pub async fn create_memory_cache(&self, capacity: usize) -> Arc<TestCache> {
        let test_id = format!("memory_test_{}", uuid::Uuid::new_v4());
        let cache = Arc::new(TestCache::new_memory(capacity, &test_id).await);

        {
            let mut caches = self.caches.lock().await;
            caches.push(cache.clone());
        }

        cache
    }

    pub async fn create_redis_cache(&self) -> Result<Arc<TestCache>> {
        let redis_url = self
            .redis_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Redis not available for testing"))?;

        let test_id = format!("redis_test_{}", uuid::Uuid::new_v4());
        let cache = Arc::new(TestCache::new_redis(redis_url, &test_id).await?);

        {
            let mut caches = self.caches.lock().await;
            caches.push(cache.clone());
        }

        Ok(cache)
    }

    pub async fn create_multi_level_cache(&self, memory_capacity: usize) -> Result<Arc<TestCache>> {
        let test_id = format!("multi_test_{}", uuid::Uuid::new_v4());
        let cache = Arc::new(
            TestCache::new_multi_level(self.redis_url.as_deref(), memory_capacity, &test_id)
                .await?,
        );

        {
            let mut caches = self.caches.lock().await;
            caches.push(cache.clone());
        }

        Ok(cache)
    }

    pub fn redis_available(&self) -> bool {
        self.redis_url.is_some()
    }

    pub async fn cleanup_all(&self) -> Result<()> {
        info!("Cleaning up all test caches");

        let caches = {
            let mut caches_guard = self.caches.lock().await;
            let caches = caches_guard.clone();
            caches_guard.clear();
            caches
        };

        for cache in caches {
            if let Err(e) = cache.cleanup().await {
                warn!("Failed to cleanup cache {}: {}", cache.test_id, e);
            }
        }

        info!("All test caches cleaned up");
        Ok(())
    }
}

/// Cache operation test helpers
pub struct CacheTestHelpers;

impl CacheTestHelpers {
    /// Test basic cache operations (set, get, delete)
    pub async fn test_basic_operations(cache: &Arc<dyn CacheProvider>) -> Result<()> {
        // Test set and get
        cache
            .set("test_key", "test_value", Duration::from_secs(60))
            .await?;
        let value = cache.get("test_key").await?;
        assert_eq!(value, Some("test_value".to_string()));

        // Test overwrite
        cache
            .set("test_key", "new_value", Duration::from_secs(60))
            .await?;
        let value = cache.get("test_key").await?;
        assert_eq!(value, Some("new_value".to_string()));

        // Test delete
        cache.delete("test_key").await?;
        let value = cache.get("test_key").await?;
        assert_eq!(value, None);

        // Test non-existent key
        let value = cache.get("non_existent").await?;
        assert_eq!(value, None);

        Ok(())
    }

    /// Test TTL (Time To Live) functionality
    pub async fn test_ttl_expiration(cache: &Arc<dyn CacheProvider>) -> Result<()> {
        // Set with short TTL
        cache
            .set("ttl_key", "ttl_value", Duration::from_millis(100))
            .await?;

        // Should be available immediately
        let value = cache.get("ttl_key").await?;
        assert_eq!(value, Some("ttl_value".to_string()));

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be expired
        let value = cache.get("ttl_key").await?;
        assert_eq!(value, None);

        Ok(())
    }

    /// Test concurrent access
    pub async fn test_concurrent_access(cache: &Arc<dyn CacheProvider>) -> Result<()> {
        let cache_clone = cache.clone();
        let mut handles = Vec::new();

        // Launch multiple concurrent operations
        for i in 0..10 {
            let cache = cache_clone.clone();
            let handle = tokio::spawn(async move {
                let key = format!("concurrent_key_{}", i);
                let value = format!("concurrent_value_{}", i);

                // Set value
                cache.set(&key, &value, Duration::from_secs(60)).await?;

                // Get value immediately
                let retrieved = cache.get(&key).await?;
                assert_eq!(retrieved, Some(value.clone()));

                // Delete value
                cache.delete(&key).await?;

                Result::<()>::Ok(())
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            handle.await??;
        }

        Ok(())
    }

    /// Test cache statistics
    pub async fn test_cache_statistics(cache: &Arc<dyn CacheProvider>) -> Result<()> {
        // Clear any existing stats
        let _ = cache.clear().await;

        // Perform operations to generate stats
        cache
            .set("stats_key1", "value1", Duration::from_secs(60))
            .await?;
        cache
            .set("stats_key2", "value2", Duration::from_secs(60))
            .await?;

        // Generate hits
        let _ = cache.get("stats_key1").await?;
        let _ = cache.get("stats_key2").await?;

        // Generate misses
        let _ = cache.get("non_existent1").await?;
        let _ = cache.get("non_existent2").await?;

        // Check stats
        let stats = cache.stats().await?;

        // We should have some hits and misses
        assert!(
            stats.total_operations() > 0,
            "Should have recorded operations"
        );
        assert!(stats.hits >= 2, "Should have at least 2 hits");
        assert!(stats.misses >= 2, "Should have at least 2 misses");

        // Hit rate should be reasonable
        let hit_rate = stats.hit_ratio();
        assert!(
            hit_rate >= 0.0 && hit_rate <= 1.0,
            "Hit rate should be between 0 and 1"
        );

        Ok(())
    }

    /// Test cache ping/health check
    pub async fn test_cache_health(cache: &Arc<dyn CacheProvider>) -> Result<()> {
        // Ping should succeed for healthy cache
        cache.ping().await?;
        Ok(())
    }

    /// Test cache clear functionality
    pub async fn test_cache_clear(cache: &Arc<dyn CacheProvider>) -> Result<()> {
        // Set some values
        cache
            .set("clear_key1", "value1", Duration::from_secs(60))
            .await?;
        cache
            .set("clear_key2", "value2", Duration::from_secs(60))
            .await?;

        // Verify they exist
        let value1 = cache.get("clear_key1").await?;
        let value2 = cache.get("clear_key2").await?;
        assert_eq!(value1, Some("value1".to_string()));
        assert_eq!(value2, Some("value2".to_string()));

        // Clear cache
        cache.clear().await?;

        // Values should be gone
        let value1 = cache.get("clear_key1").await?;
        let value2 = cache.get("clear_key2").await?;
        assert_eq!(value1, None);
        assert_eq!(value2, None);

        Ok(())
    }

    /// Test cache with various data sizes
    pub async fn test_data_sizes(cache: &Arc<dyn CacheProvider>) -> Result<()> {
        // Test small value
        let small_value = "small";
        cache
            .set("size_small", small_value, Duration::from_secs(60))
            .await?;
        let retrieved = cache.get("size_small").await?;
        assert_eq!(retrieved, Some(small_value.to_string()));

        // Test medium value (1KB)
        let medium_value = "x".repeat(1024);
        cache
            .set("size_medium", &medium_value, Duration::from_secs(60))
            .await?;
        let retrieved = cache.get("size_medium").await?;
        assert_eq!(retrieved, Some(medium_value));

        // Test large value (100KB)
        let large_value = "y".repeat(100 * 1024);
        cache
            .set("size_large", &large_value, Duration::from_secs(60))
            .await?;
        let retrieved = cache.get("size_large").await?;
        assert_eq!(retrieved, Some(large_value));

        Ok(())
    }

    /// Test cache with special characters and edge cases
    pub async fn test_edge_cases(cache: &Arc<dyn CacheProvider>) -> Result<()> {
        // Test empty value
        cache.set("empty", "", Duration::from_secs(60)).await?;
        let value = cache.get("empty").await?;
        assert_eq!(value, Some("".to_string()));

        // Test Unicode characters
        let unicode_value = "Hello 世界 🌍 こんにちは";
        cache
            .set("unicode", unicode_value, Duration::from_secs(60))
            .await?;
        let value = cache.get("unicode").await?;
        assert_eq!(value, Some(unicode_value.to_string()));

        // Test JSON-like content
        let json_value = r#"{"name": "test", "value": 123, "nested": {"key": "value"}}"#;
        cache
            .set("json", json_value, Duration::from_secs(60))
            .await?;
        let value = cache.get("json").await?;
        assert_eq!(value, Some(json_value.to_string()));

        // Test special characters in keys (if supported)
        let special_key = "test:key:with:colons";
        cache
            .set(special_key, "special_value", Duration::from_secs(60))
            .await?;
        let value = cache.get(special_key).await?;
        assert_eq!(value, Some("special_value".to_string()));

        Ok(())
    }
}
