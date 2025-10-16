use super::{CacheProvider, CacheStats};
use anyhow::{Context, Result};
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub struct RedisCache {
    connection_manager: ConnectionManager,
    stats: Arc<RwLock<CacheStats>>,
    redis_url: String,
}

impl RedisCache {
    pub async fn new(redis_url: &str) -> Result<Self> {
        info!("Connecting to Redis at: {}", redis_url);

        let client = Client::open(redis_url).context("Failed to create Redis client")?;

        let connection_manager = ConnectionManager::new(client)
            .await
            .context("Failed to create Redis connection manager")?;

        // Test the connection
        let mut conn = connection_manager.clone();
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .context("Failed to ping Redis server")?;

        info!("Successfully connected to Redis");

        Ok(Self {
            connection_manager,
            stats: Arc::new(RwLock::new(CacheStats::new())),
            redis_url: redis_url.to_string(),
        })
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
}

#[async_trait]
impl CacheProvider for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        let mut conn = self.connection_manager.clone();

        match conn.get::<_, Option<String>>(key).await {
            Ok(Some(value)) => {
                self.record_hit().await;
                Ok(Some(value))
            }
            Ok(None) => {
                self.record_miss().await;
                Ok(None)
            }
            Err(e) => {
                self.record_miss().await;
                error!("Redis GET error for key '{}': {}", key, e);
                Err(anyhow::anyhow!("Redis GET failed: {}", e))
            }
        }
    }

    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<()> {
        let mut conn = self.connection_manager.clone();

        let ttl_seconds = ttl.as_secs();
        if ttl_seconds == 0 {
            warn!(
                "Setting Redis key '{}' with 0 TTL, using default 1 hour",
                key
            );
            conn.set_ex::<_, _, ()>(key, value, 3600).await
        } else {
            conn.set_ex(key, value, ttl_seconds).await
        }
        .with_context(|| format!("Failed to set Redis key '{}'", key))?;

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut conn = self.connection_manager.clone();

        let deleted: i32 = conn
            .del(key)
            .await
            .with_context(|| format!("Failed to delete Redis key '{}'", key))?;

        if deleted == 0 {
            warn!("Redis key '{}' was not found during deletion", key);
        }

        Ok(())
    }

    async fn ping(&self) -> Result<()> {
        let mut conn = self.connection_manager.clone();

        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .context("Redis ping failed")?;

        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        let mut conn = self.connection_manager.clone();

        let _: String = redis::cmd("FLUSHDB")
            .query_async(&mut conn)
            .await
            .context("Failed to clear Redis database")?;

        // Reset stats
        let mut stats = self.stats.write().await;
        *stats = CacheStats::new();

        Ok(())
    }

    async fn stats(&self) -> Result<CacheStats> {
        let mut conn = self.connection_manager.clone();

        // Get Redis database size
        let db_size: usize = redis::cmd("DBSIZE")
            .query_async(&mut conn)
            .await
            .unwrap_or(0);

        let stats = self.stats.read().await;
        Ok(CacheStats {
            hits: stats.hits,
            misses: stats.misses,
            size: db_size,
            hit_rate: stats.hit_rate,
        })
    }
}

/// Redis connection pool for high-performance scenarios
#[allow(dead_code)]
pub struct RedisPool {
    client: Client,
    #[allow(dead_code)]
    pool_size: usize,
}

impl RedisPool {
    #[allow(dead_code)]
    pub fn new(redis_url: &str, pool_size: usize) -> Result<Self> {
        let client = Client::open(redis_url).context("Failed to create Redis client")?;

        Ok(Self { client, pool_size })
    }

    #[allow(dead_code)]
    pub async fn get_connection(&self) -> Result<ConnectionManager> {
        ConnectionManager::new(self.client.clone())
            .await
            .context("Failed to get Redis connection from pool")
    }
}

/// Redis Pub/Sub for cache invalidation
#[allow(dead_code)]
pub struct RedisPubSub {
    connection_manager: ConnectionManager,
    redis_url: String,
}

impl RedisPubSub {
    #[allow(dead_code)]
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client =
            Client::open(redis_url).context("Failed to create Redis client for Pub/Sub")?;

        let connection_manager = ConnectionManager::new(client)
            .await
            .context("Failed to create Redis connection manager for Pub/Sub")?;

        Ok(Self {
            connection_manager,
            redis_url: redis_url.to_string(),
        })
    }

    #[allow(dead_code)]
    pub async fn publish(&self, channel: &str, message: &str) -> Result<()> {
        let mut conn = self.connection_manager.clone();

        let _: i32 = conn
            .publish(channel, message)
            .await
            .with_context(|| format!("Failed to publish to Redis channel '{}'", channel))?;

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn subscribe(&self, channels: &[&str]) -> Result<redis::aio::PubSub> {
        // Get a fresh connection for PubSub using the configured Redis URL
        let client = Client::open(self.redis_url.as_str())?;
        let conn = client.get_async_connection().await?;
        let mut pubsub = conn.into_pubsub();

        for channel in channels {
            pubsub
                .subscribe(channel)
                .await
                .with_context(|| format!("Failed to subscribe to Redis channel '{}'", channel))?;
        }

        Ok(pubsub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    async fn get_test_redis() -> Result<RedisCache> {
        let redis_url =
            env::var("REDIS_TEST_URL").unwrap_or_else(|_| "redis://localhost:6379/15".to_string()); // Use DB 15 for tests

        RedisCache::new(&redis_url).await
    }

    #[tokio::test]
    #[ignore] // Requires Redis instance
    async fn test_redis_cache_operations() {
        let cache = get_test_redis().await.unwrap();

        // Clear test database
        cache.clear().await.unwrap();

        // Test set and get
        cache
            .set("test_key", "test_value", Duration::from_secs(60))
            .await
            .unwrap();
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

        // Test stats
        let stats = cache.stats().await.unwrap();
        assert!(stats.hits > 0 || stats.misses > 0);
    }

    #[tokio::test]
    #[ignore] // Requires Redis instance
    async fn test_redis_ttl() {
        let cache = get_test_redis().await.unwrap();

        // Set with short TTL
        cache
            .set("ttl_test", "value", Duration::from_millis(100))
            .await
            .unwrap();

        // Should exist immediately
        let value = cache.get("ttl_test").await.unwrap();
        assert_eq!(value, Some("value".to_string()));

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be expired
        let expired = cache.get("ttl_test").await.unwrap();
        assert_eq!(expired, None);
    }

    #[tokio::test]
    #[ignore] // Requires Redis instance
    async fn test_redis_pubsub() {
        let redis_url =
            env::var("REDIS_TEST_URL").unwrap_or_else(|_| "redis://localhost:6379/15".to_string());

        let pubsub = RedisPubSub::new(&redis_url).await.unwrap();

        // Test publish (subscriber test would need async coordination)
        pubsub
            .publish("test_channel", "test_message")
            .await
            .unwrap();
    }
}
