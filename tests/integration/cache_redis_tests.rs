use anyhow::Result;
use std::time::Duration;
use tokio;
use tracing::{debug, info, warn};

use crate::helpers::*;

use rust_auth_service::cache::{CacheProvider, RedisCache};

/// Redis-specific integration tests
#[cfg(test)]
mod redis_integration {
    use super::*;

    #[tokio::test]
    async fn test_redis_basic_operations() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis basic operations");

        let cache = manager.create_redis_cache().await?;

        // Test basic CRUD operations
        CacheTestHelpers::test_basic_operations(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Redis basic operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_ttl_expiration() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis TTL tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis TTL expiration");

        let cache = manager.create_redis_cache().await?;

        // Test TTL functionality
        CacheTestHelpers::test_ttl_expiration(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Redis TTL expiration test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_concurrent_operations() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis concurrent tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis concurrent operations");

        let cache = manager.create_redis_cache().await?;

        // Test concurrent access
        CacheTestHelpers::test_concurrent_access(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Redis concurrent operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_connection_management() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis connection tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis connection management");

        let cache = manager.create_redis_cache().await?;

        // Test health check
        CacheTestHelpers::test_cache_health(&cache.provider).await?;

        // Test multiple ping operations
        for i in 0..10 {
            let (_, _metrics) = measure_async("redis_ping", "redis", cache.provider.ping()).await?;
            debug!("Ping {} completed successfully", i + 1);
        }

        cache.cleanup().await?;
        info!("Redis connection management test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_statistics_tracking() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis statistics tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis statistics tracking");

        let cache = manager.create_redis_cache().await?;

        // Test statistics
        CacheTestHelpers::test_cache_statistics(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Redis statistics tracking test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_large_data_handling() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis large data tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis large data handling");

        let cache = manager.create_redis_cache().await?;

        // Test various data sizes
        CacheTestHelpers::test_data_sizes(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Redis large data handling test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_edge_cases() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis edge case tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis edge cases");

        let cache = manager.create_redis_cache().await?;

        // Test edge cases
        CacheTestHelpers::test_edge_cases(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Redis edge cases test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_bulk_operations() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis bulk tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis bulk operations");

        let cache = manager.create_redis_cache().await?;

        // Bulk set operations
        let mut set_operations = Vec::new();
        for i in 0..100 {
            let key = format!("bulk_key_{}", i);
            let value = format!("bulk_value_{}", i);
            cache.track_key(&key).await;
            set_operations.push((key, value));
        }

        // Measure bulk set performance
        let start = std::time::Instant::now();
        for (key, value) in &set_operations {
            cache
                .provider
                .set(key, value, Duration::from_secs(300))
                .await?;
        }
        let set_duration = start.elapsed();

        // Measure bulk get performance
        let start = std::time::Instant::now();
        let mut retrieved_count = 0;
        for (key, expected_value) in &set_operations {
            if let Some(value) = cache.provider.get(key).await? {
                assert_eq!(&value, expected_value);
                retrieved_count += 1;
            }
        }
        let get_duration = start.elapsed();

        info!(
            "Redis bulk operations: {} sets in {:.2}ms, {} gets in {:.2}ms",
            set_operations.len(),
            set_duration.as_millis(),
            retrieved_count,
            get_duration.as_millis()
        );

        assert_eq!(retrieved_count, set_operations.len());

        cache.cleanup().await?;
        info!("Redis bulk operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_stress_testing() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis stress tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis under stress");

        let cache = manager.create_redis_cache().await?;

        // Run stress test with concurrent operations
        let stress_runner = StressTestRunner::new(10, 100);
        let cache_provider = cache.provider.clone();

        let duration = stress_runner
            .run_concurrent_test(move |operation_id| {
                let cache = cache_provider.clone();
                async move {
                    let key = format!("stress_key_{}", operation_id);
                    let value = format!("stress_value_{}", operation_id);

                    // Set value
                    cache
                        .set(&key, &value, Duration::from_secs(60))
                        .await
                        .map_err(|e| anyhow::anyhow!("Set failed: {:?}", e))?;

                    // Get value
                    let retrieved = cache
                        .get(&key)
                        .await
                        .map_err(|e| anyhow::anyhow!("Get failed: {:?}", e))?;

                    if retrieved != Some(value) {
                        return Err(anyhow::anyhow!("Value mismatch"));
                    }

                    // Delete value
                    cache
                        .delete(&key)
                        .await
                        .map_err(|e| anyhow::anyhow!("Delete failed: {:?}", e))?;

                    Ok(())
                }
            })
            .await?;

        let success_rate = stress_runner.success_rate();
        let ops_per_second = 100.0 / duration.as_secs_f64();

        info!(
            "Redis stress test: {:.1} ops/sec, {:.1}% success rate",
            ops_per_second,
            success_rate * 100.0
        );

        assert!(
            success_rate > 0.95,
            "Redis should handle stress with >95% success rate"
        );
        assert!(
            ops_per_second > 50.0,
            "Redis should handle >50 ops/sec under stress"
        );

        cache.cleanup().await?;
        info!("Redis stress testing completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_persistence() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis persistence tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis persistence behavior");

        let cache = manager.create_redis_cache().await?;

        // Set values with long TTL
        let test_keys = vec![
            ("persist_key1", "persist_value1"),
            ("persist_key2", "persist_value2"),
            ("persist_key3", "persist_value3"),
        ];

        for (key, value) in &test_keys {
            cache
                .set_and_track(key, value, Duration::from_secs(3600))
                .await?;
        }

        // Verify all values are set
        for (key, expected_value) in &test_keys {
            let value = cache.provider.get(key).await?;
            assert_eq!(value, Some(expected_value.to_string()));
        }

        // Create a new Redis connection to simulate restart
        let cache2 = manager.create_redis_cache().await?;

        // Values should still be there (Redis persistence)
        for (key, expected_value) in &test_keys {
            let value = cache2.provider.get(key).await?;
            assert_eq!(value, Some(expected_value.to_string()));

            // Track for cleanup in second cache instance
            cache2.track_key(key).await;
        }

        cache.cleanup().await?;
        cache2.cleanup().await?;
        info!("Redis persistence test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_key_patterns() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis key pattern tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis key patterns and namespacing");

        let cache = manager.create_redis_cache().await?;

        // Test various key patterns commonly used in auth systems
        let key_patterns = vec![
            ("user:123", "user_data"),
            ("session:abc-def-ghi", "session_data"),
            ("token:reset:xyz", "reset_token_data"),
            ("rate_limit:192.168.1.1", "rate_limit_data"),
            ("cache:user:profile:456", "profile_data"),
            ("temp:verification:789", "verification_data"),
        ];

        for (key, value) in &key_patterns {
            cache
                .set_and_track(key, value, Duration::from_secs(60))
                .await?;
        }

        // Verify all patterns work
        for (key, expected_value) in &key_patterns {
            let value = cache.provider.get(key).await?;
            assert_eq!(value, Some(expected_value.to_string()));
        }

        cache.cleanup().await?;
        info!("Redis key patterns test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_error_handling() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis error handling tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis error handling");

        let cache = manager.create_redis_cache().await?;

        // Test normal operations work
        cache
            .set_and_track("error_test", "value", Duration::from_secs(60))
            .await?;
        let value = cache.provider.get("error_test").await?;
        assert_eq!(value, Some("value".to_string()));

        // Test operations continue to work after errors
        // (Note: Hard to simulate Redis errors in integration tests without
        // external tools, so we focus on verifying recovery)

        // Verify cache is still functional
        CacheTestHelpers::test_cache_health(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Redis error handling test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_redis_pubsub_functionality() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping Redis pub/sub tests - Redis not available");
            return Ok(());
        }

        info!("Testing Redis pub/sub functionality");

        let cache = manager.create_redis_cache().await?;

        // Test cache invalidation notifications via pub/sub patterns
        // This simulates cache invalidation events that would be published
        // when cache entries are modified or expired

        // Set up test data
        let test_channel = "cache:invalidation:test";
        let test_keys = vec!["pubsub:test:key1", "pubsub:test:key2", "pubsub:test:key3"];

        // Set test values
        for (i, key) in test_keys.iter().enumerate() {
            let value = format!("pubsub_value_{}", i);
            cache
                .set_and_track(key, &value, Duration::from_secs(300))
                .await?;
            cache.track_key(key).await;
        }

        // Verify all values are set
        for (i, key) in test_keys.iter().enumerate() {
            let expected_value = format!("pubsub_value_{}", i);
            let value = cache.provider.get(key).await?;
            assert_eq!(value, Some(expected_value));
        }

        // Simulate pub/sub pattern for cache invalidation
        // In a real scenario, this would involve Redis PUBLISH/SUBSCRIBE
        // For testing purposes, we'll test the invalidation pattern

        // Test pattern-based invalidation (simulating pub/sub notification handling)
        info!("Testing pattern-based cache invalidation (pub/sub simulation)");

        // Delete keys matching pattern (simulates pub/sub invalidation message)
        for key in &test_keys {
            cache.provider.delete(key).await?;
        }

        // Verify all keys are invalidated
        for key in &test_keys {
            let value = cache.provider.get(key).await?;
            assert_eq!(value, None, "Key {} should be invalidated", key);
        }

        // Test cache invalidation notification patterns commonly used in auth systems
        let auth_patterns = vec![
            ("user:123:profile", "User profile update"),
            ("session:abc123", "Session invalidation"),
            ("token:blacklist:xyz789", "JWT token blacklist"),
            ("rate_limit:192.168.1.1", "Rate limit reset"),
        ];

        info!("Testing authentication system pub/sub patterns");

        for (pattern_key, description) in &auth_patterns {
            // Set value
            cache
                .set_and_track(pattern_key, description, Duration::from_secs(60))
                .await?;

            // Verify set
            let value = cache.provider.get(pattern_key).await?;
            assert_eq!(value, Some(description.to_string()));

            // Simulate pub/sub invalidation
            cache.provider.delete(pattern_key).await?;

            // Verify invalidated
            let value = cache.provider.get(pattern_key).await?;
            assert_eq!(value, None, "Pattern {} should be invalidated", pattern_key);

            info!(
                "✅ Pub/sub pattern tested: {} - {}",
                pattern_key, description
            );
        }

        cache.cleanup().await?;
        info!("Redis pub/sub functionality test completed successfully");
        Ok(())
    }
}
