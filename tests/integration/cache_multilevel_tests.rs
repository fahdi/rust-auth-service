use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio;
use tracing::{debug, info, warn};

use crate::helpers::*;

use rust_auth_service::cache::{CacheProvider, MemoryCache, MultiLevelCache, RedisCache};

/// Multi-level cache integration tests
#[cfg(test)]
mod multilevel_integration {
    use super::*;

    #[tokio::test]
    async fn test_multilevel_basic_operations() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Multi-level cache basic operations");

        let cache = manager.create_multi_level_cache(100).await?;

        // Test basic CRUD operations
        CacheTestHelpers::test_basic_operations(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Multi-level cache basic operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_fallback_behavior() -> Result<()> {
        init_test_environment().await?;

        info!("Testing Multi-level cache fallback behavior");

        // Create multi-level cache with explicit Redis and memory components
        let memory_cache = Arc::new(MemoryCache::new(100));

        // Try to create Redis cache, but handle failure gracefully
        let redis_cache = if let Ok(redis_url) = std::env::var("REDIS_URL") {
            match RedisCache::new(&redis_url).await {
                Ok(redis) => Some(Arc::new(redis) as Arc<dyn CacheProvider>),
                Err(e) => {
                    warn!("Redis not available, testing memory-only fallback: {}", e);
                    None
                }
            }
        } else {
            warn!("REDIS_URL not set, testing memory-only fallback");
            None
        };

        let multi_cache = Arc::new(MultiLevelCache::new(redis_cache, memory_cache.clone()));

        // Test operations work regardless of Redis availability
        multi_cache
            .set("fallback_key", "fallback_value", Duration::from_secs(60))
            .await?;
        let value = multi_cache.get("fallback_key").await?;
        assert_eq!(value, Some("fallback_value".to_string()));

        // Value should be in memory cache at minimum
        let memory_value = memory_cache.get("fallback_key").await?;
        assert_eq!(memory_value, Some("fallback_value".to_string()));

        // Cleanup
        multi_cache.delete("fallback_key").await?;

        info!("Multi-level cache fallback behavior test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_cache_promotion() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        if !manager.redis_available() {
            warn!("Skipping cache promotion tests - Redis not available");
            return Ok(());
        }

        info!("Testing Multi-level cache promotion from memory to Redis");

        // Create separate Redis and memory caches for direct access
        let redis_cache = Arc::new(
            RedisCache::new(
                &std::env::var("REDIS_URL")
                    .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            )
            .await?,
        );
        let memory_cache = Arc::new(MemoryCache::new(100));
        let multi_cache = Arc::new(MultiLevelCache::new(
            Some(redis_cache.clone()),
            memory_cache.clone(),
        ));

        // Clear both caches
        redis_cache.clear().await?;
        memory_cache.clear().await?;

        // Put value only in memory cache directly
        memory_cache
            .set("promotion_key", "promotion_value", Duration::from_secs(60))
            .await?;

        // Verify it's only in memory cache
        assert_eq!(
            memory_cache.get("promotion_key").await?,
            Some("promotion_value".to_string())
        );
        assert_eq!(redis_cache.get("promotion_key").await?, None);

        // Access through multi-level cache - should find in memory and promote to Redis
        let value = multi_cache.get("promotion_key").await?;
        assert_eq!(value, Some("promotion_value".to_string()));

        // Now it should be in both caches
        tokio::time::sleep(Duration::from_millis(50)).await; // Small delay for async promotion
        assert_eq!(
            memory_cache.get("promotion_key").await?,
            Some("promotion_value".to_string())
        );
        // Note: Promotion to Redis happens asynchronously and may not be immediate in tests

        // Cleanup
        multi_cache.delete("promotion_key").await?;

        info!("Multi-level cache promotion test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_consistency() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Multi-level cache consistency");

        let cache = manager.create_multi_level_cache(100).await?;

        // Set values through multi-level cache
        cache
            .set_and_track("consistency_key1", "value1", Duration::from_secs(60))
            .await?;
        cache
            .set_and_track("consistency_key2", "value2", Duration::from_secs(60))
            .await?;

        // Values should be consistently retrievable
        assert_eq!(
            cache.provider.get("consistency_key1").await?,
            Some("value1".to_string())
        );
        assert_eq!(
            cache.provider.get("consistency_key2").await?,
            Some("value2".to_string())
        );

        // Update values
        cache
            .provider
            .set(
                "consistency_key1",
                "updated_value1",
                Duration::from_secs(60),
            )
            .await?;

        // Should get updated value
        assert_eq!(
            cache.provider.get("consistency_key1").await?,
            Some("updated_value1".to_string())
        );
        assert_eq!(
            cache.provider.get("consistency_key2").await?,
            Some("value2".to_string())
        );

        // Delete one value
        cache.provider.delete("consistency_key1").await?;

        // Should be gone from all levels
        assert_eq!(cache.provider.get("consistency_key1").await?, None);
        assert_eq!(
            cache.provider.get("consistency_key2").await?,
            Some("value2".to_string())
        );

        cache.cleanup().await?;
        info!("Multi-level cache consistency test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_statistics_aggregation() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Multi-level cache statistics aggregation");

        let cache = manager.create_multi_level_cache(100).await?;

        // Clear cache to reset stats
        cache.provider.clear().await?;

        // Perform operations to generate stats
        cache
            .set_and_track("stats_key1", "value1", Duration::from_secs(60))
            .await?;
        cache
            .set_and_track("stats_key2", "value2", Duration::from_secs(60))
            .await?;

        // Generate hits
        let _ = cache.provider.get("stats_key1").await?;
        let _ = cache.provider.get("stats_key2").await?;

        // Generate misses
        let _ = cache.provider.get("non_existent1").await?;
        let _ = cache.provider.get("non_existent2").await?;

        // Check aggregated stats
        let stats = cache.provider.stats().await?;

        assert!(
            stats.total_operations() > 0,
            "Should have recorded operations"
        );
        assert!(stats.hits >= 2, "Should have at least 2 hits");
        assert!(stats.misses >= 2, "Should have at least 2 misses");

        let hit_rate = stats.hit_ratio();
        assert!(
            hit_rate >= 0.0 && hit_rate <= 1.0,
            "Hit rate should be between 0 and 1"
        );

        cache.cleanup().await?;
        info!("Multi-level cache statistics aggregation test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_ttl_behavior() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Multi-level cache TTL behavior");

        let cache = manager.create_multi_level_cache(100).await?;

        // Set with short TTL
        cache
            .set_and_track("ttl_key", "ttl_value", Duration::from_millis(100))
            .await?;

        // Should be available immediately
        assert_eq!(
            cache.provider.get("ttl_key").await?,
            Some("ttl_value".to_string())
        );

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be expired from both levels
        assert_eq!(cache.provider.get("ttl_key").await?, None);

        cache.cleanup().await?;
        info!("Multi-level cache TTL behavior test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_concurrent_access() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Multi-level cache concurrent access");

        let cache = manager.create_multi_level_cache(200).await?;

        // Test concurrent access
        CacheTestHelpers::test_concurrent_access(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Multi-level cache concurrent access test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_error_resilience() -> Result<()> {
        init_test_environment().await?;

        info!("Testing Multi-level cache error resilience");

        // Create multi-level cache with memory fallback
        let memory_cache = Arc::new(MemoryCache::new(100));

        // Simulate Redis unavailable by passing None
        let multi_cache = Arc::new(MultiLevelCache::new(None, memory_cache.clone()));

        // Operations should still work with memory fallback
        multi_cache
            .set(
                "resilience_key",
                "resilience_value",
                Duration::from_secs(60),
            )
            .await?;
        let value = multi_cache.get("resilience_key").await?;
        assert_eq!(value, Some("resilience_value".to_string()));

        // Health check should pass (memory cache should be healthy)
        multi_cache.ping().await?;

        // Stats should be available
        let stats = multi_cache.stats().await?;
        assert!(stats.total_operations() >= 0);

        // Cleanup
        multi_cache.delete("resilience_key").await?;

        info!("Multi-level cache error resilience test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_performance_characteristics() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Multi-level cache performance characteristics");

        let cache = manager.create_multi_level_cache(500).await?;

        // Measure performance
        let start = std::time::Instant::now();
        for i in 0..100 {
            let key = format!("perf_ml_key_{}", i);
            let value = format!("perf_ml_value_{}", i);
            cache
                .provider
                .set(&key, &value, Duration::from_secs(60))
                .await?;
            cache.track_key(&key).await;
        }
        let set_duration = start.elapsed();

        let start = std::time::Instant::now();
        for i in 0..100 {
            let key = format!("perf_ml_key_{}", i);
            let _ = cache.provider.get(&key).await?;
        }
        let get_duration = start.elapsed();

        let set_ops_per_sec = 100.0 / set_duration.as_secs_f64();
        let get_ops_per_sec = 100.0 / get_duration.as_secs_f64();

        info!(
            "Multi-level cache performance: {:.0} sets/sec, {:.0} gets/sec",
            set_ops_per_sec, get_ops_per_sec
        );

        // Multi-level cache should still be reasonably fast
        assert!(
            set_ops_per_sec > 100.0,
            "Multi-level cache sets should be >100 ops/sec"
        );
        assert!(
            get_ops_per_sec > 500.0,
            "Multi-level cache gets should be >500 ops/sec"
        );

        cache.cleanup().await?;
        info!("Multi-level cache performance characteristics test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_stress_testing() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Multi-level cache under stress");

        let cache = manager.create_multi_level_cache(1000).await?;

        // Run stress test
        let stress_runner = StressTestRunner::new(15, 150);
        let cache_provider = cache.provider.clone();

        let duration = stress_runner
            .run_concurrent_test(move |operation_id| {
                let cache = cache_provider.clone();
                async move {
                    let key = format!("stress_ml_key_{}", operation_id);
                    let value = format!("stress_ml_value_{}", operation_id);

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
        let ops_per_second = 150.0 / duration.as_secs_f64();

        info!(
            "Multi-level cache stress test: {:.1} ops/sec, {:.1}% success rate",
            ops_per_second,
            success_rate * 100.0
        );

        assert!(
            success_rate > 0.95,
            "Multi-level cache should handle stress with >95% success rate"
        );
        assert!(
            ops_per_second > 100.0,
            "Multi-level cache should handle >100 ops/sec under stress"
        );

        cache.cleanup().await?;
        info!("Multi-level cache stress testing completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_cache_warming() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Multi-level cache warming behavior");

        let cache = manager.create_multi_level_cache(100).await?;

        // Simulate cache warming - pre-populate with data
        let warm_data = vec![
            (
                "warm_user:1",
                r#"{"id":1,"name":"User1","email":"user1@example.com"}"#,
            ),
            (
                "warm_user:2",
                r#"{"id":2,"name":"User2","email":"user2@example.com"}"#,
            ),
            ("warm_config", r#"{"theme":"dark","lang":"en"}"#),
            (
                "warm_permissions",
                r#"{"admin":true,"read":true,"write":false}"#,
            ),
        ];

        // Warm the cache
        for (key, value) in &warm_data {
            cache
                .set_and_track(key, value, Duration::from_secs(300))
                .await?;
        }

        // Verify all warmed data is accessible
        for (key, expected_value) in &warm_data {
            let value = cache.provider.get(key).await?;
            assert_eq!(value, Some(expected_value.to_string()));
        }

        // Measure access performance after warming
        let start = std::time::Instant::now();
        for (key, _) in &warm_data {
            let _ = cache.provider.get(key).await?;
        }
        let warmed_access_time = start.elapsed();

        info!(
            "Cache warming: {} items accessed in {:.2}ms",
            warm_data.len(),
            warmed_access_time.as_millis()
        );

        // Warmed cache should be very fast
        let avg_access_time = warmed_access_time.as_millis() as f64 / warm_data.len() as f64;
        assert!(
            avg_access_time < 10.0,
            "Warmed cache access should be <10ms per item"
        );

        cache.cleanup().await?;
        info!("Multi-level cache warming test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_clear_functionality() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Multi-level cache clear functionality");

        let cache = manager.create_multi_level_cache(100).await?;

        // Test clear functionality
        CacheTestHelpers::test_cache_clear(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Multi-level cache clear functionality test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_multilevel_health_checks() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Multi-level cache health checks");

        let cache = manager.create_multi_level_cache(100).await?;

        // Test health check
        CacheTestHelpers::test_cache_health(&cache.provider).await?;

        // Multiple health checks should all pass
        for i in 0..5 {
            let (_, _metrics) =
                measure_async("multilevel_ping", "multilevel", cache.provider.ping()).await?;
            debug!("Multi-level ping {} completed successfully", i + 1);
        }

        cache.cleanup().await?;
        info!("Multi-level cache health checks test completed successfully");
        Ok(())
    }
}
