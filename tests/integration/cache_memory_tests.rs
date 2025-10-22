use anyhow::Result;
use std::time::Duration;
use tokio;
use tracing::info;

use crate::helpers::*;

use rust_auth_service::cache::{CacheProvider, MemoryCache};

/// Memory cache specific integration tests
#[cfg(test)]
mod memory_integration {
    use super::*;

    #[tokio::test]
    async fn test_memory_basic_operations() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache basic operations");

        let cache = manager.create_memory_cache(100).await;

        // Test basic CRUD operations
        CacheTestHelpers::test_basic_operations(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Memory cache basic operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_ttl_expiration() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache TTL expiration");

        let cache = manager.create_memory_cache(100).await;

        // Test TTL functionality
        CacheTestHelpers::test_ttl_expiration(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Memory cache TTL expiration test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_lru_eviction() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache LRU eviction");

        // Create small cache to force eviction
        let cache = manager.create_memory_cache(3).await;

        // Fill cache to capacity
        cache
            .set_and_track("key1", "value1", Duration::from_secs(300))
            .await?;
        cache
            .set_and_track("key2", "value2", Duration::from_secs(300))
            .await?;
        cache
            .set_and_track("key3", "value3", Duration::from_secs(300))
            .await?;

        // All should be present
        assert_eq!(
            cache.provider.get("key1").await?,
            Some("value1".to_string())
        );
        assert_eq!(
            cache.provider.get("key2").await?,
            Some("value2".to_string())
        );
        assert_eq!(
            cache.provider.get("key3").await?,
            Some("value3".to_string())
        );

        // Add one more to trigger eviction of least recently used (key1)
        cache
            .set_and_track("key4", "value4", Duration::from_secs(300))
            .await?;

        // key1 should be evicted
        assert_eq!(cache.provider.get("key1").await?, None);
        assert_eq!(
            cache.provider.get("key2").await?,
            Some("value2".to_string())
        );
        assert_eq!(
            cache.provider.get("key3").await?,
            Some("value3".to_string())
        );
        assert_eq!(
            cache.provider.get("key4").await?,
            Some("value4".to_string())
        );

        // Access key2 to make it recently used
        let _ = cache.provider.get("key2").await?;

        // Add another key, should evict key3 (now least recently used)
        cache
            .set_and_track("key5", "value5", Duration::from_secs(300))
            .await?;

        assert_eq!(
            cache.provider.get("key2").await?,
            Some("value2".to_string())
        );
        assert_eq!(cache.provider.get("key3").await?, None);
        assert_eq!(
            cache.provider.get("key4").await?,
            Some("value4".to_string())
        );
        assert_eq!(
            cache.provider.get("key5").await?,
            Some("value5".to_string())
        );

        cache.cleanup().await?;
        info!("Memory cache LRU eviction test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_concurrent_operations() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache concurrent operations");

        let cache = manager.create_memory_cache(1000).await;

        // Test concurrent access
        CacheTestHelpers::test_concurrent_access(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Memory cache concurrent operations test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_statistics_tracking() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache statistics tracking");

        let cache = manager.create_memory_cache(100).await;

        // Test statistics
        CacheTestHelpers::test_cache_statistics(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Memory cache statistics tracking test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_capacity_limits() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache capacity limits");

        // Test with very small capacity
        let cache = manager.create_memory_cache(5).await;

        // Add items up to capacity
        for i in 0..5 {
            let key = format!("capacity_key_{}", i);
            let value = format!("capacity_value_{}", i);
            cache
                .set_and_track(&key, &value, Duration::from_secs(300))
                .await?;
        }

        // All items should be present
        for i in 0..5 {
            let key = format!("capacity_key_{}", i);
            let expected_value = format!("capacity_value_{}", i);
            let value = cache.provider.get(&key).await?;
            assert_eq!(value, Some(expected_value));
        }

        // Add more items to force eviction
        for i in 5..10 {
            let key = format!("capacity_key_{}", i);
            let value = format!("capacity_value_{}", i);
            cache
                .set_and_track(&key, &value, Duration::from_secs(300))
                .await?;
        }

        // Check that only latest 5 items remain (LRU eviction)
        let mut present_count = 0;
        for i in 0..10 {
            let key = format!("capacity_key_{}", i);
            if cache.provider.get(&key).await?.is_some() {
                present_count += 1;
            }
        }

        assert_eq!(
            present_count, 5,
            "Cache should maintain exactly capacity limit"
        );

        cache.cleanup().await?;
        info!("Memory cache capacity limits test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_ttl_cleanup() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache TTL cleanup");

        let cache = manager.create_memory_cache(100).await;

        // Set items with different TTLs
        cache
            .set_and_track("short_ttl", "short_value", Duration::from_millis(50))
            .await?;
        cache
            .set_and_track("medium_ttl", "medium_value", Duration::from_millis(200))
            .await?;
        cache
            .set_and_track("long_ttl", "long_value", Duration::from_secs(300))
            .await?;

        // All should be present initially
        assert_eq!(
            cache.provider.get("short_ttl").await?,
            Some("short_value".to_string())
        );
        assert_eq!(
            cache.provider.get("medium_ttl").await?,
            Some("medium_value".to_string())
        );
        assert_eq!(
            cache.provider.get("long_ttl").await?,
            Some("long_value".to_string())
        );

        // Wait for short TTL to expire
        tokio::time::sleep(Duration::from_millis(75)).await;

        assert_eq!(cache.provider.get("short_ttl").await?, None);
        assert_eq!(
            cache.provider.get("medium_ttl").await?,
            Some("medium_value".to_string())
        );
        assert_eq!(
            cache.provider.get("long_ttl").await?,
            Some("long_value".to_string())
        );

        // Wait for medium TTL to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(cache.provider.get("short_ttl").await?, None);
        assert_eq!(cache.provider.get("medium_ttl").await?, None);
        assert_eq!(
            cache.provider.get("long_ttl").await?,
            Some("long_value".to_string())
        );

        cache.cleanup().await?;
        info!("Memory cache TTL cleanup test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_large_data_handling() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache large data handling");

        let cache = manager.create_memory_cache(10).await;

        // Test various data sizes
        CacheTestHelpers::test_data_sizes(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Memory cache large data handling test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_edge_cases() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache edge cases");

        let cache = manager.create_memory_cache(100).await;

        // Test edge cases
        CacheTestHelpers::test_edge_cases(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Memory cache edge cases test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_performance_characteristics() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache performance characteristics");

        let cache = manager.create_memory_cache(1000).await;

        // Measure set performance
        let start = std::time::Instant::now();
        for i in 0..100 {
            let key = format!("perf_key_{}", i);
            let value = format!("perf_value_{}", i);
            cache
                .provider
                .set(&key, &value, Duration::from_secs(60))
                .await?;
            cache.track_key(&key).await;
        }
        let set_duration = start.elapsed();

        // Measure get performance
        let start = std::time::Instant::now();
        for i in 0..100 {
            let key = format!("perf_key_{}", i);
            let _ = cache.provider.get(&key).await?;
        }
        let get_duration = start.elapsed();

        let set_ops_per_sec = 100.0 / set_duration.as_secs_f64();
        let get_ops_per_sec = 100.0 / get_duration.as_secs_f64();

        info!(
            "Memory cache performance: {:.0} sets/sec, {:.0} gets/sec",
            set_ops_per_sec, get_ops_per_sec
        );

        // Memory cache should be very fast
        assert!(
            set_ops_per_sec > 1000.0,
            "Memory cache sets should be >1000 ops/sec"
        );
        assert!(
            get_ops_per_sec > 5000.0,
            "Memory cache gets should be >5000 ops/sec"
        );

        cache.cleanup().await?;
        info!("Memory cache performance characteristics test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_stress_testing() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache under stress");

        let cache = manager.create_memory_cache(500).await;

        // Run stress test with concurrent operations
        let stress_runner = StressTestRunner::new(20, 200);
        let cache_provider = cache.provider.clone();

        let duration = stress_runner
            .run_concurrent_test(move |operation_id| {
                let cache = cache_provider.clone();
                async move {
                    let key = format!("stress_mem_key_{}", operation_id);
                    let value = format!("stress_mem_value_{}", operation_id);

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
        let ops_per_second = 200.0 / duration.as_secs_f64();

        info!(
            "Memory cache stress test: {:.1} ops/sec, {:.1}% success rate",
            ops_per_second,
            success_rate * 100.0
        );

        assert!(
            success_rate > 0.98,
            "Memory cache should handle stress with >98% success rate"
        );
        assert!(
            ops_per_second > 500.0,
            "Memory cache should handle >500 ops/sec under stress"
        );

        cache.cleanup().await?;
        info!("Memory cache stress testing completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_clear_functionality() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache clear functionality");

        let cache = manager.create_memory_cache(100).await;

        // Test clear functionality
        CacheTestHelpers::test_cache_clear(&cache.provider).await?;

        cache.cleanup().await?;
        info!("Memory cache clear functionality test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_zero_capacity_edge_case() -> Result<()> {
        init_test_environment().await?;

        info!("Testing Memory cache with zero/minimal capacity");

        // Test with capacity 1 (minimum allowed)
        let cache = std::sync::Arc::new(MemoryCache::new(1));

        // Should be able to store one item
        cache
            .set("single_key", "single_value", Duration::from_secs(60))
            .await?;
        let value = cache.get("single_key").await?;
        assert_eq!(value, Some("single_value".to_string()));

        // Adding another should evict the first
        cache
            .set("second_key", "second_value", Duration::from_secs(60))
            .await?;

        assert_eq!(cache.get("single_key").await?, None);
        assert_eq!(
            cache.get("second_key").await?,
            Some("second_value".to_string())
        );

        info!("Memory cache zero/minimal capacity test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_memory_update_existing_keys() -> Result<()> {
        init_test_environment().await?;
        let manager = CacheTestManager::new();

        info!("Testing Memory cache update existing keys");

        let cache = manager.create_memory_cache(10).await;

        // Set initial value
        cache
            .set_and_track("update_key", "initial_value", Duration::from_secs(60))
            .await?;
        assert_eq!(
            cache.provider.get("update_key").await?,
            Some("initial_value".to_string())
        );

        // Update with new value
        cache
            .provider
            .set("update_key", "updated_value", Duration::from_secs(60))
            .await?;
        assert_eq!(
            cache.provider.get("update_key").await?,
            Some("updated_value".to_string())
        );

        // Update with different TTL
        cache
            .provider
            .set("update_key", "final_value", Duration::from_millis(100))
            .await?;
        assert_eq!(
            cache.provider.get("update_key").await?,
            Some("final_value".to_string())
        );

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(cache.provider.get("update_key").await?, None);

        cache.cleanup().await?;
        info!("Memory cache update existing keys test completed successfully");
        Ok(())
    }
}
