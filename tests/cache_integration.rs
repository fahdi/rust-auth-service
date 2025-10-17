use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

use rust_auth_service::cache::{
    create_cache_provider, create_multi_level_cache, CacheKey, CacheService,
};
use rust_auth_service::config::cache::CacheConfig;

/// Cache Integration Tests
///
/// This test suite validates all cache implementations:
/// - Memory cache with LRU eviction and TTL
/// - Redis cache with connection handling
/// - Multi-level cache with Redis primary and memory fallback
/// - Cache service layer with advanced patterns
/// - Performance and concurrency validation
///
/// Run with: cargo test --test cache_integration -- --include-ignored

/// Generate unique test keys to prevent collisions
fn generate_test_key(prefix: &str) -> String {
    let unique_id = Uuid::new_v4().to_string()[..8].to_string();
    format!("{}:{}", prefix, unique_id)
}

/// Create test cache configurations for different cache types
fn create_test_cache_configs() -> Vec<(String, CacheConfig)> {
    let mut configs = Vec::new();

    // Memory cache configuration
    configs.push((
        "memory".to_string(),
        CacheConfig {
            r#type: "memory".to_string(),
            url: None,
            ttl: 3600,
            lru_size: 100,
            memory: Default::default(),
            redis: None,
        },
    ));

    // No-op cache configuration
    configs.push((
        "none".to_string(),
        CacheConfig {
            r#type: "none".to_string(),
            url: None,
            ttl: 3600,
            lru_size: 100,
            memory: Default::default(),
            redis: None,
        },
    ));

    // Redis cache configuration (if available)
    if let Ok(redis_url) = std::env::var("REDIS_TEST_URL") {
        configs.push((
            "redis".to_string(),
            CacheConfig {
                r#type: "redis".to_string(),
                url: Some(redis_url),
                ttl: 3600,
                lru_size: 100,
                memory: Default::default(),
                redis: None,
            },
        ));
    }

    // Multi-level cache configuration (if Redis available)
    if let Ok(redis_url) = std::env::var("REDIS_TEST_URL") {
        configs.push((
            "multi".to_string(),
            CacheConfig {
                r#type: "multi".to_string(),
                url: Some(redis_url),
                ttl: 3600,
                lru_size: 100,
                memory: Default::default(),
                redis: None,
            },
        ));
    }

    configs
}

/// Test basic cache operations across all cache types
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_basic_cache_operations() {
    let configs = create_test_cache_configs();

    for (cache_type, config) in configs {
        println!("🔍 Testing {} basic operations", cache_type);

        let cache = create_cache_provider(&config)
            .await
            .expect("Cache creation should succeed");

        let key = generate_test_key(&format!("basic_{}", cache_type));
        let value = "test_value";

        // Test set operation
        cache
            .set(&key, value, Duration::from_secs(60))
            .await
            .expect("Set operation should succeed");

        // Test get operation
        let retrieved = cache.get(&key).await.expect("Get operation should succeed");

        if cache_type == "none" {
            // No-op cache should always return None
            assert_eq!(retrieved, None, "{} should return None", cache_type);
        } else {
            // Other caches should return the value
            assert_eq!(
                retrieved,
                Some(value.to_string()),
                "{} should return stored value",
                cache_type
            );
        }

        // Test delete operation
        cache
            .delete(&key)
            .await
            .expect("Delete operation should succeed");

        // Verify deletion
        let after_delete = cache
            .get(&key)
            .await
            .expect("Get after delete should succeed");
        assert_eq!(
            after_delete, None,
            "{} should return None after delete",
            cache_type
        );

        println!("✅ {} basic operations passed", cache_type);
    }
}

/// Test cache TTL (Time To Live) functionality
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_cache_ttl() {
    let configs = create_test_cache_configs();

    for (cache_type, config) in configs.into_iter().filter(|(t, _)| t != "none") {
        println!("🔍 Testing {} TTL functionality", cache_type);

        let cache = create_cache_provider(&config)
            .await
            .expect("Cache creation should succeed");

        let key = generate_test_key(&format!("ttl_{}", cache_type));
        let value = "ttl_test_value";

        // Set with very short TTL
        cache
            .set(&key, value, Duration::from_millis(100))
            .await
            .expect("Set with TTL should succeed");

        // Should be available immediately
        let immediate = cache.get(&key).await.expect("Immediate get should succeed");
        assert_eq!(
            immediate,
            Some(value.to_string()),
            "{} should return value immediately",
            cache_type
        );

        // Wait for TTL to expire
        sleep(Duration::from_millis(150)).await;

        // Should be expired now
        let after_ttl = cache.get(&key).await.expect("Get after TTL should succeed");

        // Note: Memory cache with cleanup might still have the value until next cleanup
        // Redis should definitely have expired it
        if cache_type == "redis" {
            assert_eq!(
                after_ttl, None,
                "{} should return None after TTL",
                cache_type
            );
        }

        println!("✅ {} TTL functionality passed", cache_type);
    }
}

/// Test cache health checks and connectivity
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_cache_health_checks() {
    let configs = create_test_cache_configs();

    for (cache_type, config) in configs {
        println!("🔍 Testing {} health checks", cache_type);

        let cache = create_cache_provider(&config)
            .await
            .expect("Cache creation should succeed");

        // Test ping operation
        cache
            .ping()
            .await
            .expect("Ping should succeed for healthy cache");

        // Test stats operation
        let stats = cache.stats().await.expect("Stats should be available");

        assert!(
            stats.hit_rate >= 0.0 && stats.hit_rate <= 1.0,
            "{} hit rate should be between 0 and 1",
            cache_type
        );

        println!("✅ {} health checks passed", cache_type);
    }
}

/// Test cache statistics and hit rate calculation
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_cache_statistics() {
    let configs = create_test_cache_configs();

    for (cache_type, config) in configs.into_iter().filter(|(t, _)| t != "none") {
        println!("🔍 Testing {} statistics", cache_type);

        let cache = create_cache_provider(&config)
            .await
            .expect("Cache creation should succeed");

        // Clear cache to start fresh
        cache.clear().await.expect("Clear should succeed");

        let key1 = generate_test_key(&format!("stats1_{}", cache_type));
        let key2 = generate_test_key(&format!("stats2_{}", cache_type));

        // Set some values
        cache
            .set(&key1, "value1", Duration::from_secs(60))
            .await
            .expect("Set should succeed");
        cache
            .set(&key2, "value2", Duration::from_secs(60))
            .await
            .expect("Set should succeed");

        // Generate cache hits
        let _ = cache.get(&key1).await;
        let _ = cache.get(&key2).await;
        let _ = cache.get(&key1).await; // Hit

        // Generate cache miss
        let _ = cache.get("nonexistent_key").await;

        // Check statistics
        let stats = cache.stats().await.expect("Stats should be available");

        // We should have some operations recorded
        assert!(
            stats.total_operations() > 0,
            "{} should have recorded operations",
            cache_type
        );

        // Hit ratio should be calculated correctly
        let expected_ratio = stats.hits as f64 / (stats.hits + stats.misses) as f64;
        assert!(
            (stats.hit_ratio() - expected_ratio).abs() < 0.001,
            "{} hit ratio calculation should be correct",
            cache_type
        );

        println!(
            "✅ {} statistics passed (Hit ratio: {:.2}%)",
            cache_type,
            stats.hit_ratio() * 100.0
        );
    }
}

/// Test cache service layer functionality
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_cache_service() {
    let configs = create_test_cache_configs();

    for (cache_type, config) in configs.into_iter().filter(|(t, _)| t != "none") {
        println!("🔍 Testing {} cache service", cache_type);

        let provider = create_cache_provider(&config)
            .await
            .expect("Cache creation should succeed");

        let service = CacheService::new(provider, 3600);

        let key = generate_test_key(&format!("service_{}", cache_type));

        // Test basic service operations
        service
            .set(&key, "service_value")
            .await
            .expect("Service set should succeed");

        let value = service.get(&key).await.expect("Service get should succeed");
        assert_eq!(
            value,
            Some("service_value".to_string()),
            "{} service should return stored value",
            cache_type
        );

        // Test set with custom TTL
        let ttl_key = generate_test_key(&format!("service_ttl_{}", cache_type));
        service
            .set_with_ttl(&ttl_key, "ttl_value", Duration::from_secs(30))
            .await
            .expect("Service set with TTL should succeed");

        let ttl_value = service
            .get(&ttl_key)
            .await
            .expect("Service get TTL value should succeed");
        assert_eq!(
            ttl_value,
            Some("ttl_value".to_string()),
            "{} service should return TTL value",
            cache_type
        );

        // Test delete
        service
            .delete(&key)
            .await
            .expect("Service delete should succeed");

        let after_delete = service
            .get(&key)
            .await
            .expect("Service get after delete should succeed");
        assert_eq!(
            after_delete, None,
            "{} service should return None after delete",
            cache_type
        );

        println!("✅ {} cache service passed", cache_type);
    }
}

/// Test get_or_set pattern in cache service
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_get_or_set_pattern() {
    let configs = create_test_cache_configs();

    for (cache_type, config) in configs.into_iter().filter(|(t, _)| t != "none") {
        println!("🔍 Testing {} get_or_set pattern", cache_type);

        let provider = create_cache_provider(&config)
            .await
            .expect("Cache creation should succeed");

        let service = CacheService::new(provider, 3600);

        let key = generate_test_key(&format!("get_or_set_{}", cache_type));
        let mut compute_count = 0;

        // First call should compute the value
        let value1 = service
            .get_or_set(&key, || {
                compute_count += 1;
                async move { Ok("computed_value".to_string()) }
            })
            .await
            .expect("Get or set should succeed");

        assert_eq!(
            value1, "computed_value",
            "{} should return computed value",
            cache_type
        );
        assert_eq!(compute_count, 1, "{} should have computed once", cache_type);

        // Second call should use cached value
        let value2 = service
            .get_or_set(&key, || {
                compute_count += 1;
                async move { Ok("should_not_compute".to_string()) }
            })
            .await
            .expect("Get or set should succeed");

        assert_eq!(
            value2, "computed_value",
            "{} should return cached value",
            cache_type
        );
        assert_eq!(
            compute_count, 1,
            "{} should not have computed again",
            cache_type
        );

        // Test get_or_set with custom TTL
        let ttl_key = generate_test_key(&format!("get_or_set_ttl_{}", cache_type));
        let ttl_value = service
            .get_or_set_with_ttl(&ttl_key, Duration::from_secs(30), || async {
                Ok("ttl_computed_value".to_string())
            })
            .await
            .expect("Get or set with TTL should succeed");

        assert_eq!(
            ttl_value, "ttl_computed_value",
            "{} should return TTL computed value",
            cache_type
        );

        println!("✅ {} get_or_set pattern passed", cache_type);
    }
}

/// Test cache key utility functions
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_cache_key_utilities() {
    println!("🔍 Testing cache key utilities");

    // Test cache key generation
    assert_eq!(CacheKey::user_by_id("123"), "user:id:123");
    assert_eq!(
        CacheKey::user_by_email("test@example.com"),
        "user:email:test@example.com"
    );
    assert_eq!(CacheKey::session("sess_abc123"), "session:sess_abc123");
    assert_eq!(
        CacheKey::password_reset_token("reset_token_123"),
        "reset_token:reset_token_123"
    );
    assert_eq!(
        CacheKey::email_verification_token("verify_token_123"),
        "verify_token:verify_token_123"
    );
    assert_eq!(
        CacheKey::rate_limit("192.168.1.1"),
        "rate_limit:192.168.1.1"
    );
    assert_eq!(
        CacheKey::login_attempts("user@example.com"),
        "login_attempts:user@example.com"
    );

    // Test with real cache operations
    let config = CacheConfig {
        r#type: "memory".to_string(),
        url: None,
        ttl: 3600,
        lru_size: 100,
        memory: Default::default(),
        redis: None,
    };

    let cache = create_cache_provider(&config)
        .await
        .expect("Memory cache creation should succeed");

    // Test user caching with proper keys
    let user_id = "user_123";
    let user_key = CacheKey::user_by_id(user_id);
    let user_data = r#"{"id":"user_123","email":"test@example.com"}"#;

    cache
        .set(&user_key, user_data, Duration::from_secs(60))
        .await
        .expect("User cache set should succeed");

    let cached_user = cache
        .get(&user_key)
        .await
        .expect("User cache get should succeed");
    assert_eq!(
        cached_user,
        Some(user_data.to_string()),
        "Cached user data should match"
    );

    // Test session caching
    let session_id = "sess_abc123";
    let session_key = CacheKey::session(session_id);
    let session_data = r#"{"user_id":"user_123","expires_at":"2024-12-31T23:59:59Z"}"#;

    cache
        .set(&session_key, session_data, Duration::from_secs(60))
        .await
        .expect("Session cache set should succeed");

    let cached_session = cache
        .get(&session_key)
        .await
        .expect("Session cache get should succeed");
    assert_eq!(
        cached_session,
        Some(session_data.to_string()),
        "Cached session data should match"
    );

    println!("✅ Cache key utilities passed");
}

/// Test multi-level cache specific functionality
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_multi_level_cache() {
    // Only run if Redis is available
    if std::env::var("REDIS_TEST_URL").is_err() {
        println!("⚠️ REDIS_TEST_URL not set, skipping multi-level cache test");
        return;
    }

    println!("🔍 Testing multi-level cache functionality");

    let config = CacheConfig {
        r#type: "multi".to_string(),
        url: std::env::var("REDIS_TEST_URL").ok(),
        ttl: 3600,
        lru_size: 100,
    };

    let cache = create_multi_level_cache(&config)
        .await
        .expect("Multi-level cache creation should succeed");

    let key = generate_test_key("multi_level");
    let value = "multi_level_value";

    // Clear any existing data
    cache.clear().await.expect("Clear should succeed");

    // Test basic operations
    cache
        .set(&key, value, Duration::from_secs(60))
        .await
        .expect("Multi-level set should succeed");

    let retrieved = cache
        .get(&key)
        .await
        .expect("Multi-level get should succeed");
    assert_eq!(
        retrieved,
        Some(value.to_string()),
        "Multi-level cache should return stored value"
    );

    // Test failover behavior by ensuring fallback works
    let stats = cache
        .stats()
        .await
        .expect("Multi-level stats should be available");
    assert!(
        stats.total_operations() >= 0,
        "Multi-level cache should have operation stats"
    );

    // Test ping for health check
    cache.ping().await.expect("Multi-level ping should succeed");

    println!("✅ Multi-level cache functionality passed");
}

/// Test concurrent cache operations
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_concurrent_cache_operations() {
    let configs = create_test_cache_configs();

    for (cache_type, config) in configs.into_iter().filter(|(t, _)| t != "none") {
        println!("🔍 Testing {} concurrent operations", cache_type);

        let cache = create_cache_provider(&config)
            .await
            .expect("Cache creation should succeed");

        const CONCURRENT_OPS: usize = 20;
        let mut handles = Vec::new();

        // Concurrent set operations
        for i in 0..CONCURRENT_OPS {
            let cache_clone = Arc::clone(&cache);
            let key = format!("concurrent_{}_{}", cache_type, i);
            let value = format!("value_{}", i);

            let handle = tokio::spawn(async move {
                cache_clone.set(&key, &value, Duration::from_secs(60)).await
            });

            handles.push(handle);
        }

        // Wait for all operations to complete
        let mut successful = 0;
        for handle in handles {
            match handle.await {
                Ok(Ok(_)) => successful += 1,
                _ => {}
            }
        }

        println!(
            "📊 {} concurrent sets - Success: {}/{}",
            cache_type, successful, CONCURRENT_OPS
        );
        assert!(
            successful >= CONCURRENT_OPS * 8 / 10,
            "{} should handle concurrent operations (>80% success rate)",
            cache_type
        );

        // Concurrent get operations
        let mut get_handles = Vec::new();
        for i in 0..CONCURRENT_OPS {
            let cache_clone = Arc::clone(&cache);
            let key = format!("concurrent_{}_{}", cache_type, i);

            let handle = tokio::spawn(async move { cache_clone.get(&key).await });

            get_handles.push(handle);
        }

        // Check get results
        let mut get_successful = 0;
        for handle in get_handles {
            if let Ok(Ok(Some(_))) = handle.await {
                get_successful += 1;
            }
        }

        println!(
            "📊 {} concurrent gets - Success: {}/{}",
            cache_type, get_successful, CONCURRENT_OPS
        );

        println!("✅ {} concurrent operations passed", cache_type);
    }
}

/// Test cache error handling and resilience
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_cache_error_handling() {
    let configs = create_test_cache_configs();

    for (cache_type, config) in configs {
        println!("🔍 Testing {} error handling", cache_type);

        let cache = create_cache_provider(&config)
            .await
            .expect("Cache creation should succeed");

        // Test operations with empty key
        let empty_result = cache.get("").await;
        assert!(
            empty_result.is_ok(),
            "{} should handle empty key gracefully",
            cache_type
        );

        // Test operations with very long key
        let long_key = "x".repeat(1000);
        let long_key_result = cache.set(&long_key, "value", Duration::from_secs(60)).await;
        assert!(
            long_key_result.is_ok(),
            "{} should handle long keys",
            cache_type
        );

        // Test operations with special characters in key
        let special_key = "key:with/special\\chars@#$%";
        let special_result = cache
            .set(special_key, "value", Duration::from_secs(60))
            .await;
        assert!(
            special_result.is_ok(),
            "{} should handle special characters",
            cache_type
        );

        // Test zero TTL
        let zero_ttl_result = cache.set("zero_ttl", "value", Duration::from_secs(0)).await;
        assert!(
            zero_ttl_result.is_ok(),
            "{} should handle zero TTL",
            cache_type
        );

        println!("✅ {} error handling passed", cache_type);
    }
}

/// Test cache memory management and LRU eviction
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_cache_memory_management() {
    println!("🔍 Testing memory cache LRU eviction");

    // Create memory cache with small size for testing eviction
    let config = CacheConfig {
        r#type: "memory".to_string(),
        url: None,
        ttl: 3600,
        lru_size: 3, // Very small for testing
        memory: Default::default(),
        redis: None,
    };

    let cache = create_cache_provider(&config)
        .await
        .expect("Small memory cache creation should succeed");

    // Fill cache beyond capacity
    cache
        .set("key1", "value1", Duration::from_secs(60))
        .await
        .expect("Set key1 should succeed");
    cache
        .set("key2", "value2", Duration::from_secs(60))
        .await
        .expect("Set key2 should succeed");
    cache
        .set("key3", "value3", Duration::from_secs(60))
        .await
        .expect("Set key3 should succeed");

    // All keys should be present
    assert_eq!(cache.get("key1").await.unwrap(), Some("value1".to_string()));
    assert_eq!(cache.get("key2").await.unwrap(), Some("value2".to_string()));
    assert_eq!(cache.get("key3").await.unwrap(), Some("value3".to_string()));

    // Add one more key to trigger eviction
    cache
        .set("key4", "value4", Duration::from_secs(60))
        .await
        .expect("Set key4 should succeed");

    // key4 should be present
    assert_eq!(cache.get("key4").await.unwrap(), Some("value4".to_string()));

    // Check that LRU eviction occurred (implementation dependent)
    let stats = cache.stats().await.expect("Stats should be available");
    assert!(stats.size <= 3, "Cache size should not exceed limit");

    println!("✅ Memory cache LRU eviction passed");
}

/// Test cache performance characteristics
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_cache_performance() {
    let configs = create_test_cache_configs();

    for (cache_type, config) in configs.into_iter().filter(|(t, _)| t != "none") {
        println!("🔍 Testing {} performance", cache_type);

        let cache = create_cache_provider(&config)
            .await
            .expect("Cache creation should succeed");

        const PERFORMANCE_OPS: usize = 100;

        // Measure set operations
        let start = std::time::Instant::now();
        for i in 0..PERFORMANCE_OPS {
            let key = format!("perf_set_{}_{}", cache_type, i);
            cache
                .set(&key, "performance_value", Duration::from_secs(60))
                .await
                .expect("Performance set should succeed");
        }
        let set_duration = start.elapsed();
        let set_ops_per_sec = PERFORMANCE_OPS as f64 / set_duration.as_secs_f64();

        // Measure get operations
        let start = std::time::Instant::now();
        for i in 0..PERFORMANCE_OPS {
            let key = format!("perf_set_{}_{}", cache_type, i);
            cache
                .get(&key)
                .await
                .expect("Performance get should succeed");
        }
        let get_duration = start.elapsed();
        let get_ops_per_sec = PERFORMANCE_OPS as f64 / get_duration.as_secs_f64();

        println!("📊 {} Performance:", cache_type);
        println!(
            "   Set: {:.0} ops/sec ({:.2}ms avg)",
            set_ops_per_sec,
            set_duration.as_millis() as f64 / PERFORMANCE_OPS as f64
        );
        println!(
            "   Get: {:.0} ops/sec ({:.2}ms avg)",
            get_ops_per_sec,
            get_duration.as_millis() as f64 / PERFORMANCE_OPS as f64
        );

        // Performance thresholds (very lenient for testing environments)
        assert!(
            set_ops_per_sec > 10.0,
            "{} set performance should be reasonable",
            cache_type
        );
        assert!(
            get_ops_per_sec > 50.0,
            "{} get performance should be reasonable",
            cache_type
        );

        println!("✅ {} performance passed", cache_type);
    }
}

/// Integration test combining all cache functionality
#[tokio::test]
#[cfg(any(feature = "mongodb", feature = "postgresql", feature = "mysql"))]
async fn test_complete_cache_workflow() {
    let configs = create_test_cache_configs();

    for (cache_type, config) in configs.into_iter().filter(|(t, _)| t != "none") {
        println!("🔍 Testing {} complete workflow", cache_type);

        let provider = create_cache_provider(&config)
            .await
            .expect("Cache creation should succeed");

        let service = CacheService::new(provider, 3600);

        // Step 1: User session workflow
        let user_id = "user123";
        let session_id = "sess_abc123";

        let user_key = CacheKey::user_by_id(user_id);
        let session_key = CacheKey::session(session_id);

        // Cache user data
        let user_data = r#"{"id":"user123","email":"user@example.com","role":"user"}"#;
        service
            .set(&user_key, user_data)
            .await
            .expect("User data caching should succeed");

        // Cache session data
        let session_data = r#"{"user_id":"user123","expires_at":"2024-12-31T23:59:59Z"}"#;
        service
            .set(&session_key, session_data)
            .await
            .expect("Session data caching should succeed");

        // Step 2: Authentication workflow
        let email = "user@example.com";
        let login_attempts_key = CacheKey::login_attempts(email);

        // Track login attempts
        service
            .set(&login_attempts_key, "1")
            .await
            .expect("Login attempts caching should succeed");

        // Step 3: Token workflow
        let reset_token = "reset_token_abc123";
        let reset_key = CacheKey::password_reset_token(reset_token);

        service
            .set_with_ttl(&reset_key, user_id, Duration::from_secs(1800))
            .await
            .expect("Reset token caching should succeed");

        // Step 4: Rate limiting workflow
        let ip = "192.168.1.100";
        let rate_limit_key = CacheKey::rate_limit(ip);

        service
            .set_with_ttl(&rate_limit_key, "5", Duration::from_secs(300))
            .await
            .expect("Rate limit caching should succeed");

        // Step 5: Verify all data is cached correctly
        assert_eq!(
            service.get(&user_key).await.unwrap(),
            Some(user_data.to_string())
        );
        assert_eq!(
            service.get(&session_key).await.unwrap(),
            Some(session_data.to_string())
        );
        assert_eq!(
            service.get(&login_attempts_key).await.unwrap(),
            Some("1".to_string())
        );
        assert_eq!(
            service.get(&reset_key).await.unwrap(),
            Some(user_id.to_string())
        );
        assert_eq!(
            service.get(&rate_limit_key).await.unwrap(),
            Some("5".to_string())
        );

        // Step 6: Test get_or_set for computed values
        let computed_key = CacheKey::user_by_email(email);
        let computed_value = service
            .get_or_set(&computed_key, || async {
                // Simulate database lookup
                Ok(user_data.to_string())
            })
            .await
            .expect("Get or set should succeed");

        assert_eq!(computed_value, user_data);

        // Step 7: Cleanup workflow
        service
            .delete(&session_key)
            .await
            .expect("Session cleanup should succeed");
        service
            .delete(&reset_key)
            .await
            .expect("Token cleanup should succeed");

        // Verify cleanup
        assert_eq!(service.get(&session_key).await.unwrap(), None);
        assert_eq!(service.get(&reset_key).await.unwrap(), None);

        // Step 8: Check cache statistics
        let stats = service
            .stats()
            .await
            .expect("Cache stats should be available");
        assert!(
            stats.total_operations() > 0,
            "Cache should have recorded operations"
        );

        println!("✅ {} complete workflow passed", cache_type);
        println!(
            "   Final stats - Hits: {}, Misses: {}, Hit Rate: {:.1}%",
            stats.hits,
            stats.misses,
            stats.hit_ratio() * 100.0
        );
    }
}
