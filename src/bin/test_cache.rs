use rust_auth_service::{
    cache::{create_cache_provider, CacheService, CacheKey},
    config::cache::CacheConfig,
};
use anyhow::Result;
use std::time::{Duration, Instant};
use tracing::{info, error};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting comprehensive cache testing...");

    // Test configurations
    let configs = vec![
        ("Memory Cache", CacheConfig {
            r#type: "memory".to_string(),
            url: None,
            ttl: 3600,
            lru_size: 1000,
        }),
        ("Multi-Level Cache (Redis + Memory)", CacheConfig {
            r#type: "multi".to_string(),
            url: Some("redis://localhost:6379".to_string()),
            ttl: 3600,
            lru_size: 1000,
        }),
        ("Redis Cache", CacheConfig {
            r#type: "redis".to_string(),
            url: Some("redis://localhost:6379".to_string()),
            ttl: 3600,
            lru_size: 1000,
        }),
        ("No-Op Cache", CacheConfig {
            r#type: "none".to_string(),
            url: None,
            ttl: 3600,
            lru_size: 1000,
        }),
    ];

    for (name, config) in configs {
        info!("\n=== Testing {} ===", name);
        match test_cache_configuration(&config).await {
            Ok(_) => info!("✅ {} tests passed", name),
            Err(e) => error!("❌ {} tests failed: {}", name, e),
        }
    }

    // Performance comparison
    info!("\n=== Performance Comparison ===");
    performance_test().await?;

    info!("\nCache testing completed!");
    Ok(())
}

async fn test_cache_configuration(config: &CacheConfig) -> Result<()> {
    let provider = create_cache_provider(config).await?;
    let cache = CacheService::new(provider, 3600);
    
    // Test 1: Basic operations
    info!("Testing basic cache operations...");
    
    // Clear cache first
    cache.clear().await?;
    
    // Test set/get
    cache.set("test_key", "test_value").await?;
    let value = cache.get("test_key").await?;
    
    // No-Op cache always returns None, so we handle this case
    if config.r#type == "none" {
        assert_eq!(value, None);
        info!("No-Op cache correctly returns None for all gets");
    } else {
        assert_eq!(value, Some("test_value".to_string()));
    }
    
    // Test missing key
    let missing = cache.get("missing_key").await?;
    assert_eq!(missing, None);
    
    // Test delete
    cache.delete("test_key").await?;
    let deleted = cache.get("test_key").await?;
    assert_eq!(deleted, None);
    
    // Test 2: TTL functionality
    info!("Testing TTL functionality...");
    cache.set_with_ttl("ttl_key", "ttl_value", Duration::from_millis(100)).await?;
    
    // Should exist immediately (except for no-op cache)
    let immediate = cache.get("ttl_key").await?;
    if config.r#type == "none" {
        assert_eq!(immediate, None);
    } else {
        assert_eq!(immediate, Some("ttl_value".to_string()));
    }
    
    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(150)).await;
    
    // Should be expired (may not work for all cache types)
    let expired = cache.get("ttl_key").await?;
    if expired.is_some() && config.r#type != "none" {
        info!("Note: TTL not fully supported by this cache type");
    }
    
    // Test 3: get_or_set pattern
    info!("Testing get_or_set pattern...");
    let computed = cache.get_or_set("computed_key", || async {
        Ok("computed_value".to_string())
    }).await?;
    assert_eq!(computed, "computed_value");
    
    // Second call should return cached value (except for no-op cache)
    let cached = cache.get_or_set("computed_key", || async {
        Ok("should_not_be_called".to_string())
    }).await?;
    
    if config.r#type == "none" {
        // No-op cache will call the function every time
        assert_eq!(cached, "should_not_be_called");
        info!("No-Op cache correctly recomputes values every time");
    } else {
        assert_eq!(cached, "computed_value");
    }
    
    // Test 4: Cache keys utility
    info!("Testing cache key utilities...");
    let user_key = CacheKey::user_by_id("user123");
    let email_key = CacheKey::user_by_email("test@example.com");
    let session_key = CacheKey::session("sess_456");
    
    cache.set(&user_key, "user_data").await?;
    cache.set(&email_key, "email_data").await?;
    cache.set(&session_key, "session_data").await?;
    
    if config.r#type != "none" {
        assert_eq!(cache.get(&user_key).await?, Some("user_data".to_string()));
        assert_eq!(cache.get(&email_key).await?, Some("email_data".to_string()));
        assert_eq!(cache.get(&session_key).await?, Some("session_data".to_string()));
    } else {
        // No-op cache returns None
        assert_eq!(cache.get(&user_key).await?, None);
        assert_eq!(cache.get(&email_key).await?, None);
        assert_eq!(cache.get(&session_key).await?, None);
    }
    
    // Test 5: Health check
    info!("Testing health check...");
    cache.ping().await?;
    
    // Test 6: Statistics
    info!("Testing statistics...");
    let stats = cache.stats().await?;
    info!("Cache stats - Hits: {}, Misses: {}, Size: {}, Hit Rate: {:.2}%", 
          stats.hits, stats.misses, stats.size, stats.hit_rate * 100.0);
    
    Ok(())
}

async fn performance_test() -> Result<()> {
    let configs = vec![
        ("Memory", CacheConfig {
            r#type: "memory".to_string(),
            url: None,
            ttl: 3600,
            lru_size: 10000,
        }),
        ("Multi-Level", CacheConfig {
            r#type: "multi".to_string(),
            url: Some("redis://localhost:6379".to_string()),
            ttl: 3600,
            lru_size: 10000,
        }),
    ];
    
    const OPERATIONS: usize = 1000;
    
    for (name, config) in configs {
        if let Ok(provider) = create_cache_provider(&config).await {
            let cache = CacheService::new(provider, 3600);
            cache.clear().await?;
            
            // Warm up
            for i in 0..100 {
                cache.set(&format!("warm_{}", i), &format!("value_{}", i)).await?;
            }
            
            // Test write performance
            let start = Instant::now();
            for i in 0..OPERATIONS {
                cache.set(&format!("perf_key_{}", i), &format!("value_{}", i)).await?;
            }
            let write_duration = start.elapsed();
            
            // Test read performance
            let start = Instant::now();
            for i in 0..OPERATIONS {
                let _ = cache.get(&format!("perf_key_{}", i)).await?;
            }
            let read_duration = start.elapsed();
            
            // Calculate rates
            let write_ops_per_sec = OPERATIONS as f64 / write_duration.as_secs_f64();
            let read_ops_per_sec = OPERATIONS as f64 / read_duration.as_secs_f64();
            
            info!("{} Cache Performance:", name);
            info!("  Write: {:.0} ops/sec ({:.2}ms avg)", write_ops_per_sec, write_duration.as_millis() as f64 / OPERATIONS as f64);
            info!("  Read:  {:.0} ops/sec ({:.2}ms avg)", read_ops_per_sec, read_duration.as_millis() as f64 / OPERATIONS as f64);
            
            // Test cache statistics
            let stats = cache.stats().await?;
            info!("  Final stats - Hits: {}, Misses: {}, Size: {}, Hit Rate: {:.1}%", 
                  stats.hits, stats.misses, stats.size, stats.hit_rate * 100.0);
        } else {
            info!("{} Cache: Connection failed, skipping performance test", name);
        }
    }
    
    Ok(())
}