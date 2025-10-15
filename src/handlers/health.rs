use axum::{extract::State, http::StatusCode, response::Json};
use serde_json::{json, Value};
use tracing::error;

use crate::AppState;

// Health check handler
pub async fn health_check(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    let db_health = match state.database.health_check().await {
        Ok(health) => health,
        Err(e) => {
            error!("Database health check failed: {}", e);
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    // Check cache health
    let cache_healthy = state.cache.ping().await.is_ok();
    let cache_stats = state.cache.stats().await.unwrap_or_default();

    let response = json!({
        "status": if db_health.connected && cache_healthy { "ok" } else { "degraded" },
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "service": "rust-auth-service",
        "database": {
            "status": db_health.status,
            "type": db_health.database_type,
            "connected": db_health.connected,
            "response_time_ms": db_health.response_time_ms
        },
        "cache": {
            "healthy": cache_healthy,
            "type": state.config.cache.r#type,
            "stats": {
                "hits": cache_stats.hits,
                "misses": cache_stats.misses,
                "hit_ratio": cache_stats.hit_ratio(),
                "total_operations": cache_stats.total_operations()
            }
        }
    });

    if db_health.connected {
        Ok(Json(response))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

// Ready check handler (for Kubernetes readiness probes)
pub async fn ready_check(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    // Check if database and cache are ready
    let db_ready = state
        .database
        .health_check()
        .await
        .map(|health| health.connected)
        .unwrap_or(false);

    let cache_ready = state.cache.ping().await.is_ok();

    if db_ready && cache_ready {
        Ok(Json(json!({
            "status": "ready",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "database": db_ready,
            "cache": cache_ready
        })))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

// Liveness check handler (for Kubernetes liveness probes)
pub async fn liveness_check() -> Json<Value> {
    Json(json!({
        "status": "alive",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
