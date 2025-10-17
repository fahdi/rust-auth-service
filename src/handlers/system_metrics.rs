use axum::{
    body::Body,
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use tracing::debug;

use crate::AppState;

// Removed unused metrics_handler - using observability module instead

/// System stats endpoint (JSON format for debugging)
///
/// Provides system statistics in JSON format for debugging and development.
/// This is separate from the Prometheus metrics endpoint.
pub async fn stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    debug!("Serving system stats");

    // Get basic system information
    let stats = serde_json::json!({
        "server": {
            "host": state.config.server.host,
            "port": state.config.server.port,
            "workers": state.config.server.workers
        },
        "database": {
            "type": state.config.database.r#type,
            "pool": {
                "min_connections": state.config.database.pool.min_connections,
                "max_connections": state.config.database.pool.max_connections,
                "idle_timeout": state.config.database.pool.idle_timeout
            }
        },
        "cache": {
            "type": state.config.cache.r#type,
            "ttl": state.config.cache.ttl,
            "lru_size": state.config.cache.lru_size
        },
        "monitoring": {
            "metrics": state.config.monitoring.metrics,
            "prometheus_port": state.config.monitoring.prometheus_port,
            "health_check_interval": state.config.monitoring.health_check_interval
        },
        "rate_limit": {
            "enabled": state.config.rate_limit.enabled,
            "backend": state.config.rate_limit.backend,
            "memory_cache_size": state.config.rate_limit.memory_cache_size
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(stats.to_string()))
        .unwrap()
}

// Removed tests that depend on disabled OAuth2 module
