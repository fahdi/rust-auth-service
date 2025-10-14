use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
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
    
    let response = json!({
        "status": "ok",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "service": "rust-auth-service",
        "database": {
            "status": db_health.status,
            "type": db_health.database_type,
            "connected": db_health.connected,
            "response_time_ms": db_health.response_time_ms
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
    // Check if database is ready
    match state.database.health_check().await {
        Ok(health) if health.connected => {
            Ok(Json(json!({
                "status": "ready",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })))
        }
        _ => Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

// Liveness check handler (for Kubernetes liveness probes)
pub async fn liveness_check() -> Json<Value> {
    Json(json!({
        "status": "alive",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}