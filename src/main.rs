use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
// mod handlers;
mod models;
// mod services;
mod database;
// mod cache;
// mod email;
// mod middleware;
mod utils;

use config::Config;
use database::AuthDatabase;

// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub database: Arc<dyn AuthDatabase>,
}

// Health check handler
async fn health_check(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
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
async fn ready_check(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
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
async fn liveness_check() -> Json<Value> {
    Json(json!({
        "status": "alive",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_auth_service=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Rust Auth Service...");

    // Load configuration
    let config = Config::from_env_and_file()?;
    info!("Configuration loaded successfully");

    // Initialize database
    let database = database::create_database(&config.database).await?;
    info!("Database connection established");

    // Test database connection
    match database.health_check().await {
        Ok(health) => {
            if health.connected {
                info!("Database health check passed: {} ({}ms)", health.status, health.response_time_ms);
            } else {
                error!("Database health check failed: {}", health.status);
                return Err(anyhow::anyhow!("Database not ready"));
            }
        }
        Err(e) => {
            error!("Database health check error: {}", e);
            return Err(e);
        }
    }

    // Build application state
    let app_state = AppState {
        config: Arc::new(config.clone()),
        database: Arc::from(database),
    };

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
        ])
        .allow_headers(Any)
        .allow_origin(Any);

    // Build router with health check endpoints
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .route("/live", get(liveness_check))
        .with_state(app_state)
        .layer(cors)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    // Start server
    let listener =
        tokio::net::TcpListener::bind(format!("{}:{}", config.server.host, config.server.port))
            .await?;
    info!(
        "Server listening on {}:{}",
        config.server.host, config.server.port
    );

    axum::serve(listener, app).await?;

    Ok(())
}

// #[derive(Clone)]
// pub struct AppState {
//     pub config: Config,
//     pub database: Box<dyn database::AuthDatabase>,
//     pub cache: Box<dyn cache::CacheProvider>,
//     pub email_service: Box<dyn email::EmailProvider>,
// }
