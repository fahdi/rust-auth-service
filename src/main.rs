use anyhow::Result;
use axum::{
    middleware::from_fn_with_state,
    routing::{get, post, put},
    Router,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod errors;
mod handlers;
mod metrics;
mod models;
mod oauth2;
// mod services;
mod cache;
mod database;
// mod email;
mod middleware;
mod migrations;
mod utils;

use cache::CacheService;
use config::Config;
use database::AuthDatabase;

// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub database: Arc<dyn AuthDatabase>,
    pub cache: Arc<CacheService>,
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

    // Initialize metrics if enabled
    if config.monitoring.metrics {
        metrics::Metrics::init();
        info!("Prometheus metrics initialized");
    }

    // Initialize database
    let database = database::create_database(&config.database).await?;
    info!("Database connection established");

    // Initialize cache
    let cache_provider = cache::create_cache_provider(&config.cache).await?;
    let cache_service = CacheService::new(cache_provider, config.cache.ttl);
    info!("Cache system initialized");

    // Test database connection
    match database.health_check().await {
        Ok(health) => {
            if health.connected {
                info!(
                    "Database health check passed: {} ({}ms)",
                    health.status, health.response_time_ms
                );
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
        cache: Arc::new(cache_service),
    };

    // Build public routes (no authentication required)
    let public_routes = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::ready_check))
        .route("/live", get(handlers::liveness_check))
        .route("/metrics", get(handlers::metrics_handler))
        .route("/stats", get(handlers::stats_handler))
        .route("/auth/register", post(handlers::register))
        .route("/auth/login", post(handlers::login))
        .route("/auth/verify", post(handlers::verify_email))
        .route("/auth/forgot-password", post(handlers::forgot_password))
        .route("/auth/reset-password", post(handlers::reset_password))
        .route("/auth/refresh", post(handlers::refresh_token));

    // Build protected routes (authentication required)
    let protected_routes = Router::new()
        .route("/auth/me", get(handlers::get_profile))
        .route("/auth/profile", put(handlers::update_profile))
        .route("/auth/logout", post(handlers::logout))
        .route_layer(from_fn_with_state(
            app_state.clone(),
            middleware::jwt_auth_middleware,
        ));

    // Combine all routes
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(app_state.clone())
        .layer(from_fn_with_state(
            app_state.clone(),
            middleware::metrics_middleware,
        ))
        .layer(from_fn_with_state(
            app_state.clone(),
            middleware::rate_limit_middleware,
        ))
        .layer(middleware::create_cors_layer())
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
