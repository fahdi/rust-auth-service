use anyhow::Result;
use axum::{
    middleware::from_fn_with_state,
    routing::{delete, get, post, put},
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
use oauth2::{OAuth2Config, OAuth2Service};
use oauth2::server::OAuth2Server;
use oauth2::tokens::TokenManager;

// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub database: Arc<dyn AuthDatabase>,
    pub cache: Arc<CacheService>,
    pub oauth2_server: Arc<OAuth2Server>,
    pub token_manager: Arc<TokenManager>,
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

    // Initialize OAuth2 components
    let oauth2_config = OAuth2Config::default(); // TODO: Load from config
    
    // Create a default JWT signing key for HMAC
    let jwt_key = oauth2_config.jwt_signing_key
        .as_ref()
        .map(|k| k.as_bytes())
        .unwrap_or(b"default-secret-key-change-in-production");
        
    let token_manager = TokenManager::new(oauth2_config.clone(), jwt_key, None)?;
    
    // Create OAuth2Service from database
    let oauth2_service: Arc<dyn oauth2::OAuth2Service> = match config.database.r#type.as_str() {
        "mongodb" => {
            // Create a new MongoDB connection specifically for OAuth2Service
            let mongodb = database::mongodb::MongoDatabase::new(&config.database.url, &config.database.pool).await?;
            Arc::new(mongodb)
        }
        _ => return Err(anyhow::anyhow!("OAuth2Service not implemented for database type: {}", config.database.r#type)),
    };
    
    let oauth2_server = OAuth2Server::new(oauth2_config, oauth2_service, token_manager.clone());
    info!("OAuth2 server initialized");

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
        oauth2_server: Arc::new(oauth2_server),
        token_manager: Arc::new(token_manager),
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

    // Build OAuth2 routes
    let oauth2_routes = Router::new()
        // Authorization endpoints
        .route("/oauth2/authorize", get(handlers::authorize))
        .route("/oauth2/authorize", post(handlers::authorize_consent_post))
        .route("/oauth2/token", post(handlers::token))
        .route("/oauth2/revoke", post(handlers::revoke))
        .route("/oauth2/introspect", post(handlers::introspect))
        // Device flow endpoints
        .route("/oauth2/device/authorize", post(handlers::device_authorization))
        .route("/oauth2/device/verify", get(handlers::device_verify))
        .route("/oauth2/device/verify", post(handlers::device_verify_post))
        // Metadata and discovery
        .route("/.well-known/oauth-authorization-server", get(handlers::metadata))
        .route("/.well-known/jwks.json", get(handlers::jwks))
        // Client management (TODO: implement when OAuth2Service is integrated)
        // .route("/oauth2/clients", post(handlers::register_client))
        // .route("/oauth2/clients", get(handlers::list_clients))
        // .route("/oauth2/clients/:client_id", get(handlers::get_client))
        // .route("/oauth2/clients/:client_id", put(handlers::update_client))
        // .route("/oauth2/clients/:client_id", delete(handlers::delete_client))
        ;

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
        .merge(oauth2_routes)
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
