use anyhow::Result;
use axum::{
    extract::State,
    middleware::from_fn_with_state,
    routing::{get, post, put},
    Router,
};
use observability::{AppMetrics, LoggingConfig, MetricsConfig};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
// OpenAPI/Swagger removed due to unmaintained dependencies (RUSTSEC-2024-0370)

mod admin;
mod config;
mod errors;
mod handlers;
mod metrics;
// mod mfa;  // Unused - removing for clean foundation
mod models;
// mod oauth2;
mod observability;
// mod services;
mod cache;
mod database;
mod email;
mod middleware;
mod migrations;
mod utils;

// For now, avoid library re-exports to fix compilation
use cache::CacheService;
use config::Config;
use email::EmailService;

// Application state for this binary
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub database: Arc<dyn database::AuthDatabase>,
    pub cache: Arc<CacheService>,
    pub email: Arc<EmailService>,
    pub metrics: Arc<AppMetrics>,
}

// OpenAPI documentation configuration removed due to security vulnerabilities

/// Handler for Prometheus metrics endpoint
async fn observability_metrics_handler(
    State(state): State<AppState>,
) -> Result<String, (axum::http::StatusCode, String)> {
    match state.metrics.gather() {
        Ok(metrics) => Ok(metrics),
        Err(e) => {
            error!("Failed to gather metrics: {}", e);
            Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to gather metrics".to_string(),
            ))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize comprehensive observability
    let logging_config = LoggingConfig::default();
    let metrics_config = MetricsConfig::default();

    // Initialize structured logging
    observability::init_logging(&logging_config)?;
    info!("Structured logging initialized");

    // Initialize metrics collection
    let app_metrics = Arc::new(AppMetrics::new()?);
    info!("Metrics collection initialized");

    info!(
        service = "rust-auth-service",
        version = env!("CARGO_PKG_VERSION"),
        "Starting Rust Auth Service with comprehensive observability"
    );

    // Load configuration
    let config = Config::from_env_and_file()?;
    info!("Configuration loaded successfully");

    // Initialize metrics if enabled
    if config.monitoring.metrics {
        metrics::Metrics::init();
        info!("Prometheus metrics initialized");
    }

    // Initialize database using local function
    let database = database::create_database(&config.database).await?;
    info!("Database connection established");

    // Initialize cache
    let cache_provider = cache::create_cache_provider(&config.cache).await?;
    let cache_service = CacheService::new(cache_provider, config.cache.ttl);
    info!("Cache system initialized");

    // Initialize email service
    let email_service = EmailService::new(&config.email).await?;
    info!("Email service initialized with provider: {}", email_service.provider_name());

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

    // Start system metrics collection background task
    let metrics_clone = app_metrics.clone();
    tokio::spawn(async move {
        observability::start_system_metrics_collector(
            metrics_clone,
            metrics_config.collection_interval_secs,
        )
        .await;
    });

    // Build application state using local types
    let app_state = AppState {
        config: Arc::new(config.clone()),
        database: Arc::from(database), // Convert Box<dyn AuthDatabase> to Arc<dyn AuthDatabase>
        cache: Arc::new(cache_service),
        email: Arc::new(email_service),
        metrics: app_metrics,
    };

    // Build public routes (no authentication required)
    let public_routes = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::ready_check))
        .route("/live", get(handlers::liveness_check))
        .route("/metrics", get(observability_metrics_handler))
        .route("/stats", get(handlers::stats_handler))
        .route("/auth/register", post(handlers::register))
        .route("/auth/login", post(handlers::login))
        .route("/auth/verify", post(handlers::verify_email))
        .route("/auth/forgot-password", post(handlers::forgot_password))
        .route("/auth/reset-password", post(handlers::reset_password))
        .route("/auth/refresh", post(handlers::refresh_token));

    // TODO: Build OAuth2 routes when OAuth2 module is re-enabled
    // let oauth2_routes = Router::new()
    //     // Authorization endpoints
    //     .route("/oauth2/authorize", get(handlers::authorize))
    //     .route("/oauth2/authorize", post(handlers::authorize_consent_post))
    //     .route("/oauth2/token", post(handlers::token))
    //     .route("/oauth2/revoke", post(handlers::revoke))
    //     .route("/oauth2/introspect", post(handlers::introspect))
    //     // Device flow endpoints
    //     .route("/oauth2/device/authorize", post(handlers::device_authorization))
    //     .route("/oauth2/device/verify", get(handlers::device_verify))
    //     .route("/oauth2/device/verify", post(handlers::device_verify_post))
    //     // Metadata and discovery
    //     .route("/.well-known/oauth-authorization-server", get(handlers::metadata))
    //     .route("/.well-known/jwks.json", get(handlers::jwks))
    //     // Client management (TODO: implement when OAuth2Service is integrated)
    //     // .route("/oauth2/clients", post(handlers::register_client))
    //     // .route("/oauth2/clients", get(handlers::list_clients))
    //     // .route("/oauth2/clients/:client_id", get(handlers::get_client))
    //     // .route("/oauth2/clients/:client_id", put(handlers::update_client))
    //     // .route("/oauth2/clients/:client_id", delete(handlers::delete_client))
    //     ;

    // Build protected routes (authentication required)
    let protected_routes = Router::new()
        .route("/auth/me", get(handlers::get_profile))
        .route("/auth/profile", put(handlers::update_profile))
        .route("/auth/logout", post(handlers::logout))
        .route_layer(from_fn_with_state(
            app_state.clone(),
            middleware::jwt_auth_middleware,
        ));

    // Build admin routes (admin authentication required)
    let admin_routes = Router::new()
        // Admin dashboard HTML page
        .route("/admin", get(admin::admin_dashboard))
        // Admin API endpoints
        .route("/admin/api/stats", get(admin::get_dashboard_stats))
        .route("/admin/api/metrics", get(admin::get_system_metrics))
        .route("/admin/api/users", get(admin::list_users))
        .route("/admin/api/users/search", get(admin::search_users))
        .route("/admin/api/users/export", get(admin::export_users))
        .route("/admin/api/users/:user_id", get(admin::get_user_details))
        .route(
            "/admin/api/users/:user_id/action",
            post(admin::admin_user_action),
        )
        .route("/admin/api/clients", get(admin::list_oauth2_clients))
        .route(
            "/admin/api/security/events",
            get(admin::list_security_events),
        )
        .route_layer(from_fn_with_state(
            app_state.clone(),
            middleware::jwt_auth_middleware,
        ));

    // Swagger UI documentation routes removed due to security vulnerabilities

    // Combine all routes
    let app = Router::new()
        .merge(public_routes)
        // .merge(oauth2_routes)  // Disabled until OAuth2 module is integrated
        .merge(protected_routes)
        .merge(admin_routes)
        // .merge(docs_routes)  // Removed due to security vulnerabilities
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

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

// #[derive(Clone)]
// pub struct AppState {
//     pub config: Config,
//     pub database: Box<dyn database::AuthDatabase>,
//     pub cache: Box<dyn cache::CacheProvider>,
//     pub email_service: Box<dyn email::EmailProvider>,
// }
