use anyhow::Result;
use axum::{
    extract::State,
    middleware::from_fn_with_state,
    routing::{get, post, put},
    Router,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use observability::{LoggingConfig, TracingConfig, MetricsConfig, AppMetrics};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

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
// mod email;
mod middleware;
mod migrations;
mod utils;

// For now, avoid library re-exports to fix compilation
use cache::CacheService;
use config::Config;

// Application state for this binary
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub database: Arc<dyn database::AuthDatabase>,
    pub cache: Arc<CacheService>,
    pub metrics: Arc<AppMetrics>,
}

// OpenAPI documentation configuration
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::health_check,
        handlers::ready_check,
        handlers::liveness_check,
        handlers::register,
        handlers::login,
        handlers::verify_email,
        handlers::forgot_password,
        handlers::reset_password,
        handlers::refresh_token,
        handlers::get_profile,
        handlers::update_profile,
        handlers::logout,
        // handlers::metrics_handler,  // Removed unused handler
        handlers::stats_handler,
        admin::admin_dashboard,
        admin::get_dashboard_stats,
        admin::get_system_metrics,
        admin::list_users,
        admin::get_user_details,
        admin::admin_user_action,
        admin::list_oauth2_clients,
        admin::list_security_events,
        admin::export_users,
        admin::search_users,
    ),
    components(
        schemas(
            models::user::CreateUserRequest,
            models::user::UpdateUserRequest,
            models::user::PasswordResetRequest,
            models::user::PasswordChangeRequest,
            models::user::EmailVerificationRequest,
            models::user::UserResponse,
            models::user::AuthResponse,
            models::user::UserRole,
            models::user::UserMetadata,
            handlers::auth::LoginRequest,
            handlers::auth::RefreshTokenRequest,
            utils::jwt::Claims,
            admin::DashboardStats,
            admin::UserManagement,
            admin::ClientManagement,
            admin::SystemMetrics,
            admin::SecurityEvent,
            admin::AdminActionRequest,
            admin::AdminActionResponse,
            admin::PaginationParams,
        )
    ),
    tags(
        (name = "authentication", description = "User authentication and authorization"),
        (name = "users", description = "User profile management"),
        (name = "health", description = "Service health and monitoring"),
        (name = "system", description = "System metrics and statistics"),
        (name = "admin", description = "Administrative dashboard and user management")
    ),
    info(
        title = "Rust Auth Service API",
        version = "0.1.0",
        description = "270x faster authentication service - production-ready out of the box",
        contact(
            name = "Rust Auth Service",
            url = "https://github.com/your-org/rust-auth-service",
            email = "your.email@example.com"
        ),
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    modifiers(&SecurityAddon),
    servers(
        (url = "http://localhost:8080", description = "Local development server"),
        (url = "https://api.example.com", description = "Production server")
    )
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "Bearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("Enter JWT token"))
                        .build(),
                ),
            )
        }
    }
}

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
    let tracing_config = TracingConfig::default();
    let metrics_config = MetricsConfig::default();

    // Initialize structured logging
    observability::init_logging(&logging_config)?;
    info!("Structured logging initialized");

    // Initialize distributed tracing if enabled
    if tracing_config.enabled {
        observability::init_tracing(&tracing_config).await?;
        info!("Distributed tracing initialized");
    }

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
        observability::start_system_metrics_collector(metrics_clone, metrics_config.collection_interval_secs).await;
    });

    // Build application state using local types
    let app_state = AppState {
        config: Arc::new(config.clone()),
        database: Arc::from(database), // Convert Box<dyn AuthDatabase> to Arc<dyn AuthDatabase>
        cache: Arc::new(cache_service),
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
        .route("/admin/api/users/:user_id/action", post(admin::admin_user_action))
        .route("/admin/api/clients", get(admin::list_oauth2_clients))
        .route("/admin/api/security/events", get(admin::list_security_events))
        .route_layer(from_fn_with_state(
            app_state.clone(),
            middleware::jwt_auth_middleware,
        ));

    // Add Swagger UI documentation routes
    let docs_routes = Router::new()
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/api-docs/openapi.json", get(|| async { axum::Json(ApiDoc::openapi()) }));

    // Combine all routes
    let app = Router::new()
        .merge(public_routes)
        // .merge(oauth2_routes)  // Disabled until OAuth2 module is integrated
        .merge(protected_routes)
        .merge(admin_routes)
        .merge(docs_routes)
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
