use anyhow::Result;
use axum::{
    extract::Extension,
    http::Method,
    routing::{get, post},
    Router,
};
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
// mod handlers;
// mod models;
// mod services;
// mod database;
// mod cache;
// mod email;
// mod middleware;
mod utils;

use config::Config;
// use handlers::{auth, health, user};

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

    // // Initialize database
    // let database = database::create_database(&config.database).await?;
    // info!("Database connection established");

    // // Initialize cache
    // let cache = cache::create_cache(&config.cache).await?;
    // info!("Cache initialized");

    // // Initialize email service
    // let email_service = email::create_email_service(&config.email).await?;
    // info!("Email service initialized");

    // // Build application state
    // let app_state = AppState {
    //     config: config.clone(),
    //     database,
    //     cache,
    //     email_service,
    // };

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(Any)
        .allow_origin(Any);

    // // Build router
    // let app = Router::new()
    //     .route("/health", get(health::health_check))
    //     .route("/metrics", get(health::metrics))
    //     .route("/auth/register", post(auth::register))
    //     .route("/auth/login", post(auth::login))
    //     .route("/auth/verify", post(auth::verify))
    //     .route("/auth/forgot-password", post(auth::forgot_password))
    //     .route("/auth/reset-password", post(auth::reset_password))
    //     .route("/auth/refresh", post(auth::refresh))
    //     .route("/auth/me", get(auth::me))
    //     .route("/auth/profile", post(auth::update_profile))
    //     .route("/auth/logout", post(auth::logout))
    //     .layer(cors)
    //     .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()))
    //     .layer(Extension(app_state));

    // Temporary simple router for testing
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
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
