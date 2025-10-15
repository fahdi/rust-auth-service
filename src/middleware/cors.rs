use axum::http::HeaderValue;
use tower_http::cors::{Any, CorsLayer};

/// Create CORS layer for development
/// Allows all origins, methods, and headers
pub fn create_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::PATCH,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers(Any)
        .allow_origin(Any)
}

/// Create CORS layer for production
/// More restrictive CORS configuration
#[allow(dead_code)]
pub fn create_production_cors_layer(allowed_origins: Vec<&str>) -> CorsLayer {
    let mut cors = CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::PATCH,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
        ]);

    for origin in allowed_origins {
        let header_value = HeaderValue::from_str(origin).unwrap();
        cors = cors.allow_origin(header_value);
    }

    cors
}
