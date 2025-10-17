use axum::{
    body::Body,
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use tracing::{debug, error};

use crate::{metrics, AppState};

/// Prometheus metrics endpoint
///
/// Returns metrics in Prometheus text format for scraping by monitoring systems.
/// Includes HTTP metrics, authentication metrics, database metrics, cache metrics,
/// and custom business metrics.
pub async fn metrics_handler(State(_state): State<AppState>) -> impl IntoResponse {
    debug!("Serving Prometheus metrics");

    match metrics::get_metrics_text() {
        Ok(metrics_text) => {
            debug!(
                "Successfully generated metrics text ({} bytes)",
                metrics_text.len()
            );

            Response::builder()
                .status(StatusCode::OK)
                .header(
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )
                .body(Body::from(metrics_text))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to generate metrics: {}", e);

            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("Error generating metrics"))
                .unwrap()
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, AppState, oauth2::OAuth2Service};
    use axum::extract::State;
    use std::sync::Arc;

    async fn create_test_state() -> AppState {
        let config = Config::default();
        let database = crate::database::create_database(&config.database)
            .await
            .expect("Failed to create test database");

        let cache_provider = crate::cache::create_cache_provider(&config.cache)
            .await
            .expect("Failed to create cache provider");
        let cache_service = crate::cache::CacheService::new(cache_provider, config.cache.ttl);

        let oauth2_config = crate::oauth2::OAuth2Config::default();
        let private_key = b"an-insanely-long-and-secure-secret-key-for-testing-purposes-only";
        let token_manager = crate::oauth2::tokens::TokenManager::new(
            oauth2_config.clone(),
            private_key,
            None,
        )
        .expect("Failed to create token manager");

        let oauth2_service: Arc<dyn OAuth2Service> = Arc::new(crate::oauth2::server::StubOAuth2Service);
        let oauth2_server = crate::oauth2::server::OAuth2Server::new(
            oauth2_config,
            oauth2_service,
            token_manager.clone(),
        );

        AppState {
            config: Arc::new(config),
            database: Arc::from(database),
            cache: Arc::new(cache_service),
            oauth2_server: Arc::new(oauth2_server),
            token_manager: Arc::new(token_manager),
        }
    }

    #[tokio::test]
    async fn test_metrics_handler() {
        // Initialize metrics first
        crate::metrics::Metrics::init();

        let state = create_test_state().await;
        let response = metrics_handler(State(state)).await.into_response();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.starts_with("text/plain"));
    }

    #[tokio::test]
    async fn test_stats_handler() {
        let state = create_test_state().await;
        let response = stats_handler(State(state)).await.into_response();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(content_type, "application/json");
    }
}
