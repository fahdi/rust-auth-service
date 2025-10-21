pub mod logging;
pub mod metrics;
pub mod tracing;

pub use logging::*;
pub use metrics::*;
pub use tracing::*;

use anyhow::Result;
use std::sync::Arc;

/// Comprehensive observability configuration
#[derive(Debug, Clone, Default)]
pub struct ObservabilityConfig {
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub tracing: TracingConfig,
}

/// Initialize comprehensive observability stack
pub async fn init_observability(config: &ObservabilityConfig) -> Result<Arc<AppMetrics>> {
    // Initialize structured logging
    init_logging(&config.logging)?;
    ::tracing::info!("Structured logging initialized");

    // Initialize metrics collection
    let metrics = Arc::new(AppMetrics::new()?);
    ::tracing::info!("Metrics collection initialized");

    // Initialize distributed tracing
    init_tracing(&config.tracing).await?;
    ::tracing::info!("Distributed tracing initialized");

    // Start background metrics collection
    if config.metrics.enabled {
        let metrics_clone = Arc::clone(&metrics);
        let collection_interval = config.metrics.collection_interval_secs;
        tokio::spawn(async move {
            start_system_metrics_collector(metrics_clone, collection_interval).await;
        });
        ::tracing::info!(
            interval_secs = config.metrics.collection_interval_secs,
            "Background metrics collection started"
        );
    }

    ::tracing::info!("Comprehensive observability stack initialized successfully");
    Ok(metrics)
}
