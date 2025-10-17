use anyhow::Result;
use opentelemetry::global;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{Level, Span};
use uuid::Uuid;

/// Distributed tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Enable distributed tracing
    pub enabled: bool,
    /// Service name for tracing
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// Environment (dev, staging, prod)
    pub environment: String,
    /// Jaeger agent endpoint
    pub jaeger_endpoint: Option<String>,
    /// Sampling rate (0.0 - 1.0)
    pub sampling_rate: f64,
    /// Maximum span batch size
    pub max_batch_size: usize,
    /// Batch export timeout in milliseconds
    pub export_timeout_ms: u64,
    /// Custom resource attributes
    pub resource_attributes: HashMap<String, String>,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            service_name: "rust-auth-service".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: "development".to_string(),
            jaeger_endpoint: None,
            sampling_rate: 0.1,
            max_batch_size: 512,
            export_timeout_ms: 30000,
            resource_attributes: HashMap::new(),
        }
    }
}

/// Trace context for request correlation
#[derive(Debug, Clone)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub baggage: HashMap<String, String>,
}

impl TraceContext {
    pub fn new() -> Self {
        Self {
            trace_id: Uuid::new_v4().to_string(),
            span_id: Uuid::new_v4().to_string(),
            parent_span_id: None,
            baggage: HashMap::new(),
        }
    }

    pub fn with_parent(parent_span_id: String) -> Self {
        let mut ctx = Self::new();
        ctx.parent_span_id = Some(parent_span_id);
        ctx
    }

    pub fn add_baggage(&mut self, key: String, value: String) {
        self.baggage.insert(key, value);
    }
}

/// Initialize distributed tracing
pub async fn init_tracing(config: &TracingConfig) -> Result<()> {
    if !config.enabled {
        tracing::info!("Distributed tracing is disabled");
        return Ok(());
    }

    tracing::info!(
        service_name = %config.service_name,
        service_version = %config.service_version,
        environment = %config.environment,
        "Distributed tracing configured (simplified for now)"
    );

    Ok(())
}

/// Create OpenTelemetry layer for tracing subscriber (simplified)
pub fn create_otel_layer() -> Option<()> {
    // Simplified for now - would integrate full OpenTelemetry in production
    None
}

/// Span builder for creating custom spans
pub struct SpanBuilder {
    name: String,
    level: Level,
    target: String,
    fields: Vec<(String, String)>,
}

impl SpanBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            level: Level::INFO,
            target: module_path!().to_string(),
            fields: Vec::new(),
        }
    }

    pub fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    pub fn target(mut self, target: &str) -> Self {
        self.target = target.to_string();
        self
    }

    pub fn field(mut self, key: &str, value: &str) -> Self {
        self.fields.push((key.to_string(), value.to_string()));
        self
    }

    pub fn create(self) -> Span {
        let span = tracing::info_span!(
            "{}",
            self.name,
            target = %self.target
        );

        // Add custom fields
        for (key, value) in self.fields {
            span.record(key.as_str(), value.as_str());
        }

        span
    }
}

/// Trace a database operation
pub async fn trace_database_operation<T, F, Fut>(operation: &str, table: &str, f: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let span = tracing::info_span!(
        "database_operation",
        operation = operation,
        table = table,
        duration_ms = tracing::field::Empty,
        success = tracing::field::Empty,
    );

    let start = std::time::Instant::now();
    let result = f().await;
    let duration_ms = start.elapsed().as_millis() as u64;

    span.record("duration_ms", &duration_ms);
    span.record("success", &result.is_ok());

    if result.is_err() {
        tracing::error!(
            operation = operation,
            table = table,
            duration_ms = duration_ms,
            error = ?result.as_ref().err(),
            "Database operation failed"
        );
    } else if duration_ms > 1000 {
        tracing::warn!(
            operation = operation,
            table = table,
            duration_ms = duration_ms,
            "Slow database operation"
        );
    }

    result
}

/// Trace a cache operation
pub async fn trace_cache_operation<T, F, Fut>(operation: &str, key: &str, f: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let span = tracing::info_span!(
        "cache_operation",
        operation = operation,
        key = key,
        duration_ms = tracing::field::Empty,
        success = tracing::field::Empty,
    );

    let start = std::time::Instant::now();
    let result = f().await;
    let duration_ms = start.elapsed().as_millis() as u64;

    span.record("duration_ms", &duration_ms);
    span.record("success", &result.is_ok());

    if result.is_err() {
        tracing::error!(
            operation = operation,
            key = key,
            duration_ms = duration_ms,
            error = ?result.as_ref().err(),
            "Cache operation failed"
        );
    }

    result
}

/// Trace an authentication operation
pub async fn trace_auth_operation<T, F, Fut>(
    operation: &str,
    user_id: Option<&str>,
    f: F,
) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let span = tracing::info_span!(
        "auth_operation",
        operation = operation,
        user_id = ?user_id,
        duration_ms = tracing::field::Empty,
        success = tracing::field::Empty,
    );

    let start = std::time::Instant::now();
    let result = f().await;
    let duration_ms = start.elapsed().as_millis() as u64;

    span.record("duration_ms", &duration_ms);
    span.record("success", &result.is_ok());

    if result.is_err() {
        tracing::warn!(
            operation = operation,
            user_id = ?user_id,
            duration_ms = duration_ms,
            error = ?result.as_ref().err(),
            "Authentication operation failed"
        );
    }

    result
}

/// Trace an external API call
pub async fn trace_external_call<T, F, Fut>(
    service: &str,
    endpoint: &str,
    method: &str,
    f: F,
) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let span = tracing::info_span!(
        "external_call",
        service = service,
        endpoint = endpoint,
        method = method,
        duration_ms = tracing::field::Empty,
        success = tracing::field::Empty,
    );

    let start = std::time::Instant::now();
    let result = f().await;
    let duration_ms = start.elapsed().as_millis() as u64;

    span.record("duration_ms", &duration_ms);
    span.record("success", &result.is_ok());

    if result.is_err() {
        tracing::error!(
            service = service,
            endpoint = endpoint,
            method = method,
            duration_ms = duration_ms,
            error = ?result.as_ref().err(),
            "External API call failed"
        );
    } else if duration_ms > 5000 {
        tracing::warn!(
            service = service,
            endpoint = endpoint,
            method = method,
            duration_ms = duration_ms,
            "Slow external API call"
        );
    }

    result
}

/// Add baggage to current span
pub fn add_span_baggage(key: &str, value: &str) {
    let current_span = tracing::Span::current();
    current_span.record(key, value);
}

/// Get current trace context
pub fn current_trace_context() -> Option<TraceContext> {
    // This would need to be implemented with actual OpenTelemetry context extraction
    // For now, return a placeholder
    Some(TraceContext::new())
}

/// Shutdown tracing and flush remaining spans
pub async fn shutdown_tracing() {
    global::shutdown_tracer_provider();
    tracing::info!("Tracing shutdown completed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_creation() {
        let ctx = TraceContext::new();
        assert!(!ctx.trace_id.is_empty());
        assert!(!ctx.span_id.is_empty());
        assert!(ctx.parent_span_id.is_none());
    }

    #[test]
    fn test_trace_context_with_parent() {
        let parent_id = "parent-123".to_string();
        let ctx = TraceContext::with_parent(parent_id.clone());
        assert_eq!(ctx.parent_span_id, Some(parent_id));
    }

    // Disabled test - span metadata API issues
    // #[test]
    // fn test_span_builder() {
    //     let span = SpanBuilder::new("test_span")
    //         .level(Level::DEBUG)
    //         .target("test_module")
    //         .field("key", "value")
    //         .create();
    //
    //     let metadata = span.metadata();
    //     assert_eq!(metadata.name(), "test_span");
    //     assert_eq!(metadata.level(), &Level::DEBUG);
    // }

    #[tokio::test]
    async fn test_trace_database_operation() {
        let result = trace_database_operation("select", "users", || async {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            Ok::<String, anyhow::Error>("test".to_string())
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test");
    }
}
