use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::Subscriber;
use tracing_subscriber::{
    fmt::{self, time::ChronoUtc},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Log format (json, pretty, compact)
    pub format: LogFormat,
    /// Output destination
    pub output: LogOutput,
    /// Include source code location
    pub include_location: bool,
    /// Include target module path
    pub include_target: bool,
    /// Include thread ID
    pub include_thread_id: bool,
    /// Include span information
    pub include_spans: bool,
    /// Custom fields to include in all log entries
    pub custom_fields: HashMap<String, String>,
    /// Log file rotation settings
    pub rotation: Option<LogRotation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    Json,
    Pretty,
    Compact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogOutput {
    Stdout,
    Stderr,
    File { path: String },
    Syslog,
    Multiple(Vec<LogOutput>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotation {
    pub max_size_mb: u64,
    pub max_files: u32,
    pub daily: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Json,
            output: LogOutput::Stdout,
            include_location: false,
            include_target: true,
            include_thread_id: false,
            include_spans: true,
            custom_fields: HashMap::new(),
            rotation: None,
        }
    }
}

/// Structured logging context for requests
#[derive(Debug, Clone, Serialize)]
pub struct RequestContext {
    pub request_id: String,
    pub user_id: Option<String>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub method: String,
    pub path: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub custom_fields: HashMap<String, String>,
}

impl RequestContext {
    #[allow(dead_code)]
    pub fn new(request_id: String, ip_address: String, method: String, path: String) -> Self {
        Self {
            request_id,
            user_id: None,
            ip_address,
            user_agent: None,
            method,
            path,
            start_time: chrono::Utc::now(),
            custom_fields: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    #[allow(dead_code)]
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    #[allow(dead_code)]
    pub fn with_custom_field(mut self, key: String, value: String) -> Self {
        self.custom_fields.insert(key, value);
        self
    }

    #[allow(dead_code)]
    pub fn elapsed_ms(&self) -> u64 {
        let elapsed = chrono::Utc::now().signed_duration_since(self.start_time);
        elapsed.num_milliseconds().max(0) as u64
    }
}

/// Security event context for audit logging
#[derive(Debug, Clone, Serialize)]
pub struct SecurityContext {
    pub event_type: SecurityEventType,
    pub user_id: Option<String>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub risk_level: RiskLevel,
    pub details: HashMap<String, serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub enum SecurityEventType {
    LoginAttempt,
    LoginSuccess,
    LoginFailure,
    LogoutSuccess,
    PasswordReset,
    EmailVerification,
    AccountLocked,
    AccountUnlocked,
    PermissionDenied,
    TokenIssued,
    TokenRevoked,
    SuspiciousActivity,
    RateLimitExceeded,
    AdminAction,
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Performance context for monitoring
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PerformanceContext {
    pub operation: String,
    pub component: String,
    pub start_time: std::time::Instant,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl PerformanceContext {
    #[allow(dead_code)]
    pub fn new(operation: String, component: String) -> Self {
        Self {
            operation,
            component,
            start_time: std::time::Instant::now(),
            metadata: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }

    #[allow(dead_code)]
    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}

/// Custom log layer for structured logging
pub struct StructuredLogLayer {
    service_name: String,
    version: String,
    environment: String,
}

impl StructuredLogLayer {
    #[allow(dead_code)]
    pub fn new(service_name: String, version: String, environment: String) -> Self {
        Self {
            service_name,
            version,
            environment,
        }
    }
}

impl<S> Layer<S> for StructuredLogLayer
where
    S: Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let metadata = event.metadata();

        // Extract structured data from event
        let mut visitor = JsonVisitor::new();
        event.record(&mut visitor);

        let mut json_data = visitor.into_map();

        // Add service metadata
        json_data.insert(
            "service".to_string(),
            serde_json::Value::String(self.service_name.clone()),
        );
        json_data.insert(
            "version".to_string(),
            serde_json::Value::String(self.version.clone()),
        );
        json_data.insert(
            "environment".to_string(),
            serde_json::Value::String(self.environment.clone()),
        );
        json_data.insert(
            "timestamp".to_string(),
            serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
        );
        json_data.insert(
            "level".to_string(),
            serde_json::Value::String(metadata.level().to_string()),
        );
        json_data.insert(
            "target".to_string(),
            serde_json::Value::String(metadata.target().to_string()),
        );

        // Print structured log
        println!("{}", serde_json::to_string(&json_data).unwrap_or_default());
    }
}

/// Custom visitor for extracting JSON data from tracing events
struct JsonVisitor {
    map: std::collections::HashMap<String, serde_json::Value>,
}

impl JsonVisitor {
    fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
        }
    }

    fn into_map(self) -> std::collections::HashMap<String, serde_json::Value> {
        self.map
    }
}

impl tracing::field::Visit for JsonVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.map.insert(
            field.name().to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.map.insert(
            field.name().to_string(),
            serde_json::Value::String(format!("{value:?}")),
        );
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.map.insert(
            field.name().to_string(),
            serde_json::Value::Number(serde_json::Number::from(value)),
        );
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.map.insert(
            field.name().to_string(),
            serde_json::Value::Number(serde_json::Number::from(value)),
        );
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.map
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if let Some(num) = serde_json::Number::from_f64(value) {
            self.map
                .insert(field.name().to_string(), serde_json::Value::Number(num));
        }
    }
}

/// Initialize structured logging
pub fn init_logging(config: &LoggingConfig) -> Result<()> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));

    match config.format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_timer(ChronoUtc::rfc_3339()))
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().pretty().with_timer(ChronoUtc::rfc_3339()))
                .init();
        }
        LogFormat::Compact => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().compact().with_timer(ChronoUtc::rfc_3339()))
                .init();
        }
    }

    Ok(())
}

/// Log a request with structured context
#[allow(dead_code)]
pub fn log_request(ctx: &RequestContext, status_code: u16, response_size: Option<usize>) {
    let duration_ms = ctx.elapsed_ms();

    tracing::info!(
        request_id = %ctx.request_id,
        user_id = ?ctx.user_id,
        ip_address = %ctx.ip_address,
        user_agent = ?ctx.user_agent,
        method = %ctx.method,
        path = %ctx.path,
        status_code = status_code,
        duration_ms = duration_ms,
        response_size = ?response_size,
        "HTTP request completed"
    );
}

/// Log a security event
#[allow(dead_code)]
pub fn log_security_event(ctx: &SecurityContext) {
    match ctx.risk_level {
        RiskLevel::Critical => {
            tracing::error!(
                event_type = ?ctx.event_type,
                user_id = ?ctx.user_id,
                ip_address = %ctx.ip_address,
                user_agent = ?ctx.user_agent,
                risk_level = ?ctx.risk_level,
                details = ?ctx.details,
                timestamp = %ctx.timestamp.to_rfc3339(),
                "Security event - CRITICAL"
            );
        }
        RiskLevel::High => {
            tracing::warn!(
                event_type = ?ctx.event_type,
                user_id = ?ctx.user_id,
                ip_address = %ctx.ip_address,
                user_agent = ?ctx.user_agent,
                risk_level = ?ctx.risk_level,
                details = ?ctx.details,
                timestamp = %ctx.timestamp.to_rfc3339(),
                "Security event - HIGH"
            );
        }
        RiskLevel::Medium | RiskLevel::Low => {
            tracing::info!(
                event_type = ?ctx.event_type,
                user_id = ?ctx.user_id,
                ip_address = %ctx.ip_address,
                user_agent = ?ctx.user_agent,
                risk_level = ?ctx.risk_level,
                details = ?ctx.details,
                timestamp = %ctx.timestamp.to_rfc3339(),
                "Security event"
            );
        }
    }
}

/// Log performance metrics
#[allow(dead_code)]
pub fn log_performance(ctx: &PerformanceContext, success: bool) {
    let duration_ms = ctx.elapsed_ms();

    if duration_ms > 1000 {
        tracing::warn!(
            operation = %ctx.operation,
            component = %ctx.component,
            duration_ms = duration_ms,
            success = success,
            metadata = ?ctx.metadata,
            "Slow operation detected"
        );
    } else {
        tracing::debug!(
            operation = %ctx.operation,
            component = %ctx.component,
            duration_ms = duration_ms,
            success = success,
            metadata = ?ctx.metadata,
            "Operation completed"
        );
    }
}

/// Create a span for distributed tracing
#[macro_export]
macro_rules! trace_span {
    ($name:expr) => {
        tracing::info_span!($name)
    };
    ($name:expr, $($field:tt)*) => {
        tracing::info_span!($name, $($field)*)
    };
}

/// Create an async span for distributed tracing
#[macro_export]
macro_rules! trace_async_span {
    ($name:expr) => {
        tracing::info_span!($name).entered()
    };
    ($name:expr, $($field:tt)*) => {
        tracing::info_span!($name, $($field)*).entered()
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_context_creation() {
        let ctx = RequestContext::new(
            "req-123".to_string(),
            "192.168.1.1".to_string(),
            "GET".to_string(),
            "/api/users".to_string(),
        );

        assert_eq!(ctx.request_id, "req-123");
        assert_eq!(ctx.ip_address, "192.168.1.1");
        assert_eq!(ctx.method, "GET");
        assert_eq!(ctx.path, "/api/users");
        assert!(ctx.user_id.is_none());
    }

    #[test]
    fn test_request_context_with_user() {
        let ctx = RequestContext::new(
            "req-123".to_string(),
            "192.168.1.1".to_string(),
            "GET".to_string(),
            "/api/users".to_string(),
        )
        .with_user("user-456".to_string());

        assert_eq!(ctx.user_id, Some("user-456".to_string()));
    }

    #[test]
    fn test_performance_context() {
        let ctx = PerformanceContext::new("database_query".to_string(), "user_service".to_string());

        assert_eq!(ctx.operation, "database_query");
        assert_eq!(ctx.component, "user_service");
        assert!(ctx.elapsed_ms() < 100); // Should be very fast in tests
    }
}
