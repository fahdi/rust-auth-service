use anyhow::Result;
use prometheus::{
    Counter, CounterVec, Encoder, Gauge, GaugeVec, HistogramVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::interval;

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,
    /// Metrics endpoint path
    pub endpoint: String,
    /// Collection interval in seconds
    pub collection_interval_secs: u64,
    /// Enable high cardinality metrics
    pub enable_high_cardinality: bool,
    /// Custom labels to add to all metrics
    pub global_labels: HashMap<String, String>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "/metrics".to_string(),
            collection_interval_secs: 15,
            enable_high_cardinality: false,
            global_labels: HashMap::new(),
        }
    }
}

/// Application metrics collector
#[derive(Clone)]
pub struct AppMetrics {
    registry: Arc<Registry>,

    // HTTP metrics
    pub http_requests_total: CounterVec,
    pub http_request_duration: HistogramVec,
    pub http_request_size: HistogramVec,
    pub http_response_size: HistogramVec,
    pub http_requests_in_flight: IntGaugeVec,

    // Authentication metrics
    pub auth_attempts_total: CounterVec,
    pub auth_successes_total: CounterVec,
    pub auth_failures_total: CounterVec,
    pub auth_duration: HistogramVec,
    pub active_sessions: IntGauge,
    pub token_validations_total: CounterVec,

    // Database metrics
    pub db_connections_active: IntGauge,
    pub db_connections_idle: IntGauge,
    pub db_query_duration: HistogramVec,
    pub db_queries_total: CounterVec,
    pub db_connection_errors: Counter,

    // Cache metrics
    pub cache_operations_total: CounterVec,
    pub cache_hits_total: Counter,
    pub cache_misses_total: Counter,
    pub cache_evictions_total: Counter,
    pub cache_operation_duration: HistogramVec,
    pub cache_size_bytes: Gauge,

    // Business metrics
    pub user_registrations_total: Counter,
    pub user_logins_total: Counter,
    pub user_logouts_total: Counter,
    pub password_resets_total: Counter,
    pub email_verifications_total: Counter,

    // System metrics
    pub memory_usage_bytes: Gauge,
    pub cpu_usage_percent: Gauge,
    pub disk_usage_bytes: GaugeVec,
    pub network_connections: IntGauge,
    pub uptime_seconds: Counter,

    // Error metrics
    pub errors_total: CounterVec,
    pub panics_total: Counter,
    pub rate_limit_hits: CounterVec,

    // Performance metrics
    pub response_time_percentiles: HistogramVec,
    pub throughput_ops_per_second: Gauge,
    pub concurrent_requests: IntGauge,

    start_time: Instant,
}

impl AppMetrics {
    pub fn new() -> Result<Self> {
        let registry = Arc::new(Registry::new());

        // HTTP metrics
        let http_requests_total = CounterVec::new(
            Opts::new("http_requests_total", "Total number of HTTP requests"),
            &["method", "path", "status_code"],
        )?;

        let http_request_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method", "path"],
        )?;

        let http_request_size = HistogramVec::new(
            prometheus::HistogramOpts::new("http_request_size_bytes", "HTTP request size in bytes")
                .buckets(vec![100.0, 1000.0, 10000.0, 100000.0, 1000000.0]),
            &["method", "path"],
        )?;

        let http_response_size = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "http_response_size_bytes",
                "HTTP response size in bytes",
            )
            .buckets(vec![100.0, 1000.0, 10000.0, 100000.0, 1000000.0]),
            &["method", "path"],
        )?;

        let http_requests_in_flight = IntGaugeVec::new(
            Opts::new(
                "http_requests_in_flight",
                "Number of HTTP requests currently being processed",
            ),
            &["method", "path"],
        )?;

        // Authentication metrics
        let auth_attempts_total = CounterVec::new(
            Opts::new(
                "auth_attempts_total",
                "Total number of authentication attempts",
            ),
            &["method", "result"],
        )?;

        let auth_successes_total = CounterVec::new(
            Opts::new(
                "auth_successes_total",
                "Total number of successful authentications",
            ),
            &["method"],
        )?;

        let auth_failures_total = CounterVec::new(
            Opts::new(
                "auth_failures_total",
                "Total number of failed authentications",
            ),
            &["method", "reason"],
        )?;

        let auth_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "auth_duration_seconds",
                "Authentication operation duration",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
            &["method"],
        )?;

        let active_sessions = IntGauge::new("active_sessions", "Number of active user sessions")?;

        let token_validations_total = CounterVec::new(
            Opts::new(
                "token_validations_total",
                "Total number of token validations",
            ),
            &["result"],
        )?;

        // Database metrics
        let db_connections_active = IntGauge::new(
            "db_connections_active",
            "Number of active database connections",
        )?;

        let db_connections_idle =
            IntGauge::new("db_connections_idle", "Number of idle database connections")?;

        let db_query_duration = HistogramVec::new(
            prometheus::HistogramOpts::new("db_query_duration_seconds", "Database query duration")
                .buckets(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
                ]),
            &["operation", "table"],
        )?;

        let db_queries_total = CounterVec::new(
            Opts::new("db_queries_total", "Total number of database queries"),
            &["operation", "table", "result"],
        )?;

        let db_connection_errors = Counter::new(
            "db_connection_errors_total",
            "Total number of database connection errors",
        )?;

        // Cache metrics
        let cache_operations_total = CounterVec::new(
            Opts::new("cache_operations_total", "Total number of cache operations"),
            &["operation", "result"],
        )?;

        let cache_hits_total = Counter::new("cache_hits_total", "Total number of cache hits")?;

        let cache_misses_total =
            Counter::new("cache_misses_total", "Total number of cache misses")?;

        let cache_evictions_total =
            Counter::new("cache_evictions_total", "Total number of cache evictions")?;

        let cache_operation_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "cache_operation_duration_seconds",
                "Cache operation duration",
            )
            .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1]),
            &["operation"],
        )?;

        let cache_size_bytes = Gauge::new("cache_size_bytes", "Current cache size in bytes")?;

        // Business metrics
        let user_registrations_total = Counter::new(
            "user_registrations_total",
            "Total number of user registrations",
        )?;

        let user_logins_total = Counter::new("user_logins_total", "Total number of user logins")?;

        let user_logouts_total =
            Counter::new("user_logouts_total", "Total number of user logouts")?;

        let password_resets_total =
            Counter::new("password_resets_total", "Total number of password resets")?;

        let email_verifications_total = Counter::new(
            "email_verifications_total",
            "Total number of email verifications",
        )?;

        // System metrics
        let memory_usage_bytes = Gauge::new("memory_usage_bytes", "Current memory usage in bytes")?;

        let cpu_usage_percent = Gauge::new("cpu_usage_percent", "Current CPU usage percentage")?;

        let disk_usage_bytes = GaugeVec::new(
            Opts::new("disk_usage_bytes", "Current disk usage in bytes"),
            &["mount_point"],
        )?;

        let network_connections = IntGauge::new(
            "network_connections",
            "Number of active network connections",
        )?;

        let uptime_seconds = Counter::new("uptime_seconds_total", "Total uptime in seconds")?;

        // Error metrics
        let errors_total = CounterVec::new(
            Opts::new("errors_total", "Total number of errors"),
            &["type", "component"],
        )?;

        let panics_total = Counter::new("panics_total", "Total number of panics")?;

        let rate_limit_hits = CounterVec::new(
            Opts::new("rate_limit_hits_total", "Total number of rate limit hits"),
            &["endpoint", "user_id"],
        )?;

        // Performance metrics
        let response_time_percentiles = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "response_time_percentiles",
                "Response time percentiles",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
            &["endpoint"],
        )?;

        let throughput_ops_per_second = Gauge::new(
            "throughput_ops_per_second",
            "Current throughput in operations per second",
        )?;

        let concurrent_requests =
            IntGauge::new("concurrent_requests", "Number of concurrent requests")?;

        // Register all metrics
        registry.register(Box::new(http_requests_total.clone()))?;
        registry.register(Box::new(http_request_duration.clone()))?;
        registry.register(Box::new(http_request_size.clone()))?;
        registry.register(Box::new(http_response_size.clone()))?;
        registry.register(Box::new(http_requests_in_flight.clone()))?;

        registry.register(Box::new(auth_attempts_total.clone()))?;
        registry.register(Box::new(auth_successes_total.clone()))?;
        registry.register(Box::new(auth_failures_total.clone()))?;
        registry.register(Box::new(auth_duration.clone()))?;
        registry.register(Box::new(active_sessions.clone()))?;
        registry.register(Box::new(token_validations_total.clone()))?;

        registry.register(Box::new(db_connections_active.clone()))?;
        registry.register(Box::new(db_connections_idle.clone()))?;
        registry.register(Box::new(db_query_duration.clone()))?;
        registry.register(Box::new(db_queries_total.clone()))?;
        registry.register(Box::new(db_connection_errors.clone()))?;

        registry.register(Box::new(cache_operations_total.clone()))?;
        registry.register(Box::new(cache_hits_total.clone()))?;
        registry.register(Box::new(cache_misses_total.clone()))?;
        registry.register(Box::new(cache_evictions_total.clone()))?;
        registry.register(Box::new(cache_operation_duration.clone()))?;
        registry.register(Box::new(cache_size_bytes.clone()))?;

        registry.register(Box::new(user_registrations_total.clone()))?;
        registry.register(Box::new(user_logins_total.clone()))?;
        registry.register(Box::new(user_logouts_total.clone()))?;
        registry.register(Box::new(password_resets_total.clone()))?;
        registry.register(Box::new(email_verifications_total.clone()))?;

        registry.register(Box::new(memory_usage_bytes.clone()))?;
        registry.register(Box::new(cpu_usage_percent.clone()))?;
        registry.register(Box::new(disk_usage_bytes.clone()))?;
        registry.register(Box::new(network_connections.clone()))?;
        registry.register(Box::new(uptime_seconds.clone()))?;

        registry.register(Box::new(errors_total.clone()))?;
        registry.register(Box::new(panics_total.clone()))?;
        registry.register(Box::new(rate_limit_hits.clone()))?;

        registry.register(Box::new(response_time_percentiles.clone()))?;
        registry.register(Box::new(throughput_ops_per_second.clone()))?;
        registry.register(Box::new(concurrent_requests.clone()))?;

        Ok(Self {
            registry,
            http_requests_total,
            http_request_duration,
            http_request_size,
            http_response_size,
            http_requests_in_flight,
            auth_attempts_total,
            auth_successes_total,
            auth_failures_total,
            auth_duration,
            active_sessions,
            token_validations_total,
            db_connections_active,
            db_connections_idle,
            db_query_duration,
            db_queries_total,
            db_connection_errors,
            cache_operations_total,
            cache_hits_total,
            cache_misses_total,
            cache_evictions_total,
            cache_operation_duration,
            cache_size_bytes,
            user_registrations_total,
            user_logins_total,
            user_logouts_total,
            password_resets_total,
            email_verifications_total,
            memory_usage_bytes,
            cpu_usage_percent,
            disk_usage_bytes,
            network_connections,
            uptime_seconds,
            errors_total,
            panics_total,
            rate_limit_hits,
            response_time_percentiles,
            throughput_ops_per_second,
            concurrent_requests,
            start_time: Instant::now(),
        })
    }

    /// Get metrics as Prometheus text format
    pub fn gather(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut output = Vec::new();
        encoder.encode(&metric_families, &mut output)?;
        Ok(String::from_utf8(output)?)
    }

    /// Record an HTTP request
    pub fn record_http_request(
        &self,
        method: &str,
        path: &str,
        status_code: u16,
        duration: Duration,
        request_size: Option<usize>,
        response_size: Option<usize>,
    ) {
        self.http_requests_total
            .with_label_values(&[method, path, &status_code.to_string()])
            .inc();

        self.http_request_duration
            .with_label_values(&[method, path])
            .observe(duration.as_secs_f64());

        if let Some(size) = request_size {
            self.http_request_size
                .with_label_values(&[method, path])
                .observe(size as f64);
        }

        if let Some(size) = response_size {
            self.http_response_size
                .with_label_values(&[method, path])
                .observe(size as f64);
        }
    }

    /// Record an authentication attempt
    pub fn record_auth_attempt(&self, method: &str, success: bool, duration: Duration) {
        let result = if success { "success" } else { "failure" };

        self.auth_attempts_total
            .with_label_values(&[method, result])
            .inc();

        if success {
            self.auth_successes_total.with_label_values(&[method]).inc();
        } else {
            self.auth_failures_total
                .with_label_values(&[method, "invalid_credentials"])
                .inc();
        }

        self.auth_duration
            .with_label_values(&[method])
            .observe(duration.as_secs_f64());
    }

    /// Record a database operation
    pub fn record_db_operation(
        &self,
        operation: &str,
        table: &str,
        success: bool,
        duration: Duration,
    ) {
        let result = if success { "success" } else { "error" };

        self.db_queries_total
            .with_label_values(&[operation, table, result])
            .inc();

        self.db_query_duration
            .with_label_values(&[operation, table])
            .observe(duration.as_secs_f64());
    }

    /// Record a cache operation
    pub fn record_cache_operation(&self, operation: &str, hit: Option<bool>, duration: Duration) {
        match hit {
            Some(true) => {
                self.cache_hits_total.inc();
                self.cache_operations_total
                    .with_label_values(&[operation, "hit"])
                    .inc();
            }
            Some(false) => {
                self.cache_misses_total.inc();
                self.cache_operations_total
                    .with_label_values(&[operation, "miss"])
                    .inc();
            }
            None => {
                self.cache_operations_total
                    .with_label_values(&[operation, "other"])
                    .inc();
            }
        }

        self.cache_operation_duration
            .with_label_values(&[operation])
            .observe(duration.as_secs_f64());
    }

    /// Update system metrics
    pub fn update_system_metrics(&self, memory_bytes: f64, cpu_percent: f64) {
        self.memory_usage_bytes.set(memory_bytes);
        self.cpu_usage_percent.set(cpu_percent);

        // Update uptime
        let uptime_secs = self.start_time.elapsed().as_secs() as f64;
        self.uptime_seconds.inc_by(uptime_secs);
    }

    /// Record an error
    pub fn record_error(&self, error_type: &str, component: &str) {
        self.errors_total
            .with_label_values(&[error_type, component])
            .inc();
    }

    /// Start a timer for measuring operation duration
    pub fn start_timer(&self) -> MetricsTimer {
        MetricsTimer::new()
    }
}

/// Timer for measuring operation duration
pub struct MetricsTimer {
    start_time: Instant,
}

impl MetricsTimer {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn stop_and_record<F>(&self, f: F)
    where
        F: FnOnce(Duration),
    {
        f(self.elapsed());
    }
}

/// Start a background task to collect system metrics
pub async fn start_system_metrics_collector(metrics: Arc<AppMetrics>, interval_secs: u64) {
    let mut interval = interval(Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;

        // Collect system metrics (simplified - in production, use proper system monitoring)
        let memory_usage = get_memory_usage().unwrap_or(0.0);
        let cpu_usage = get_cpu_usage().unwrap_or(0.0);

        metrics.update_system_metrics(memory_usage, cpu_usage);

        tracing::debug!(
            memory_usage_mb = memory_usage / 1024.0 / 1024.0,
            cpu_usage_percent = cpu_usage,
            "System metrics updated"
        );
    }
}

/// Get current memory usage (simplified implementation)
fn get_memory_usage() -> Result<f64> {
    // In production, use a proper system monitoring crate like `sysinfo`
    Ok(1024.0 * 1024.0 * 64.0) // Placeholder: 64 MB
}

/// Get current CPU usage (simplified implementation)
fn get_cpu_usage() -> Result<f64> {
    // In production, use a proper system monitoring crate like `sysinfo`
    Ok(25.5) // Placeholder: 25.5%
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_metrics_creation() {
        let metrics = AppMetrics::new().unwrap();
        assert!(!metrics.gather().unwrap().is_empty());
    }

    #[test]
    fn test_record_http_request() {
        let metrics = AppMetrics::new().unwrap();
        metrics.record_http_request(
            "GET",
            "/api/users",
            200,
            Duration::from_millis(100),
            Some(1024),
            Some(2048),
        );

        let output = metrics.gather().unwrap();
        assert!(output.contains("http_requests_total"));
        assert!(output.contains("http_request_duration_seconds"));
    }

    #[test]
    fn test_record_auth_attempt() {
        let metrics = AppMetrics::new().unwrap();
        metrics.record_auth_attempt("password", true, Duration::from_millis(50));

        let output = metrics.gather().unwrap();
        assert!(output.contains("auth_attempts_total"));
        assert!(output.contains("auth_successes_total"));
    }

    #[test]
    fn test_metrics_timer() {
        let timer = MetricsTimer::new();
        std::thread::sleep(Duration::from_millis(10));
        let elapsed = timer.elapsed();
        assert!(elapsed >= Duration::from_millis(10));
    }
}
