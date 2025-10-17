use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge, HistogramVec,
    IntCounterVec, IntGauge,
};
use std::sync::OnceLock;

/// Global metrics registry
#[allow(dead_code)]
pub struct Metrics {
    // HTTP metrics
    pub http_requests_total: IntCounterVec,
    pub http_request_duration: HistogramVec,

    // Authentication metrics
    pub auth_attempts_total: IntCounterVec,
    pub auth_login_duration: HistogramVec,
    pub active_sessions: IntGauge,

    // Database metrics
    pub db_operations_total: IntCounterVec,
    pub db_operation_duration: HistogramVec,
    pub db_connection_pool_size: IntGauge,

    // Cache metrics
    pub cache_operations_total: IntCounterVec,
    pub cache_hit_ratio: HistogramVec,

    // Rate limiting metrics
    pub rate_limit_hits_total: IntCounterVec,

    // Business metrics
    pub user_registrations_total: IntCounterVec,
    pub email_verifications_total: IntCounterVec,
    pub password_resets_total: IntCounterVec,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

impl Metrics {
    pub fn init() -> &'static Self {
        METRICS.get_or_init(|| {
            Self {
                // HTTP metrics
                http_requests_total: register_int_counter_vec!(
                    "http_requests_total",
                    "Total number of HTTP requests",
                    &["method", "endpoint", "status"]
                )
                .expect("Failed to register http_requests_total metric"),

                http_request_duration: register_histogram_vec!(
                    "http_request_duration_seconds",
                    "HTTP request duration in seconds",
                    &["method", "endpoint"],
                    vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
                )
                .expect("Failed to register http_request_duration metric"),

                // Authentication metrics
                auth_attempts_total: register_int_counter_vec!(
                    "auth_attempts_total",
                    "Total number of authentication attempts",
                    &["endpoint", "result"]
                )
                .expect("Failed to register auth_attempts_total metric"),

                auth_login_duration: register_histogram_vec!(
                    "auth_login_duration_seconds",
                    "Authentication operation duration in seconds",
                    &["operation"],
                    vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
                )
                .expect("Failed to register auth_login_duration metric"),

                active_sessions: register_int_gauge!(
                    "active_sessions_total",
                    "Number of currently active user sessions"
                )
                .expect("Failed to register active_sessions metric"),

                // Database metrics
                db_operations_total: register_int_counter_vec!(
                    "db_operations_total",
                    "Total number of database operations",
                    &["database", "operation", "result"]
                )
                .expect("Failed to register db_operations_total metric"),

                db_operation_duration: register_histogram_vec!(
                    "db_operation_duration_seconds",
                    "Database operation duration in seconds",
                    &["database", "operation"],
                    vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
                )
                .expect("Failed to register db_operation_duration metric"),

                db_connection_pool_size: register_int_gauge!(
                    "db_connection_pool_size",
                    "Current database connection pool size"
                )
                .expect("Failed to register db_connection_pool_size metric"),

                // Cache metrics
                cache_operations_total: register_int_counter_vec!(
                    "cache_operations_total",
                    "Total number of cache operations",
                    &["operation", "result"]
                )
                .expect("Failed to register cache_operations_total metric"),

                cache_hit_ratio: register_histogram_vec!(
                    "cache_hit_ratio",
                    "Cache hit ratio over time windows",
                    &["cache_type"],
                    vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
                )
                .expect("Failed to register cache_hit_ratio metric"),

                // Rate limiting metrics
                rate_limit_hits_total: register_int_counter_vec!(
                    "rate_limit_hits_total",
                    "Total number of rate limit hits",
                    &["endpoint", "ip"]
                )
                .expect("Failed to register rate_limit_hits_total metric"),

                // Business metrics
                user_registrations_total: register_int_counter_vec!(
                    "user_registrations_total",
                    "Total number of user registrations",
                    &["result"]
                )
                .expect("Failed to register user_registrations_total metric"),

                email_verifications_total: register_int_counter_vec!(
                    "email_verifications_total",
                    "Total number of email verifications",
                    &["result"]
                )
                .expect("Failed to register email_verifications_total metric"),

                password_resets_total: register_int_counter_vec!(
                    "password_resets_total",
                    "Total number of password reset attempts",
                    &["result"]
                )
                .expect("Failed to register password_resets_total metric"),
            }
        })
    }

    pub fn get() -> &'static Self {
        METRICS.get().expect("Metrics not initialized")
    }
}

/// Record HTTP request metrics
pub fn record_http_request(method: &str, endpoint: &str, status: u16, duration: f64) {
    let metrics = Metrics::get();

    metrics
        .http_requests_total
        .with_label_values(&[method, endpoint, &status.to_string()])
        .inc();

    metrics
        .http_request_duration
        .with_label_values(&[method, endpoint])
        .observe(duration);
}

/// Record authentication attempt
#[allow(dead_code)]
pub fn record_auth_attempt(endpoint: &str, success: bool, duration: f64) {
    let metrics = Metrics::get();
    let result = if success { "success" } else { "failure" };

    metrics
        .auth_attempts_total
        .with_label_values(&[endpoint, result])
        .inc();

    metrics
        .auth_login_duration
        .with_label_values(&[endpoint])
        .observe(duration);
}

/// Record database operation
#[allow(dead_code)]
pub fn record_db_operation(database: &str, operation: &str, success: bool, duration: f64) {
    let metrics = Metrics::get();
    let result = if success { "success" } else { "error" };

    metrics
        .db_operations_total
        .with_label_values(&[database, operation, result])
        .inc();

    metrics
        .db_operation_duration
        .with_label_values(&[database, operation])
        .observe(duration);
}

/// Record cache operation
#[allow(dead_code)]
pub fn record_cache_operation(operation: &str, hit: bool) {
    let metrics = Metrics::get();
    let result = if hit { "hit" } else { "miss" };

    metrics
        .cache_operations_total
        .with_label_values(&[operation, result])
        .inc();
}

/// Record rate limit hit
#[allow(dead_code)]
pub fn record_rate_limit_hit(endpoint: &str, ip: &str) {
    let metrics = Metrics::get();

    metrics
        .rate_limit_hits_total
        .with_label_values(&[endpoint, ip])
        .inc();
}

/// Record user registration
#[allow(dead_code)]
pub fn record_user_registration(success: bool) {
    let metrics = Metrics::get();
    let result = if success { "success" } else { "failure" };

    metrics
        .user_registrations_total
        .with_label_values(&[result])
        .inc();
}

/// Record email verification
#[allow(dead_code)]
pub fn record_email_verification(success: bool) {
    let metrics = Metrics::get();
    let result = if success { "success" } else { "failure" };

    metrics
        .email_verifications_total
        .with_label_values(&[result])
        .inc();
}

/// Record password reset
#[allow(dead_code)]
pub fn record_password_reset(success: bool) {
    let metrics = Metrics::get();
    let result = if success { "success" } else { "failure" };

    metrics
        .password_resets_total
        .with_label_values(&[result])
        .inc();
}

/// Update active sessions count
#[allow(dead_code)]
pub fn update_active_sessions(count: i64) {
    let metrics = Metrics::get();
    metrics.active_sessions.set(count);
}

/// Update database connection pool size
#[allow(dead_code)]
pub fn update_db_connection_pool_size(size: i64) {
    let metrics = Metrics::get();
    metrics.db_connection_pool_size.set(size);
}

// Removed unused get_metrics_text function

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        let metrics = Metrics::init();

        // Test that metrics can be accessed
        let _http_metrics = &metrics.http_requests_total;
        let _auth_metrics = &metrics.auth_attempts_total;
        let _db_metrics = &metrics.db_operations_total;
    }

    #[test]
    fn test_record_http_request() {
        Metrics::init();

        // This should not panic
        record_http_request("GET", "/health", 200, 0.001);
        record_http_request("POST", "/auth/login", 401, 0.045);
    }

    #[test]
    fn test_record_auth_attempt() {
        Metrics::init();

        // This should not panic
        record_auth_attempt("/auth/login", true, 0.025);
        record_auth_attempt("/auth/login", false, 0.030);
    }

    #[test]
    fn test_record_db_operation() {
        Metrics::init();

        // This should not panic
        record_db_operation("mongodb", "find", true, 0.012);
        record_db_operation("postgresql", "insert", false, 0.055);
    }

    #[test]
    fn test_business_metrics() {
        Metrics::init();

        // This should not panic
        record_user_registration(true);
        record_email_verification(false);
        record_password_reset(true);
        update_active_sessions(150);
    }

    #[test]
    fn test_get_metrics_text() {
        Metrics::init();

        // Record some sample metrics
        record_http_request("GET", "/test", 200, 0.001);

        let metrics_text = get_metrics_text().expect("Failed to get metrics text");
        assert!(metrics_text.contains("http_requests_total"));
    }
}
