// Performance benchmarks and load testing modules
// Issue #43: Performance and Load Testing

pub mod endpoint_benchmarks;
pub mod database_performance;
pub mod cache_performance;
pub mod resource_monitoring;
pub mod regression_testing;

// Re-export key types for convenience
pub use endpoint_benchmarks::{PerformanceTargets, EndpointMetrics};
pub use database_performance::{DatabasePerformanceTargets, DatabaseMetrics};
pub use cache_performance::{CachePerformanceTargets, CacheMetrics};
pub use resource_monitoring::{ResourceTargets, ResourceMetrics, ResourceMonitor};
pub use regression_testing::{
    PerformanceBaseline, EndpointBaseline, DatabaseBaseline, CacheBaseline, 
    ResourceBaseline, RegressionDetector, RegressionAnalysis
};

/// Common benchmark utilities and helper functions
pub mod utils {
    use std::time::Duration;

    /// Convert duration to milliseconds as f64 for calculations
    pub fn duration_to_ms(duration: Duration) -> f64 {
        duration.as_millis() as f64
    }

    /// Calculate percentage change between two values
    pub fn percentage_change(baseline: f64, current: f64) -> f64 {
        if baseline == 0.0 {
            0.0
        } else {
            ((current - baseline) / baseline) * 100.0
        }
    }

    /// Determine if a performance change is significant
    pub fn is_significant_change(change_percent: f64, threshold: f64) -> bool {
        change_percent.abs() > threshold
    }

    /// Format performance metrics for display
    pub fn format_metrics_summary(
        test_name: &str,
        total_operations: usize,
        success_rate: f64,
        avg_response_time: Duration,
        p95_response_time: Duration,
        operations_per_second: f64,
    ) -> String {
        format!(
            "📊 {}\n\
             ├─ Operations: {}\n\
             ├─ Success Rate: {:.2}%\n\
             ├─ Avg Response: {:.2}ms\n\
             ├─ P95 Response: {:.2}ms\n\
             └─ Throughput: {:.2} ops/sec",
            test_name,
            total_operations,
            success_rate * 100.0,
            avg_response_time.as_millis(),
            p95_response_time.as_millis(),
            operations_per_second
        )
    }
}

#[cfg(test)]
mod tests {
    use super::utils::*;
    use std::time::Duration;

    #[test]
    fn test_percentage_change_calculation() {
        assert_eq!(percentage_change(100.0, 120.0), 20.0);
        assert_eq!(percentage_change(100.0, 80.0), -20.0);
        assert_eq!(percentage_change(0.0, 50.0), 0.0); // Avoid division by zero
    }

    #[test]
    fn test_significant_change_detection() {
        assert!(is_significant_change(25.0, 20.0));
        assert!(!is_significant_change(15.0, 20.0));
        assert!(is_significant_change(-25.0, 20.0));
    }

    #[test]
    fn test_duration_conversion() {
        let duration = Duration::from_millis(1500);
        assert_eq!(duration_to_ms(duration), 1500.0);
    }

    #[test]
    fn test_metrics_summary_formatting() {
        let summary = format_metrics_summary(
            "Test Endpoint",
            1000,
            0.95,
            Duration::from_millis(50),
            Duration::from_millis(100),
            20.0,
        );
        
        assert!(summary.contains("Test Endpoint"));
        assert!(summary.contains("1000"));
        assert!(summary.contains("95.00%"));
        assert!(summary.contains("50"));
        assert!(summary.contains("100"));
        assert!(summary.contains("20.00"));
    }
}