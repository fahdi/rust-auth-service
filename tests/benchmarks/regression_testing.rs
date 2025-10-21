use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::common::{IntegrationTestFramework, TestUser};

/// Performance baseline for regression detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBaseline {
    pub timestamp: u64,
    pub git_commit: Option<String>,
    pub test_environment: String,
    pub endpoints: HashMap<String, EndpointBaseline>,
    pub database_operations: HashMap<String, DatabaseBaseline>,
    pub cache_operations: HashMap<String, CacheBaseline>,
    pub resource_usage: ResourceBaseline,
}

/// Endpoint performance baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointBaseline {
    pub endpoint_name: String,
    pub response_time_p50_ms: u64,
    pub response_time_p95_ms: u64,
    pub response_time_p99_ms: u64,
    pub requests_per_second: f64,
    pub success_rate: f64,
    pub sample_size: usize,
}

/// Database operation baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseBaseline {
    pub operation_name: String,
    pub avg_response_time_ms: u64,
    pub p95_response_time_ms: u64,
    pub operations_per_second: f64,
    pub success_rate: f64,
    pub sample_size: usize,
}

/// Cache operation baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheBaseline {
    pub operation_name: String,
    pub avg_response_time_ms: u64,
    pub p95_response_time_ms: u64,
    pub hit_rate: f64,
    pub operations_per_second: f64,
    pub sample_size: usize,
}

/// Resource usage baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceBaseline {
    pub avg_memory_mb: f64,
    pub peak_memory_mb: f64,
    pub avg_cpu_percent: f64,
    pub peak_cpu_percent: f64,
    pub memory_growth_per_1k_ops_mb: f64,
}

/// Performance regression detection thresholds
#[derive(Debug, Clone)]
pub struct RegressionThresholds {
    pub response_time_increase_percent: f64,  // Max % increase in response time
    pub throughput_decrease_percent: f64,     // Max % decrease in throughput  
    pub success_rate_decrease_percent: f64,   // Max % decrease in success rate
    pub memory_increase_percent: f64,         // Max % increase in memory usage
    pub cpu_increase_percent: f64,            // Max % increase in CPU usage
}

impl Default for RegressionThresholds {
    fn default() -> Self {
        Self {
            response_time_increase_percent: 20.0,  // 20% increase allowed
            throughput_decrease_percent: 15.0,     // 15% decrease allowed
            success_rate_decrease_percent: 2.0,    // 2% decrease allowed
            memory_increase_percent: 25.0,         // 25% increase allowed
            cpu_increase_percent: 30.0,            // 30% increase allowed
        }
    }
}

/// Performance regression analysis result
#[derive(Debug)]
pub struct RegressionAnalysis {
    pub has_regression: bool,
    pub regressions: Vec<PerformanceRegression>,
    pub improvements: Vec<PerformanceImprovement>,
    pub baseline_comparison: BaselineComparison,
}

#[derive(Debug)]
pub struct PerformanceRegression {
    pub category: String,
    pub metric_name: String,
    pub baseline_value: f64,
    pub current_value: f64,
    pub change_percent: f64,
    pub severity: RegressionSeverity,
}

#[derive(Debug)]
pub struct PerformanceImprovement {
    pub category: String,
    pub metric_name: String,
    pub baseline_value: f64,
    pub current_value: f64,
    pub improvement_percent: f64,
}

#[derive(Debug)]
pub enum RegressionSeverity {
    Critical,  // >50% degradation
    Major,     // 20-50% degradation
    Minor,     // 10-20% degradation
    Warning,   // <10% degradation
}

#[derive(Debug)]
pub struct BaselineComparison {
    pub baseline_timestamp: u64,
    pub baseline_commit: Option<String>,
    pub current_timestamp: u64,
    pub days_since_baseline: f64,
}

/// Performance regression detector
pub struct RegressionDetector {
    pub baseline_path: String,
    pub thresholds: RegressionThresholds,
}

impl RegressionDetector {
    pub fn new(baseline_path: &str) -> Self {
        Self {
            baseline_path: baseline_path.to_string(),
            thresholds: RegressionThresholds::default(),
        }
    }

    /// Load performance baseline from file
    pub fn load_baseline(&self) -> Result<Option<PerformanceBaseline>> {
        let path = Path::new(&self.baseline_path);
        if path.exists() {
            let content = fs::read_to_string(path)?;
            let baseline: PerformanceBaseline = serde_json::from_str(&content)?;
            Ok(Some(baseline))
        } else {
            Ok(None)
        }
    }

    /// Save performance baseline to file
    pub fn save_baseline(&self, baseline: &PerformanceBaseline) -> Result<()> {
        let content = serde_json::to_string_pretty(baseline)?;
        
        // Create directory if it doesn't exist
        if let Some(parent) = Path::new(&self.baseline_path).parent() {
            fs::create_dir_all(parent)?;
        }
        
        fs::write(&self.baseline_path, content)?;
        info!("📊 Performance baseline saved to {}", self.baseline_path);
        Ok(())
    }

    /// Analyze performance against baseline
    pub fn analyze_regression(
        &self,
        current: &PerformanceBaseline,
        baseline: &PerformanceBaseline,
    ) -> RegressionAnalysis {
        let mut regressions = Vec::new();
        let mut improvements = Vec::new();

        // Analyze endpoint performance
        for (endpoint_name, current_endpoint) in &current.endpoints {
            if let Some(baseline_endpoint) = baseline.endpoints.get(endpoint_name) {
                self.analyze_endpoint_regression(
                    current_endpoint,
                    baseline_endpoint,
                    &mut regressions,
                    &mut improvements,
                );
            }
        }

        // Analyze database performance
        for (op_name, current_db) in &current.database_operations {
            if let Some(baseline_db) = baseline.database_operations.get(op_name) {
                self.analyze_database_regression(
                    current_db,
                    baseline_db,
                    &mut regressions,
                    &mut improvements,
                );
            }
        }

        // Analyze cache performance
        for (op_name, current_cache) in &current.cache_operations {
            if let Some(baseline_cache) = baseline.cache_operations.get(op_name) {
                self.analyze_cache_regression(
                    current_cache,
                    baseline_cache,
                    &mut regressions,
                    &mut improvements,
                );
            }
        }

        // Analyze resource usage
        self.analyze_resource_regression(
            &current.resource_usage,
            &baseline.resource_usage,
            &mut regressions,
            &mut improvements,
        );

        let baseline_comparison = BaselineComparison {
            baseline_timestamp: baseline.timestamp,
            baseline_commit: baseline.git_commit.clone(),
            current_timestamp: current.timestamp,
            days_since_baseline: (current.timestamp - baseline.timestamp) as f64 / 86400.0,
        };

        RegressionAnalysis {
            has_regression: !regressions.is_empty(),
            regressions,
            improvements,
            baseline_comparison,
        }
    }

    fn analyze_endpoint_regression(
        &self,
        current: &EndpointBaseline,
        baseline: &EndpointBaseline,
        regressions: &mut Vec<PerformanceRegression>,
        improvements: &mut Vec<PerformanceImprovement>,
    ) {
        let category = "Endpoint".to_string();

        // Check P95 response time
        self.check_metric_regression(
            &category,
            &format!("{} P95 Response Time", current.endpoint_name),
            baseline.response_time_p95_ms as f64,
            current.response_time_p95_ms as f64,
            self.thresholds.response_time_increase_percent,
            true, // Higher is worse
            regressions,
            improvements,
        );

        // Check throughput (RPS)
        self.check_metric_regression(
            &category,
            &format!("{} Requests/sec", current.endpoint_name),
            baseline.requests_per_second,
            current.requests_per_second,
            self.thresholds.throughput_decrease_percent,
            false, // Lower is worse
            regressions,
            improvements,
        );

        // Check success rate
        self.check_metric_regression(
            &category,
            &format!("{} Success Rate", current.endpoint_name),
            baseline.success_rate * 100.0,
            current.success_rate * 100.0,
            self.thresholds.success_rate_decrease_percent,
            false, // Lower is worse
            regressions,
            improvements,
        );
    }

    fn analyze_database_regression(
        &self,
        current: &DatabaseBaseline,
        baseline: &DatabaseBaseline,
        regressions: &mut Vec<PerformanceRegression>,
        improvements: &mut Vec<PerformanceImprovement>,
    ) {
        let category = "Database".to_string();

        // Check P95 response time
        self.check_metric_regression(
            &category,
            &format!("{} P95 Response Time", current.operation_name),
            baseline.p95_response_time_ms as f64,
            current.p95_response_time_ms as f64,
            self.thresholds.response_time_increase_percent,
            true,
            regressions,
            improvements,
        );

        // Check operations per second
        self.check_metric_regression(
            &category,
            &format!("{} Operations/sec", current.operation_name),
            baseline.operations_per_second,
            current.operations_per_second,
            self.thresholds.throughput_decrease_percent,
            false,
            regressions,
            improvements,
        );
    }

    fn analyze_cache_regression(
        &self,
        current: &CacheBaseline,
        baseline: &CacheBaseline,
        regressions: &mut Vec<PerformanceRegression>,
        improvements: &mut Vec<PerformanceImprovement>,
    ) {
        let category = "Cache".to_string();

        // Check P95 response time
        self.check_metric_regression(
            &category,
            &format!("{} P95 Response Time", current.operation_name),
            baseline.p95_response_time_ms as f64,
            current.p95_response_time_ms as f64,
            self.thresholds.response_time_increase_percent,
            true,
            regressions,
            improvements,
        );

        // Check hit rate
        self.check_metric_regression(
            &category,
            &format!("{} Hit Rate", current.operation_name),
            baseline.hit_rate * 100.0,
            current.hit_rate * 100.0,
            5.0, // 5% decrease in hit rate is significant
            false,
            regressions,
            improvements,
        );
    }

    fn analyze_resource_regression(
        &self,
        current: &ResourceBaseline,
        baseline: &ResourceBaseline,
        regressions: &mut Vec<PerformanceRegression>,
        improvements: &mut Vec<PerformanceImprovement>,
    ) {
        let category = "Resource".to_string();

        // Check average memory usage
        self.check_metric_regression(
            &category,
            "Average Memory Usage".to_string(),
            baseline.avg_memory_mb,
            current.avg_memory_mb,
            self.thresholds.memory_increase_percent,
            true,
            regressions,
            improvements,
        );

        // Check average CPU usage
        self.check_metric_regression(
            &category,
            "Average CPU Usage".to_string(),
            baseline.avg_cpu_percent,
            current.avg_cpu_percent,
            self.thresholds.cpu_increase_percent,
            true,
            regressions,
            improvements,
        );

        // Check memory growth rate
        self.check_metric_regression(
            &category,
            "Memory Growth per 1K Operations".to_string(),
            baseline.memory_growth_per_1k_ops_mb,
            current.memory_growth_per_1k_ops_mb,
            self.thresholds.memory_increase_percent,
            true,
            regressions,
            improvements,
        );
    }

    fn check_metric_regression(
        &self,
        category: &str,
        metric_name: String,
        baseline_value: f64,
        current_value: f64,
        threshold_percent: f64,
        higher_is_worse: bool,
        regressions: &mut Vec<PerformanceRegression>,
        improvements: &mut Vec<PerformanceImprovement>,
    ) {
        if baseline_value == 0.0 {
            return; // Avoid division by zero
        }

        let change_percent = ((current_value - baseline_value) / baseline_value) * 100.0;
        let abs_change_percent = change_percent.abs();

        if higher_is_worse {
            // For metrics where higher values are worse (response time, memory usage)
            if change_percent > threshold_percent {
                let severity = if abs_change_percent > 50.0 {
                    RegressionSeverity::Critical
                } else if abs_change_percent > 20.0 {
                    RegressionSeverity::Major
                } else if abs_change_percent > 10.0 {
                    RegressionSeverity::Minor
                } else {
                    RegressionSeverity::Warning
                };

                regressions.push(PerformanceRegression {
                    category: category.to_string(),
                    metric_name,
                    baseline_value,
                    current_value,
                    change_percent,
                    severity,
                });
            } else if change_percent < -5.0 {
                // Improvement: metric decreased by more than 5%
                improvements.push(PerformanceImprovement {
                    category: category.to_string(),
                    metric_name,
                    baseline_value,
                    current_value,
                    improvement_percent: -change_percent,
                });
            }
        } else {
            // For metrics where lower values are worse (throughput, success rate)
            if change_percent < -threshold_percent {
                let severity = if abs_change_percent > 50.0 {
                    RegressionSeverity::Critical
                } else if abs_change_percent > 20.0 {
                    RegressionSeverity::Major
                } else if abs_change_percent > 10.0 {
                    RegressionSeverity::Minor
                } else {
                    RegressionSeverity::Warning
                };

                regressions.push(PerformanceRegression {
                    category: category.to_string(),
                    metric_name,
                    baseline_value,
                    current_value,
                    change_percent,
                    severity,
                });
            } else if change_percent > 5.0 {
                // Improvement: metric increased by more than 5%
                improvements.push(PerformanceImprovement {
                    category: category.to_string(),
                    metric_name,
                    baseline_value,
                    current_value,
                    improvement_percent: change_percent,
                });
            }
        }
    }

    /// Print regression analysis report
    pub fn print_regression_report(&self, analysis: &RegressionAnalysis) {
        println!("\n📊 Performance Regression Analysis Report");
        println!("════════════════════════════════════════");
        
        println!("📅 Baseline Comparison:");
        println!("├─ Baseline Date: {} days ago", analysis.baseline_comparison.days_since_baseline);
        if let Some(ref commit) = analysis.baseline_comparison.baseline_commit {
            println!("├─ Baseline Commit: {}", commit);
        }
        println!("└─ Analysis Date: {}", 
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());

        if analysis.has_regression {
            println!("\n🚨 Performance Regressions Detected ({}):", analysis.regressions.len());
            for (i, regression) in analysis.regressions.iter().enumerate() {
                let severity_icon = match regression.severity {
                    RegressionSeverity::Critical => "🔥",
                    RegressionSeverity::Major => "⚠️",
                    RegressionSeverity::Minor => "⚡",
                    RegressionSeverity::Warning => "ℹ️",
                };
                
                println!("{}. {} [{}] {}", 
                    i + 1, severity_icon, regression.category, regression.metric_name);
                println!("   Baseline: {:.2} → Current: {:.2} ({:+.2}%)",
                    regression.baseline_value, regression.current_value, regression.change_percent);
            }
        } else {
            println!("\n✅ No Performance Regressions Detected");
        }

        if !analysis.improvements.is_empty() {
            println!("\n🚀 Performance Improvements ({}):", analysis.improvements.len());
            for (i, improvement) in analysis.improvements.iter().enumerate() {
                println!("{}. [{}] {}", 
                    i + 1, improvement.category, improvement.metric_name);
                println!("   Baseline: {:.2} → Current: {:.2} (+{:.2}%)",
                    improvement.baseline_value, improvement.current_value, improvement.improvement_percent);
            }
        }

        println!("════════════════════════════════════════");
    }
}

/// Create performance baseline from current test run
pub async fn create_performance_baseline(framework: &IntegrationTestFramework) -> Result<PerformanceBaseline> {
    info!("📊 Creating performance baseline");

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let git_commit = get_git_commit_hash();
    
    // Collect endpoint baselines
    let mut endpoints = HashMap::new();
    
    // Health endpoint baseline
    let health_baseline = collect_endpoint_baseline(framework, "GET /health", || {
        let client = framework.client.clone();
        async move {
            client.health_check().await
        }
    }).await?;
    endpoints.insert("health".to_string(), health_baseline);

    // Authentication endpoint baseline
    let auth_baseline = collect_auth_endpoint_baseline(framework).await?;
    endpoints.insert("authentication".to_string(), auth_baseline);

    // Database operation baselines
    let mut database_operations = HashMap::new();
    
    let user_create_baseline = collect_database_baseline(framework, "User Creation").await?;
    database_operations.insert("user_creation".to_string(), user_create_baseline);

    // Cache operation baselines
    let mut cache_operations = HashMap::new();
    
    let cache_get_baseline = collect_cache_baseline(framework, "Cache GET").await?;
    cache_operations.insert("cache_get".to_string(), cache_get_baseline);

    // Resource usage baseline
    let resource_usage = collect_resource_baseline(framework).await?;

    Ok(PerformanceBaseline {
        timestamp,
        git_commit,
        test_environment: "integration_test".to_string(),
        endpoints,
        database_operations,
        cache_operations,
        resource_usage,
    })
}

async fn collect_endpoint_baseline<F, Fut>(
    framework: &IntegrationTestFramework,
    endpoint_name: &str,
    operation: F,
) -> Result<EndpointBaseline>
where
    F: Fn() -> Fut + Clone,
    Fut: std::future::Future<Output = Result<serde_json::Value>>,
{
    const SAMPLE_SIZE: usize = 100;
    let mut response_times = Vec::new();
    let mut successful_requests = 0;

    let start_time = Instant::now();

    for _ in 0..SAMPLE_SIZE {
        let request_start = Instant::now();
        match operation().await {
            Ok(_) => {
                successful_requests += 1;
                response_times.push(request_start.elapsed().as_millis() as u64);
            }
            Err(_) => {
                response_times.push(request_start.elapsed().as_millis() as u64);
            }
        }
    }

    let test_duration = start_time.elapsed();
    response_times.sort();

    let p50_idx = SAMPLE_SIZE * 50 / 100;
    let p95_idx = SAMPLE_SIZE * 95 / 100;
    let p99_idx = SAMPLE_SIZE * 99 / 100;

    Ok(EndpointBaseline {
        endpoint_name: endpoint_name.to_string(),
        response_time_p50_ms: response_times[p50_idx.min(SAMPLE_SIZE - 1)],
        response_time_p95_ms: response_times[p95_idx.min(SAMPLE_SIZE - 1)],
        response_time_p99_ms: response_times[p99_idx.min(SAMPLE_SIZE - 1)],
        requests_per_second: SAMPLE_SIZE as f64 / test_duration.as_secs_f64(),
        success_rate: successful_requests as f64 / SAMPLE_SIZE as f64,
        sample_size: SAMPLE_SIZE,
    })
}

async fn collect_auth_endpoint_baseline(framework: &IntegrationTestFramework) -> Result<EndpointBaseline> {
    // Create test user first
    let test_user = TestUser::new("baseline_auth_user");
    let _ = framework.client.register(&test_user).await?;

    collect_endpoint_baseline(framework, "POST /auth/login", || {
        let client = framework.client.clone();
        let user = test_user.clone();
        async move {
            client.login(&user).await.map(|tokens| serde_json::json!({"tokens": tokens}))
        }
    }).await
}

async fn collect_database_baseline(
    framework: &IntegrationTestFramework,
    operation_name: &str,
) -> Result<DatabaseBaseline> {
    const SAMPLE_SIZE: usize = 50;
    let mut response_times = Vec::new();
    let mut successful_operations = 0;

    let start_time = Instant::now();

    for i in 0..SAMPLE_SIZE {
        let user = TestUser::new(&format!("db_baseline_{}", i));
        let request_start = Instant::now();
        
        match framework.client.register(&user).await {
            Ok(_) => {
                successful_operations += 1;
                response_times.push(request_start.elapsed().as_millis() as u64);
            }
            Err(_) => {
                response_times.push(request_start.elapsed().as_millis() as u64);
            }
        }
    }

    let test_duration = start_time.elapsed();
    response_times.sort();

    let avg_response_time = response_times.iter().sum::<u64>() / response_times.len() as u64;
    let p95_idx = response_times.len() * 95 / 100;

    Ok(DatabaseBaseline {
        operation_name: operation_name.to_string(),
        avg_response_time_ms: avg_response_time,
        p95_response_time_ms: response_times[p95_idx.min(response_times.len() - 1)],
        operations_per_second: SAMPLE_SIZE as f64 / test_duration.as_secs_f64(),
        success_rate: successful_operations as f64 / SAMPLE_SIZE as f64,
        sample_size: SAMPLE_SIZE,
    })
}

async fn collect_cache_baseline(
    framework: &IntegrationTestFramework,
    operation_name: &str,
) -> Result<CacheBaseline> {
    // Create test user for cache operations
    let test_user = TestUser::new("cache_baseline_user");
    let _ = framework.client.register(&test_user).await?;

    const SAMPLE_SIZE: usize = 100;
    let mut response_times = Vec::new();
    let mut cache_hits = 0;

    let start_time = Instant::now();

    for _ in 0..SAMPLE_SIZE {
        let request_start = Instant::now();
        match framework.client.login(&test_user).await {
            Ok(_) => {
                let elapsed = request_start.elapsed();
                response_times.push(elapsed.as_millis() as u64);
                // Assume cache hit if response is fast
                if elapsed.as_millis() < 50 {
                    cache_hits += 1;
                }
            }
            Err(_) => {
                response_times.push(request_start.elapsed().as_millis() as u64);
            }
        }
    }

    let test_duration = start_time.elapsed();
    response_times.sort();

    let avg_response_time = response_times.iter().sum::<u64>() / response_times.len() as u64;
    let p95_idx = response_times.len() * 95 / 100;

    Ok(CacheBaseline {
        operation_name: operation_name.to_string(),
        avg_response_time_ms: avg_response_time,
        p95_response_time_ms: response_times[p95_idx.min(response_times.len() - 1)],
        hit_rate: cache_hits as f64 / SAMPLE_SIZE as f64,
        operations_per_second: SAMPLE_SIZE as f64 / test_duration.as_secs_f64(),
        sample_size: SAMPLE_SIZE,
    })
}

async fn collect_resource_baseline(
    _framework: &IntegrationTestFramework,
) -> Result<ResourceBaseline> {
    // For baseline collection, use mock values
    // In a real implementation, this would collect actual resource metrics
    Ok(ResourceBaseline {
        avg_memory_mb: 45.0,
        peak_memory_mb: 60.0,
        avg_cpu_percent: 25.0,
        peak_cpu_percent: 45.0,
        memory_growth_per_1k_ops_mb: 2.5,
    })
}

fn get_git_commit_hash() -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
}

/// Test performance regression detection
#[tokio::test]
async fn test_performance_regression_detection() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping regression detection test.");
        return Ok(());
    }

    info!("🔍 Testing performance regression detection");

    let baseline_path = "target/test_baseline.json";
    let detector = RegressionDetector::new(baseline_path);

    // Create current performance baseline
    let current_baseline = create_performance_baseline(&framework).await?;

    // Try to load existing baseline
    if let Some(stored_baseline) = detector.load_baseline()? {
        println!("📊 Comparing against stored baseline...");
        
        let analysis = detector.analyze_regression(&current_baseline, &stored_baseline);
        detector.print_regression_report(&analysis);

        // Assert no critical regressions
        let critical_regressions = analysis.regressions.iter()
            .filter(|r| matches!(r.severity, RegressionSeverity::Critical))
            .count();

        assert_eq!(
            critical_regressions, 0,
            "Critical performance regressions detected: {}",
            critical_regressions
        );

        println!("✅ Performance regression analysis completed");
    } else {
        println!("📝 No existing baseline found. Creating new baseline...");
        detector.save_baseline(&current_baseline)?;
        println!("✅ Performance baseline created for future regression detection");
    }

    Ok(())
}