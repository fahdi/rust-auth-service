use anyhow::Result;
use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{info, warn};

use crate::common::{IntegrationTestFramework, TestUser};

/// Resource usage targets from Issue #43
#[derive(Debug, Clone)]
pub struct ResourceTargets {
    pub max_memory_mb: f64,         // <100MB under normal load
    pub max_cpu_percent: f64,       // <70% CPU utilization
    pub max_db_connections: f64,    // <50% of connection pool
    pub min_cache_hit_rate: f64,    // >85% cache hit rate
    pub max_response_time_ms: u64,  // <200ms P95 response time
    pub max_error_rate: f64,        // <5% error rate
    pub max_memory_growth_mb: f64,  // <50MB growth per 1000 operations
}

impl Default for ResourceTargets {
    fn default() -> Self {
        Self {
            max_memory_mb: 100.0,
            max_cpu_percent: 70.0,
            max_db_connections: 50.0, // Percentage of pool
            min_cache_hit_rate: 85.0,
            max_response_time_ms: 200,
            max_error_rate: 5.0,
            max_memory_growth_mb: 50.0,
        }
    }
}

/// System resource metrics
#[derive(Debug, Default, Clone)]
pub struct ResourceMetrics {
    pub timestamp: Instant,
    pub memory_mb: f64,
    pub cpu_percent: f64,
    pub db_connections: Option<u32>,
    pub cache_hit_rate: Option<f64>,
    pub active_connections: Option<u32>,
    pub response_time_ms: Option<u64>,
    pub error_rate: Option<f64>,
}

impl ResourceMetrics {
    pub fn new() -> Self {
        Self {
            timestamp: Instant::now(),
            ..Default::default()
        }
    }
}

/// Resource monitor for tracking system performance
#[derive(Debug)]
pub struct ResourceMonitor {
    pub service_pid: Option<u32>,
    pub metrics_history: Arc<Mutex<Vec<ResourceMetrics>>>,
    pub initial_memory: Option<f64>,
    pub monitoring_active: Arc<Mutex<bool>>,
}

impl ResourceMonitor {
    pub fn new() -> Self {
        Self {
            service_pid: None,
            metrics_history: Arc::new(Mutex::new(Vec::new())),
            initial_memory: None,
            monitoring_active: Arc::new(Mutex::new(false)),
        }
    }

    /// Start monitoring system resources
    pub async fn start_monitoring(&mut self) -> Result<()> {
        // Find the auth service process
        self.service_pid = self.find_auth_service_pid().await?;
        
        if self.service_pid.is_none() {
            warn!("Could not find auth service process. Resource monitoring will be limited.");
        }

        // Get initial memory baseline
        if let Some(memory) = self.get_memory_usage().await? {
            self.initial_memory = Some(memory);
        }

        // Start background monitoring
        let metrics_history = self.metrics_history.clone();
        let monitoring_active = self.monitoring_active.clone();
        let pid = self.service_pid;

        *monitoring_active.lock().await = true;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            
            while *monitoring_active.lock().await {
                interval.tick().await;
                
                let mut metrics = ResourceMetrics::new();
                
                // Collect memory usage
                if let Ok(Some(memory)) = Self::get_process_memory(pid).await {
                    metrics.memory_mb = memory;
                }
                
                // Collect CPU usage
                if let Ok(Some(cpu)) = Self::get_process_cpu(pid).await {
                    metrics.cpu_percent = cpu;
                }
                
                // Collect network connections
                if let Ok(connections) = Self::get_network_connections().await {
                    metrics.active_connections = Some(connections);
                }
                
                // Store metrics
                metrics_history.lock().await.push(metrics);
            }
        });

        info!("🔍 Resource monitoring started for PID: {:?}", self.service_pid);
        Ok(())
    }

    /// Stop monitoring
    pub async fn stop_monitoring(&self) {
        *self.monitoring_active.lock().await = false;
        info!("🛑 Resource monitoring stopped");
    }

    /// Get current resource usage
    pub async fn get_current_metrics(&self) -> Option<ResourceMetrics> {
        let history = self.metrics_history.lock().await;
        history.last().cloned()
    }

    /// Get memory growth since monitoring started
    pub async fn get_memory_growth(&self) -> f64 {
        if let Some(initial) = self.initial_memory {
            if let Some(current) = self.get_current_metrics().await {
                return current.memory_mb - initial;
            }
        }
        0.0
    }

    /// Get average metrics over a time period
    pub async fn get_average_metrics(&self, duration: Duration) -> ResourceMetrics {
        let history = self.metrics_history.lock().await;
        let cutoff = Instant::now() - duration;
        
        let recent_metrics: Vec<_> = history
            .iter()
            .filter(|m| m.timestamp > cutoff)
            .collect();

        if recent_metrics.is_empty() {
            return ResourceMetrics::new();
        }

        let count = recent_metrics.len() as f64;
        let mut avg_metrics = ResourceMetrics::new();
        
        avg_metrics.memory_mb = recent_metrics.iter().map(|m| m.memory_mb).sum::<f64>() / count;
        avg_metrics.cpu_percent = recent_metrics.iter().map(|m| m.cpu_percent).sum::<f64>() / count;
        
        avg_metrics
    }

    /// Find the auth service process ID
    async fn find_auth_service_pid(&self) -> Result<Option<u32>> {
        let output = Command::new("pgrep")
            .args(["-f", "rust-auth-service"])
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = stdout.lines().next() {
                    if let Ok(pid) = line.trim().parse::<u32>() {
                        return Ok(Some(pid));
                    }
                }
            }
            Err(_) => {
                // Try alternative method using ps
                let output = Command::new("ps")
                    .args(["-eo", "pid,comm"])
                    .output();
                
                if let Ok(output) = output {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if line.contains("rust-auth-service") {
                            if let Some(pid_str) = line.split_whitespace().next() {
                                if let Ok(pid) = pid_str.parse::<u32>() {
                                    return Ok(Some(pid));
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(None)
    }

    /// Get current memory usage
    async fn get_memory_usage(&self) -> Result<Option<f64>> {
        Self::get_process_memory(self.service_pid).await
    }

    /// Get memory usage for a specific process
    async fn get_process_memory(pid: Option<u32>) -> Result<Option<f64>> {
        if let Some(pid) = pid {
            let output = Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "rss="])
                .output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(rss_str) = stdout.trim().split_whitespace().next() {
                    if let Ok(rss_kb) = rss_str.parse::<f64>() {
                        return Ok(Some(rss_kb / 1024.0)); // Convert KB to MB
                    }
                }
            }
        }
        Ok(None)
    }

    /// Get CPU usage for a specific process
    async fn get_process_cpu(pid: Option<u32>) -> Result<Option<f64>> {
        if let Some(pid) = pid {
            let output = Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "pcpu="])
                .output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(cpu_str) = stdout.trim().split_whitespace().next() {
                    if let Ok(cpu_percent) = cpu_str.parse::<f64>() {
                        return Ok(Some(cpu_percent));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Get network connections count
    async fn get_network_connections() -> Result<u32> {
        let output = Command::new("netstat")
            .args(["-an"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let connections = stdout
                .lines()
                .filter(|line| line.contains(":8080") && line.contains("ESTABLISHED"))
                .count() as u32;
            return Ok(connections);
        }

        // Fallback: try lsof
        let output = Command::new("lsof")
            .args(["-i", ":8080"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let connections = stdout.lines().count() as u32;
            return Ok(connections.saturating_sub(1)); // Subtract header line
        }

        Ok(0)
    }

    /// Print detailed resource metrics
    pub async fn print_resource_summary(&self, test_name: &str) {
        let history = self.metrics_history.lock().await;
        
        if history.is_empty() {
            println!("⚠️ No resource metrics collected for {}", test_name);
            return;
        }

        let latest = &history[history.len() - 1];
        let memory_growth = self.get_memory_growth().await;
        
        println!("\n📊 Resource Usage Summary: {}", test_name);
        println!("├─ Memory Usage: {:.2} MB", latest.memory_mb);
        println!("├─ Memory Growth: {:.2} MB", memory_growth);
        println!("├─ CPU Usage: {:.2}%", latest.cpu_percent);
        
        if let Some(connections) = latest.active_connections {
            println!("├─ Active Connections: {}", connections);
        }
        
        if let Some(db_connections) = latest.db_connections {
            println!("├─ DB Connections: {}", db_connections);
        }
        
        if let Some(cache_hit_rate) = latest.cache_hit_rate {
            println!("├─ Cache Hit Rate: {:.2}%", cache_hit_rate);
        }
        
        println!("└─ Monitoring Duration: {:.2}s", 
            latest.timestamp.duration_since(history[0].timestamp).as_secs_f64());
    }
}

/// Test resource usage under normal load
#[tokio::test]
async fn test_resource_usage_under_normal_load() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping resource usage test.");
        return Ok(());
    }

    info!("📊 Testing resource usage under normal load");
    
    let mut monitor = ResourceMonitor::new();
    monitor.start_monitoring().await?;
    
    // Wait for baseline to establish
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Generate normal load
    const NORMAL_LOAD_OPERATIONS: usize = 500;
    println!("🔄 Generating normal load ({} operations)...", NORMAL_LOAD_OPERATIONS);
    
    let mut handles = Vec::new();
    for i in 0..NORMAL_LOAD_OPERATIONS {
        let client = framework.client.clone();
        
        let handle = tokio::spawn(async move {
            if i % 3 == 0 {
                // Registration operation
                let user = TestUser::new(&format!("resource_test_{}", i));
                let _ = client.register(&user).await;
            } else if i % 3 == 1 {
                // Login operation (assuming user exists)
                let user = TestUser::new(&format!("resource_test_{}", i - 1));
                let _ = client.login(&user).await;
            } else {
                // Health check operation
                let _ = client.health_check().await;
            }
        });
        
        handles.push(handle);
        
        // Add small delay to maintain steady load
        if i % 50 == 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    
    // Wait for all operations to complete
    for handle in handles {
        let _ = handle.await;
    }
    
    // Wait for metrics to stabilize
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    monitor.stop_monitoring().await;
    monitor.print_resource_summary("Normal Load Test").await;
    
    // Validate resource usage
    let targets = ResourceTargets::default();
    let final_metrics = monitor.get_current_metrics().await.unwrap_or_default();
    let memory_growth = monitor.get_memory_growth().await;
    
    assert!(
        final_metrics.memory_mb <= targets.max_memory_mb,
        "Memory usage should be ≤{}MB, got {:.2}MB",
        targets.max_memory_mb,
        final_metrics.memory_mb
    );
    
    assert!(
        final_metrics.cpu_percent <= targets.max_cpu_percent,
        "CPU usage should be ≤{}%, got {:.2}%",
        targets.max_cpu_percent,
        final_metrics.cpu_percent
    );
    
    let expected_memory_growth = (NORMAL_LOAD_OPERATIONS as f64 / 1000.0) * targets.max_memory_growth_mb;
    assert!(
        memory_growth <= expected_memory_growth,
        "Memory growth should be ≤{:.2}MB for {} operations, got {:.2}MB",
        expected_memory_growth,
        NORMAL_LOAD_OPERATIONS,
        memory_growth
    );
    
    println!("✅ Resource usage under normal load targets met");
    Ok(())
}

/// Test resource usage under sustained load
#[tokio::test]
async fn test_resource_usage_under_sustained_load() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping sustained load test.");
        return Ok(());
    }

    info!("⏱️ Testing resource usage under sustained load");
    
    let mut monitor = ResourceMonitor::new();
    monitor.start_monitoring().await?;
    
    // Wait for baseline
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Generate sustained load for extended period
    const SUSTAINED_DURATION_SECS: u64 = 30;
    const OPERATIONS_PER_SECOND: usize = 20;
    
    println!("🔄 Generating sustained load for {} seconds at {} ops/sec...", 
        SUSTAINED_DURATION_SECS, OPERATIONS_PER_SECOND);
    
    let end_time = Instant::now() + Duration::from_secs(SUSTAINED_DURATION_SECS);
    let mut operation_count = 0;
    
    while Instant::now() < end_time {
        let mut handles = Vec::new();
        
        // Generate operations for this second
        for i in 0..OPERATIONS_PER_SECOND {
            let client = framework.client.clone();
            let op_id = operation_count + i;
            
            let handle = tokio::spawn(async move {
                match op_id % 4 {
                    0 => {
                        let user = TestUser::new(&format!("sustained_test_{}", op_id));
                        let _ = client.register(&user).await;
                    },
                    1 => {
                        let user = TestUser::new(&format!("sustained_test_{}", op_id - 1));
                        let _ = client.login(&user).await;
                    },
                    2 => {
                        let _ = client.health_check().await;
                    },
                    3 => {
                        // Password reset request
                        let email = format!("sustained_test_{}@test.com", op_id);
                        let _ = client.forgot_password(&email).await;
                    },
                    _ => unreachable!(),
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for operations to complete
        for handle in handles {
            let _ = handle.await;
        }
        
        operation_count += OPERATIONS_PER_SECOND;
        
        // Maintain 1-second intervals
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
    
    // Wait for metrics to stabilize
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    monitor.stop_monitoring().await;
    monitor.print_resource_summary("Sustained Load Test").await;
    
    // Validate sustained load resource usage
    let targets = ResourceTargets::default();
    let avg_metrics = monitor.get_average_metrics(Duration::from_secs(SUSTAINED_DURATION_SECS)).await;
    let memory_growth = monitor.get_memory_growth().await;
    
    assert!(
        avg_metrics.memory_mb <= targets.max_memory_mb * 1.2, // Allow 20% more under sustained load
        "Average memory usage should be ≤{:.2}MB under sustained load, got {:.2}MB",
        targets.max_memory_mb * 1.2,
        avg_metrics.memory_mb
    );
    
    assert!(
        avg_metrics.cpu_percent <= targets.max_cpu_percent,
        "Average CPU usage should be ≤{}% under sustained load, got {:.2}%",
        targets.max_cpu_percent,
        avg_metrics.cpu_percent
    );
    
    let expected_memory_growth = (operation_count as f64 / 1000.0) * targets.max_memory_growth_mb;
    assert!(
        memory_growth <= expected_memory_growth * 1.5, // Allow more growth under sustained load
        "Memory growth should be ≤{:.2}MB for {} operations, got {:.2}MB",
        expected_memory_growth * 1.5,
        operation_count,
        memory_growth
    );
    
    println!("✅ Resource usage under sustained load targets met");
    Ok(())
}

/// Test memory leak detection
#[tokio::test]
async fn test_memory_leak_detection() -> Result<()> {
    let framework = IntegrationTestFramework::new();
    
    if !framework.is_service_running().await? {
        println!("⚠️ Auth service not running. Skipping memory leak test.");
        return Ok(());
    }

    info!("🔍 Testing memory leak detection");
    
    let mut monitor = ResourceMonitor::new();
    monitor.start_monitoring().await?;
    
    // Wait for baseline
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    const LEAK_TEST_CYCLES: usize = 5;
    const OPERATIONS_PER_CYCLE: usize = 200;
    
    let mut memory_measurements = Vec::new();
    
    for cycle in 0..LEAK_TEST_CYCLES {
        println!("🔄 Memory leak test cycle {} of {}", cycle + 1, LEAK_TEST_CYCLES);
        
        // Perform operations
        let mut handles = Vec::new();
        for i in 0..OPERATIONS_PER_CYCLE {
            let client = framework.client.clone();
            let user_id = cycle * OPERATIONS_PER_CYCLE + i;
            
            let handle = tokio::spawn(async move {
                let user = TestUser::new(&format!("leak_test_{}", user_id));
                let _ = client.register(&user).await;
                let _ = client.login(&user).await;
            });
            
            handles.push(handle);
        }
        
        for handle in handles {
            let _ = handle.await;
        }
        
        // Wait for garbage collection
        tokio::time::sleep(Duration::from_secs(3)).await;
        
        // Measure memory
        if let Some(metrics) = monitor.get_current_metrics().await {
            memory_measurements.push(metrics.memory_mb);
            println!("  Memory after cycle {}: {:.2} MB", cycle + 1, metrics.memory_mb);
        }
    }
    
    monitor.stop_monitoring().await;
    monitor.print_resource_summary("Memory Leak Detection").await;
    
    // Analyze memory growth trend
    if memory_measurements.len() >= 3 {
        let initial_memory = memory_measurements[0];
        let final_memory = memory_measurements[memory_measurements.len() - 1];
        let memory_growth = final_memory - initial_memory;
        
        // Check for linear memory growth (potential leak)
        let growth_per_cycle = memory_growth / (LEAK_TEST_CYCLES - 1) as f64;
        
        println!("📊 Memory Growth Analysis:");
        println!("├─ Initial Memory: {:.2} MB", initial_memory);
        println!("├─ Final Memory: {:.2} MB", final_memory);
        println!("├─ Total Growth: {:.2} MB", memory_growth);
        println!("└─ Growth per Cycle: {:.2} MB", growth_per_cycle);
        
        // Validate no significant memory leaks
        let targets = ResourceTargets::default();
        let max_acceptable_growth = targets.max_memory_growth_mb * 2.0; // More lenient for leak detection
        
        assert!(
            memory_growth <= max_acceptable_growth,
            "Total memory growth should be ≤{:.2}MB, got {:.2}MB (potential memory leak)",
            max_acceptable_growth,
            memory_growth
        );
        
        assert!(
            growth_per_cycle <= 5.0, // Max 5MB growth per cycle
            "Memory growth per cycle should be ≤5MB, got {:.2}MB (potential memory leak)",
            growth_per_cycle
        );
    }
    
    println!("✅ No significant memory leaks detected");
    Ok(())
}