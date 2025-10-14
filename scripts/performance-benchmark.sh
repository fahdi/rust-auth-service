#!/bin/bash

# Performance benchmark script comparing all database providers
# Measures throughput, latency, and resource usage

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}📊 Rust Auth Service - Performance Benchmark${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Configuration
CONCURRENT_USERS=(1 10 50 100)
OPERATIONS_PER_USER=100
DATABASES=("mongodb" "postgresql" "mysql")

# Database URLs
declare -A DB_URLS
DB_URLS["mongodb"]="mongodb://admin:password123@localhost:27017/auth_service_test?authSource=admin"
DB_URLS["postgresql"]="postgresql://postgres:password123@localhost:5432/auth_service_test"
DB_URLS["mysql"]="mysql://root:password123@localhost:3306/auth_service_test"

# Results storage
RESULTS_DIR="benchmark_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo -e "${YELLOW}📁 Results will be saved to: $RESULTS_DIR${NC}"
echo ""

# Function to run benchmark for a specific database and concurrency level
run_benchmark() {
    local db_type=$1
    local concurrent_users=$2
    local db_url="${DB_URLS[$db_type]}"
    
    echo -e "${BLUE}🚀 Benchmarking $db_type with $concurrent_users concurrent users${NC}"
    
    # Start monitoring system resources
    echo "timestamp,cpu_percent,memory_mb,database" > "$RESULTS_DIR/resources_${db_type}_${concurrent_users}.csv"
    
    # Background process to monitor resources
    {
        while true; do
            local timestamp=$(date +%s)
            local cpu=$(ps -eo pcpu,comm | grep -E "(mongod|postgres|mysqld)" | awk '{sum+=$1} END {print sum}')
            local memory=$(ps -eo rss,comm | grep -E "(mongod|postgres|mysqld)" | awk '{sum+=$1} END {print sum/1024}')
            echo "$timestamp,$cpu,$memory,$db_type" >> "$RESULTS_DIR/resources_${db_type}_${concurrent_users}.csv"
            sleep 1
        done
    } &
    local monitor_pid=$!
    
    # Create benchmark test
    cat > "$RESULTS_DIR/benchmark_${db_type}_${concurrent_users}.rs" << EOF
use std::time::{Duration, Instant};
use tokio::time::sleep;
use std::sync::Arc;
use tokio::sync::Semaphore;
use futures::future::join_all;
use uuid::Uuid;

use rust_auth_service::config::database::{DatabaseConfig, PoolConfig};
use rust_auth_service::database::create_database;
use rust_auth_service::models::user::{User, CreateUserRequest, UserRole};
use rust_auth_service::utils::password::hash_password;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_config = DatabaseConfig {
        r#type: "$db_type".to_string(),
        url: "$db_url".to_string(),
        pool: PoolConfig {
            min_connections: 10,
            max_connections: 100,
            idle_timeout: 300,
        },
    };
    
    let db = create_database(&db_config).await?;
    let semaphore = Arc::new(Semaphore::new($concurrent_users));
    
    println!("Starting benchmark: $db_type with $concurrent_users users, $OPERATIONS_PER_USER ops each");
    
    let start_time = Instant::now();
    let mut handles = Vec::new();
    
    for user_id in 0..$concurrent_users {
        let db = db.clone();
        let semaphore = semaphore.clone();
        
        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let mut operation_times = Vec::new();
            
            for op_id in 0..$OPERATIONS_PER_USER {
                let email = format!("bench_{}_{}_{}@example.com", "$db_type", user_id, op_id);
                
                // Measure user creation
                let op_start = Instant::now();
                
                let request = CreateUserRequest {
                    email: email.clone(),
                    password: "BenchmarkPassword123!".to_string(),
                    first_name: "Bench".to_string(),
                    last_name: "User".to_string(),
                    role: Some(UserRole::User),
                    metadata: None,
                };
                
                let password_hash = hash_password("BenchmarkPassword123!", 4).unwrap();
                let user = User::new(request, password_hash);
                
                if let Ok(created_user) = db.create_user(user).await {
                    // Measure user lookup
                    let _ = db.find_user_by_email(&email).await;
                    
                    // Measure health check
                    let _ = db.health_check().await;
                    
                    // Cleanup
                    let _ = db.deactivate_user(&created_user.user_id).await;
                }
                
                let op_time = op_start.elapsed();
                operation_times.push(op_time.as_millis());
                
                // Small delay to prevent overwhelming the database
                sleep(Duration::from_millis(1)).await;
            }
            
            operation_times
        });
        
        handles.push(handle);
    }
    
    let results = join_all(handles).await;
    let total_time = start_time.elapsed();
    
    // Collect all operation times
    let mut all_times = Vec::new();
    for result in results {
        if let Ok(times) = result {
            all_times.extend(times);
        }
    }
    
    // Calculate statistics
    all_times.sort();
    let total_ops = all_times.len();
    let avg_time = all_times.iter().sum::<u128>() as f64 / total_ops as f64;
    let p50 = all_times[total_ops / 2];
    let p95 = all_times[(total_ops as f64 * 0.95) as usize];
    let p99 = all_times[(total_ops as f64 * 0.99) as usize];
    let throughput = total_ops as f64 / total_time.as_secs_f64();
    
    println!("Benchmark Results for $db_type:");
    println!("  Total Operations: {}", total_ops);
    println!("  Total Time: {:?}", total_time);
    println!("  Throughput: {:.2} ops/sec", throughput);
    println!("  Average Latency: {:.2}ms", avg_time);
    println!("  P50 Latency: {}ms", p50);
    println!("  P95 Latency: {}ms", p95);
    println!("  P99 Latency: {}ms", p99);
    
    // Write results to CSV
    println!("{},{},{:.2},{:.2},{},{},{},{}", 
        "$db_type", $concurrent_users, throughput, avg_time, p50, p95, p99, total_ops);
    
    Ok(())
}
EOF
    
    # Run the benchmark
    local output=$(timeout 300s cargo run --bin benchmark_${db_type}_${concurrent_users} --quiet 2>/dev/null || echo "TIMEOUT,0,0,0,0,0,0,0")
    echo "$output" >> "$RESULTS_DIR/results.csv"
    
    # Stop resource monitoring
    kill $monitor_pid 2>/dev/null || true
    
    # Cleanup benchmark file
    rm -f "$RESULTS_DIR/benchmark_${db_type}_${concurrent_users}.rs"
    
    echo -e "${GREEN}✅ Completed $db_type benchmark with $concurrent_users users${NC}"
    echo ""
}

# Initialize results file
echo "database,concurrent_users,throughput_ops_per_sec,avg_latency_ms,p50_latency_ms,p95_latency_ms,p99_latency_ms,total_operations" > "$RESULTS_DIR/results.csv"

# Run benchmarks for all combinations
for db in "${DATABASES[@]}"; do
    for users in "${CONCURRENT_USERS[@]}"; do
        run_benchmark "$db" "$users"
        
        # Cool down period between tests
        echo -e "${YELLOW}😴 Cool down period (10 seconds)...${NC}"
        sleep 10
    done
done

# Generate summary report
echo -e "${BLUE}📈 Generating summary report...${NC}"

cat > "$RESULTS_DIR/summary.md" << 'EOF'
# Performance Benchmark Results

## Test Configuration
- **Databases**: MongoDB, PostgreSQL, MySQL
- **Concurrent Users**: 1, 10, 50, 100
- **Operations per User**: 100
- **Test Type**: Create user, lookup user, health check, cleanup

## Results Summary

| Database | Concurrent Users | Throughput (ops/sec) | Avg Latency (ms) | P95 Latency (ms) |
|----------|------------------|---------------------|------------------|------------------|
EOF

# Add results to markdown table
while IFS=, read -r db users throughput avg_lat p50 p95 p99 total_ops; do
    if [ "$db" != "database" ]; then  # Skip header
        printf "| %s | %s | %.2f | %.2f | %s |\n" "$db" "$users" "$throughput" "$avg_lat" "$p95" >> "$RESULTS_DIR/summary.md"
    fi
done < "$RESULTS_DIR/results.csv"

cat >> "$RESULTS_DIR/summary.md" << 'EOF'

## Analysis

### Throughput Comparison
The throughput test measures how many complete user operations (create, lookup, health check) each database can handle per second under different concurrency levels.

### Latency Analysis
- **P50**: Median response time
- **P95**: 95th percentile response time
- **P99**: 99th percentile response time

### Resource Usage
Resource monitoring data is available in the `resources_*.csv` files for detailed analysis.

## Recommendations

Based on the benchmark results:

1. **For High Throughput**: Choose the database with highest ops/sec
2. **For Low Latency**: Choose the database with lowest P95 latency
3. **For Consistency**: Choose the database with smallest gap between P50 and P99

EOF

echo -e "${GREEN}✅ Benchmark completed!${NC}"
echo -e "${BLUE}📄 Results saved to: $RESULTS_DIR/${NC}"
echo -e "${BLUE}📊 Summary report: $RESULTS_DIR/summary.md${NC}"
echo ""

# Display quick summary
echo -e "${YELLOW}📋 Quick Summary:${NC}"
echo "Database Performance Ranking (by throughput at 100 concurrent users):"
tail -n +2 "$RESULTS_DIR/results.csv" | grep ",100," | sort -t',' -k3 -nr | head -3 | while IFS=, read -r db users throughput rest; do
    echo "  🏆 $db: $throughput ops/sec"
done