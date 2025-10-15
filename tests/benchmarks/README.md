# Performance Benchmarks

This directory contains performance benchmarking tools and baseline measurements for the Rust Authentication Service.

## Benchmark Categories

### Database Performance Benchmarks
- **User CRUD Operations** - Create, read, update, delete performance across MongoDB, PostgreSQL, MySQL
- **Authentication Flow Performance** - Login, registration, email verification, password reset performance
- **Concurrent Operation Performance** - Multi-threaded database access and connection pooling efficiency
- **Query Performance** - Complex queries, indexing efficiency, and lookup performance

### Cache Performance Benchmarks
- **Cache Operations** - Set, get, delete performance across memory and Redis caches
- **Multi-Level Cache Performance** - Redis primary + memory fallback performance characteristics
- **Cache Hit/Miss Ratios** - Performance under different cache scenarios
- **Cache Eviction Performance** - LRU eviction and memory management efficiency

### Service Load Performance Benchmarks
- **Authentication Service Load** - Concurrent user simulation and RPS measurement
- **Response Time Distribution** - P50, P95, P99 response time percentiles
- **Sustained Load Testing** - Long-duration performance under continuous load
- **Memory Usage Patterns** - Resource consumption and memory leak detection

## Performance Baselines

### Database Operations (per operation)
| Operation | MongoDB | PostgreSQL | MySQL | Target |
|-----------|---------|------------|-------|--------|
| User Create | ~20ms | ~15ms | ~18ms | <50ms |
| User Lookup | ~5ms | ~3ms | ~4ms | <10ms |
| User Update | ~12ms | ~8ms | ~10ms | <25ms |
| Bulk Operations (100 users) | ~1.5s | ~1.2s | ~1.4s | <3s |

### Cache Operations (per operation)
| Operation | Memory Cache | Redis Cache | Target |
|-----------|--------------|-------------|--------|
| Set | ~0.1ms | ~1ms | <5ms |
| Get | ~0.05ms | ~0.8ms | <3ms |
| Delete | ~0.1ms | ~1ms | <5ms |
| Bulk Operations (1000 ops) | ~100ms | ~800ms | <1s |

### Authentication Service Load
| Metric | Target | Production Goal |
|--------|--------|------------------|
| RPS (Requests/sec) | >50 | >200 |
| Registration Rate | >10/sec | >50/sec |
| Concurrent Users | 50+ | 500+ |
| P95 Response Time | <1000ms | <200ms |
| Success Rate | >95% | >99.9% |
| Memory Growth | <100MB/1000 ops | <50MB/1000 ops |

## Running Benchmarks

### Prerequisites
Ensure all test databases and services are running:

```bash
# Start test databases
docker run -d --name mongo-test -p 27017:27017 mongo:latest
docker run -d --name postgres-test -p 5432:5432 -e POSTGRES_DB=auth_test -e POSTGRES_PASSWORD=test postgres:latest
docker run -d --name mysql-test -p 3306:3306 -e MYSQL_DATABASE=auth_test -e MYSQL_ROOT_PASSWORD=test mysql:latest
docker run -d --name redis-test -p 6379:6379 redis:latest

# Set environment variables
export MONGODB_TEST_URL="mongodb://localhost:27017/auth_test"
export POSTGRESQL_TEST_URL="postgresql://postgres:test@localhost:5432/auth_test"
export MYSQL_TEST_URL="mysql://root:test@localhost:3306/auth_test"
export REDIS_TEST_URL="redis://localhost:6379"

# Start auth service for load testing
cargo run --release &
```

### Individual Benchmark Tests

```bash
# Database performance benchmarks
cargo test --test performance_load_testing test_database_operation_performance -- --include-ignored

# Cache performance benchmarks
cargo test --test performance_load_testing test_cache_operation_performance -- --include-ignored

# Service load testing
cargo test --test performance_load_testing test_authentication_service_load -- --include-ignored

# Concurrent operation testing
cargo test --test performance_load_testing test_concurrent_user_registration_performance -- --include-ignored

# Memory usage testing
cargo test --test performance_load_testing test_memory_and_resource_consumption -- --include-ignored

# Sustained load stress testing
cargo test --test performance_load_testing test_sustained_load_stress_test -- --include-ignored

# Performance regression baseline
cargo test --test performance_load_testing test_performance_regression_baseline -- --include-ignored
```

### Complete Benchmark Suite

```bash
# Run all performance benchmarks
cargo test --test performance_load_testing -- --include-ignored

# Run with detailed output
RUST_LOG=info cargo test --test performance_load_testing -- --include-ignored --nocapture
```

## Benchmark Test Details

### Database Operation Performance (`test_database_operation_performance`)
- **Operations**: 100 user creates + 50 user lookups per database
- **Metrics**: Operations/sec, P95 response time, success rate
- **Thresholds**: >5 creates/sec, >20 lookups/sec, P95 <2000ms

### Cache Operation Performance (`test_cache_operation_performance`)
- **Operations**: 1000 sets + 1000 gets per cache type
- **Metrics**: Operations/sec, response time distribution
- **Thresholds**: >100 sets/sec, >500 gets/sec

### Authentication Service Load (`test_authentication_service_load`)
- **Load**: 50 concurrent users, 10 requests each (500 total requests)
- **Metrics**: RPS, success rate, P95 response time
- **Thresholds**: >50 RPS, >95% success rate, P95 <1000ms

### Concurrent User Registration (`test_concurrent_user_registration_performance`)
- **Load**: 100 simultaneous user registrations
- **Metrics**: Registration rate, success rate
- **Thresholds**: >10 registrations/sec, >90% success rate

### Memory and Resource Consumption (`test_memory_and_resource_consumption`)
- **Operations**: 500 user creations with memory tracking
- **Metrics**: Memory growth per operation, total growth
- **Thresholds**: <100MB total growth, reasonable per-operation overhead

### Sustained Load Stress Test (`test_sustained_load_stress_test`)
- **Duration**: 30 seconds at 20 RPS target
- **Metrics**: Sustained RPS, success rate over time
- **Thresholds**: >98% success rate, >80% of target RPS

### Performance Regression Baseline (`test_performance_regression_baseline`)
- **Purpose**: Establish baseline metrics for CI/CD regression detection
- **Metrics**: Single operation baselines for all components
- **Usage**: Compare against historical baselines to detect regressions

## Performance Optimization Tips

### Database Performance
- **Connection Pooling**: Properly configured pool sizes for expected load
- **Indexing Strategy**: Ensure indexes on frequently queried fields (email, user_id)
- **Query Optimization**: Use efficient queries and avoid N+1 problems
- **Database Tuning**: Optimize database configuration for workload

### Cache Performance  
- **Cache Strategy**: Implement cache-aside pattern with appropriate TTLs
- **Cache Sizing**: Size memory cache appropriately for working set
- **Redis Optimization**: Use pipelining and connection pooling for Redis
- **Multi-Level Strategy**: Optimize Redis primary + memory fallback architecture

### Service Performance
- **Async Architecture**: Leverage Tokio async runtime efficiently
- **Resource Management**: Proper connection and memory management
- **Monitoring**: Use Prometheus metrics to identify bottlenecks
- **Load Balancing**: Distribute load across multiple service instances

## Continuous Performance Monitoring

### CI/CD Integration
Performance benchmarks should be integrated into CI/CD pipeline:

```yaml
# Example GitHub Actions performance test
- name: Performance Benchmarks
  run: |
    # Start test services
    docker-compose -f tests/docker-compose.test.yml up -d
    
    # Wait for services to be ready
    sleep 30
    
    # Run performance regression baseline
    cargo test --test performance_load_testing test_performance_regression_baseline -- --include-ignored
    
    # Compare against historical baselines
    # (Implementation depends on your baseline storage strategy)
```

### Performance Alerting
Set up alerting for performance regressions:
- **Response Time Increase**: >20% increase in P95 response times
- **Throughput Decrease**: >15% decrease in operations per second
- **Memory Growth**: >50% increase in memory consumption
- **Success Rate Drop**: <95% success rate in any benchmark

### Baseline Management
- **Historical Tracking**: Store baseline results for trend analysis
- **Regression Detection**: Automated comparison against previous baselines
- **Performance Dashboard**: Visualize performance trends over time
- **Capacity Planning**: Use performance data for infrastructure planning

## Troubleshooting Performance Issues

### Common Performance Problems

#### High Response Times
- Check database connection pool exhaustion
- Verify database query performance and indexing
- Monitor cache hit ratios and Redis performance
- Analyze service resource utilization

#### Low Throughput
- Increase connection pool sizes
- Optimize async operation batching  
- Check for database locks or blocking operations
- Verify network latency between components

#### Memory Issues
- Profile memory usage patterns
- Check for connection leaks
- Analyze cache memory usage
- Monitor garbage collection impact

#### Inconsistent Performance
- Check for resource contention
- Analyze performance under different load patterns
- Monitor system resources (CPU, disk I/O)
- Verify consistent test environment setup

### Performance Debugging Tools
- **Database Profiling**: Use database-specific profiling tools
- **Memory Profiling**: Use Rust memory profiling tools (valgrind, heaptrack)
- **Network Analysis**: Monitor network latency and bandwidth
- **Service Monitoring**: Use Prometheus metrics and tracing