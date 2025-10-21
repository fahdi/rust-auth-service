# Artillery Load Testing for Rust Auth Service

This directory contains Artillery load testing configurations and scenarios designed to validate the performance targets specified in Issue #43.

## Performance Targets (From Issue #43)

### Response Time Targets
- **Authentication**: <100ms P95
- **Registration**: <200ms P95  
- **Password Reset**: <150ms P95
- **Profile Access**: <50ms P95
- **Health Check**: <10ms P95

### Throughput Targets
- **Login**: >1000 RPS
- **Registration**: >500 RPS
- **Protected Endpoints**: >2000 RPS
- **Health Check**: >10000 RPS

### Resource Usage Targets
- **Memory**: <100MB under normal load
- **CPU**: <70% utilization
- **Database Connections**: <50% of pool
- **Cache Hit Rate**: >85%

## Files

### `artillery.yml`
Main Artillery configuration file with:
- **Multi-phase load testing**: Warm-up → Ramp-up → Sustained → Peak → Cool-down
- **Performance targets**: P95/P99 response times and error rate thresholds
- **Multiple scenarios**: Health checks, registration, authentication, protected endpoints
- **Realistic workload patterns**: Mixed workload scenarios with think times

### `scenarios.js`
Custom JavaScript functions for Artillery scenarios:
- **User management**: Unique user generation and existing user selection
- **Token management**: Access token pooling for protected endpoint testing
- **Performance validation**: Real-time validation against Issue #43 targets
- **Resource monitoring**: Request tracking and performance analysis
- **Realistic data**: Diverse user profiles and load patterns

### `test_users.csv`
Pre-generated test user data for consistent load testing:
- 50 test users with unique credentials
- Designed for registration and authentication scenarios
- Prevents conflicts during concurrent testing

## Running Load Tests

### Prerequisites

1. **Install Artillery**:
```bash
npm install -g artillery
```

2. **Start Auth Service**:
```bash
# In auth service directory
cargo run --release
```

3. **Verify Service Health**:
```bash
curl http://localhost:8080/health
```

### Basic Load Tests

**Quick Health Check Load Test**:
```bash
artillery quick --count 100 --num 10 http://localhost:8080/health
```

**Full Load Test Suite**:
```bash
cd tests/load_testing/artillery
artillery run artillery.yml
```

**Load Test with Detailed Reporting**:
```bash
artillery run artillery.yml --output report.json
artillery report report.json
```

### Targeted Load Tests

**High RPS Health Check Test**:
```bash
artillery quick --count 1000 --num 100 http://localhost:8080/health
```

**Registration Load Test**:
```bash
artillery run artillery.yml --scenario "User Registration Load"
```

**Authentication Load Test**:
```bash
artillery run artillery.yml --scenario "User Authentication Load"
```

**Protected Endpoint Load Test**:
```bash
artillery run artillery.yml --scenario "Protected Endpoint Load"
```

### Advanced Load Testing

**Extended Duration Test** (30 minutes):
```bash
artillery run artillery.yml --config '{"phases":[{"duration":1800,"arrivalRate":50}]}'
```

**High Concurrency Stress Test**:
```bash
artillery run artillery.yml --config '{"phases":[{"duration":300,"arrivalRate":200}]}'
```

**Memory Pressure Test**:
```bash
artillery run artillery.yml --config '{"phases":[{"duration":600,"arrivalRate":100}]}'
```

## Performance Validation

### Automated Validation
The Artillery configuration includes automatic validation of:
- **Response Times**: P95 < 200ms, P99 < 500ms
- **Error Rates**: <5% error rate
- **Success Rates**: >95% success rate per scenario

### Manual Validation
Check results against Issue #43 targets:

```bash
# Example output validation
artillery run artillery.yml | grep -E "(p95|p99|rps|errors)"
```

Expected results should show:
- Health checks: >10,000 RPS, <10ms P95
- Authentication: >1,000 RPS, <100ms P95
- Registration: >500 RPS, <200ms P95
- Protected endpoints: >2,000 RPS, <50ms P95

## Performance Monitoring

### Real-time Monitoring
Monitor system resources during load tests:

```bash
# CPU and Memory monitoring
top -p $(pgrep rust-auth-service)

# Network connections
netstat -an | grep :8080 | wc -l

# Database connections (if using PostgreSQL)
psql -c "SELECT count(*) FROM pg_stat_activity WHERE application_name LIKE '%rust%';"
```

### Artillery Metrics
Key metrics to monitor:
- **RPS (Requests Per Second)**: Current throughput
- **Response Time Percentiles**: P50, P95, P99
- **Error Rate**: Percentage of failed requests
- **Concurrent Users**: Active virtual users
- **Scenario Completion**: Success rate per scenario

### Service Metrics
Monitor via Prometheus endpoint:
```bash
curl http://localhost:8080/metrics | grep -E "(http_requests|response_time|memory)"
```

## Troubleshooting

### Common Issues

**Connection Refused Errors**:
- Verify auth service is running on port 8080
- Check firewall settings
- Increase connection pool size in service config

**High Response Times**:
- Monitor CPU and memory usage
- Check database connection pool utilization
- Verify Redis cache is running and accessible

**Error Rate > 5%**:
- Check service logs for error patterns
- Verify test data is valid
- Monitor database performance

**Low Throughput**:
- Increase Artillery arrival rate gradually
- Check for bottlenecks in database or cache
- Monitor network latency

### Performance Tuning

**Service Configuration**:
```yaml
# config.yml optimizations
server:
  workers: 4  # Match CPU cores
  max_connections: 10000

database:
  pool_size: 50  # Adjust based on load
  
cache:
  max_connections: 100
```

**Artillery Configuration**:
```yaml
# artillery.yml optimizations
config:
  http:
    pool: 100  # Increase connection pool
    timeout: 30
  phases:
    - duration: 60
      arrivalRate: 50  # Start conservative
```

## Continuous Performance Testing

### CI/CD Integration
Add to GitHub Actions:

```yaml
- name: Performance Load Testing
  run: |
    cargo run --release &
    sleep 10
    cd tests/load_testing/artillery
    artillery run artillery.yml --quiet
    kill %1
```

### Performance Regression Detection
Compare results against baselines:

```bash
# Store baseline
artillery run artillery.yml --output baseline.json

# Compare against baseline
artillery run artillery.yml --output current.json
artillery compare baseline.json current.json
```

### Alerting Thresholds
Set up alerts for:
- **Response Time Regression**: >20% increase in P95
- **Throughput Degradation**: >15% decrease in RPS
- **Error Rate Spike**: >2% error rate
- **Resource Exhaustion**: >80% CPU or memory usage

## Performance Test Schedule

### Regular Testing
- **Daily**: Quick health check load test
- **Weekly**: Full load test suite
- **Monthly**: Extended duration stress test
- **Release**: Comprehensive performance validation

### Load Test Matrix
| Test Type | Duration | RPS | Scenarios | Purpose |
|-----------|----------|-----|-----------|---------|
| Smoke | 1 min | 10 | Health only | Basic functionality |
| Load | 10 min | 100 | All scenarios | Normal load validation |
| Stress | 30 min | 200 | All scenarios | Peak load validation |
| Soak | 2 hours | 50 | Mixed workload | Stability validation |

This comprehensive load testing setup ensures the Rust Auth Service meets all performance targets specified in Issue #43 while providing ongoing performance monitoring and regression detection capabilities.