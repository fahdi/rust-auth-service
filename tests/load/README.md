# Load Testing Documentation

This directory contains load testing configurations and scripts for the Rust Auth Service.

## Files

### Artillery Load Tests
- **`auth_load_test.yml`** - Main authentication flow load testing
- **`database_stress.yml`** - Database-specific stress testing  
- **`cache_performance.yml`** - Cache performance and invalidation testing
- **`auth_processor.js`** - Artillery processor functions for custom logic

## Running Load Tests

### Prerequisites
```bash
# Install Artillery
npm install -g artillery@latest

# Build release version of service
cargo build --release

# Start the service
./target/release/rust-auth-service &
```

### Running Individual Tests

```bash
# Basic authentication load test
artillery run tests/load/auth_load_test.yml

# Database stress testing
artillery run tests/load/database_stress.yml

# Cache performance testing  
artillery run tests/load/cache_performance.yml
```

### Running All Tests
```bash
# Run comprehensive load test suite
for test in tests/load/*.yml; do
    echo "Running $test..."
    artillery run "$test"
    sleep 10  # Cool-down between tests
done
```

## Performance Targets

### Response Time Targets
- **Health checks**: <10ms P95
- **Authentication**: <100ms P95  
- **Registration**: <200ms P95
- **Profile operations**: <50ms P95
- **Cache hits**: <30ms P95

### Throughput Targets
- **Health checks**: >10,000 RPS
- **Login**: >1,000 RPS
- **Registration**: >500 RPS
- **Protected endpoints**: >2,000 RPS

### Success Rate Targets
- **Overall**: >95% success rate
- **Cache operations**: >98% success rate
- **Database operations**: >90% success rate

## Test Scenarios

### Authentication Load Test (`auth_load_test.yml`)
- **User Registration Flow** (30% weight)
- **User Login Flow** (40% weight)  
- **Password Reset Flow** (20% weight)
- **Health Check Endpoints** (10% weight)

### Database Stress Test (`database_stress.yml`)
- **Heavy Database Reads** (40% weight)
- **Concurrent Registration** (30% weight)
- **Login/Logout Cycles** (20% weight)
- **Profile Updates** (10% weight)

### Cache Performance Test (`cache_performance.yml`)
- **Cache Hit Patterns** (50% weight)
- **Cache Invalidation** (30% weight)
- **Session Caching** (15% weight)
- **Rate Limiting Cache** (5% weight)

## Custom Metrics

The tests track custom metrics via the processor:
- `auth.successes` / `auth.failures`
- `auth.valid_token` / `auth.invalid_token`
- `performance.fast_responses` / `performance.slow_responses`
- Endpoint-specific response times

## Interpreting Results

### Key Metrics to Monitor
1. **Response Times**: P95 and P99 percentiles
2. **Request Rate**: Requests per second achieved
3. **Success Rate**: Percentage of successful requests
4. **Custom Metrics**: Authentication-specific metrics

### Success Criteria
- All performance targets met
- No errors or timeouts
- Stable memory usage
- Database connections within limits
- Cache hit rate >85%

## CI/CD Integration

These load tests are automatically run in the CI/CD pipeline during:
- Pull requests to main branch
- Main branch pushes
- Performance testing job in GitHub Actions

## Troubleshooting

### Common Issues
1. **Service not responding**: Ensure service is running on port 8080
2. **Database errors**: Check database containers are running
3. **High response times**: Check system resources and scaling
4. **Low success rates**: Investigate error logs and rate limiting

### Debugging Commands
```bash
# Check service health
curl http://localhost:8080/health

# Check service logs
docker logs rust-auth-service

# Monitor system resources
htop

# Check database connections
docker exec -it mongodb mongosh
docker exec -it postgres psql -U postgres
```