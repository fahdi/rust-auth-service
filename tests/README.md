# Integration Tests

This directory contains comprehensive integration tests for the Rust Authentication Service. Tests are organized by functionality and validate real database connections, service interactions, and end-to-end workflows.

## Test Structure

### Authentication Flow Tests
- `simple_auth_integration.rs` - Simple working authentication flow tests
- `integration/auth_flow.rs` - Advanced authentication flow tests with helper infrastructure

### Database Adapter Tests  
- `database_adapters_integration.rs` - Comprehensive database adapter testing across all supported databases

### Cache Integration Tests
- `cache_integration.rs` - Comprehensive cache layer testing including Redis, memory, multi-level, and service patterns

### Performance and Load Tests
- `performance_load_testing.rs` - Comprehensive performance benchmarks and load testing
- `benchmarks/` - Performance baseline documentation and benchmarking utilities

### Security Integration Tests
- `security_integration.rs` - Comprehensive security testing including vulnerability scanning, attack simulation, and OWASP Top 10 validation
- `security/` - Security testing documentation and baseline specifications

### CI/CD Integration and Test Automation
- `.github/workflows/ci.yml` - Main CI/CD pipeline with automated testing, security scanning, and deployment
- `.github/workflows/security.yml` - Dedicated security scanning with OWASP Top 10 validation and vulnerability assessment
- `.github/workflows/performance.yml` - Performance monitoring with regression detection and load testing
- `.github/workflows/release.yml` - Automated release pipeline with multi-platform builds and Docker publishing
- `.github/docker-compose.test.yml` - Complete testing environment with all database services
- `.github/README.md` - Comprehensive CI/CD pipeline documentation and configuration guide

## Running Tests

### Prerequisites

Before running integration tests, ensure you have the appropriate test databases running:

#### MongoDB Test Database
```bash
# Using Docker
docker run -d --name mongo-test -p 27017:27017 mongo:latest

# Set environment variable
export MONGODB_TEST_URL="mongodb://localhost:27017/auth_test"
```

#### PostgreSQL Test Database
```bash
# Using Docker
docker run -d --name postgres-test -p 5432:5432 -e POSTGRES_DB=auth_test -e POSTGRES_PASSWORD=test postgres:latest

# Set environment variable
export POSTGRESQL_TEST_URL="postgresql://postgres:test@localhost:5432/auth_test"
```

#### MySQL Test Database
```bash
# Using Docker
docker run -d --name mysql-test -p 3306:3306 -e MYSQL_DATABASE=auth_test -e MYSQL_ROOT_PASSWORD=test mysql:latest

# Set environment variable
export MYSQL_TEST_URL="mysql://root:test@localhost:3306/auth_test"
```

#### Redis Test Database
```bash
# Using Docker
docker run -d --name redis-test -p 6379:6379 redis:latest

# Set environment variable
export REDIS_TEST_URL="redis://localhost:6379"
```

### Running Tests

#### All Integration Tests
```bash
# Run all integration tests (requires all test databases)
cargo test --test "*" -- --include-ignored
```

#### Specific Test Suites
```bash
# Authentication flow tests
cargo test --test simple_auth_integration -- --include-ignored

# Database adapter tests
cargo test --test database_adapters_integration -- --include-ignored

# Cache integration tests
cargo test --test cache_integration -- --include-ignored

# Performance and load tests
cargo test --test performance_load_testing -- --include-ignored

# Security integration tests
cargo test --test security_integration -- --include-ignored
```

#### Individual Tests
```bash
# Specific authentication test
cargo test --test simple_auth_integration test_user_registration -- --include-ignored

# Specific database test
cargo test --test database_adapters_integration test_user_creation -- --include-ignored

# Specific performance test
cargo test --test performance_load_testing test_database_operation_performance -- --include-ignored

# Specific security test
cargo test --test security_integration test_authentication_bypass_attempts -- --include-ignored
```

### Test Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGODB_TEST_URL` | MongoDB test database connection | `mongodb://localhost:27017/auth_test` |
| `POSTGRESQL_TEST_URL` | PostgreSQL test database connection | `postgresql://user:pass@localhost:5432/auth_test` |
| `MYSQL_TEST_URL` | MySQL test database connection | `mysql://user:pass@localhost:3306/auth_test` |
| `REDIS_TEST_URL` | Redis test cache connection | `redis://localhost:6379` |
| `RUST_LOG` | Logging level for test output | `debug`, `info`, `warn`, `error` |

## Test Categories

### Database Adapter Integration Tests

Comprehensive testing of all database adapters (MongoDB, PostgreSQL, MySQL):

#### Core Functionality Tests
- ✅ **Health Checks** - Database connectivity and response time validation
- ✅ **User Creation** - User registration with duplicate email prevention
- ✅ **User Lookup** - Find users by email and ID (case-insensitive)
- ✅ **User Updates** - Profile updates and data persistence validation
- ✅ **Password Operations** - Password updates and hash verification

#### Authentication Flow Tests
- ✅ **Email Verification** - Token-based email verification workflow
- ✅ **Password Reset** - Token-based password reset workflow
- ✅ **Login Tracking** - Successful login recording and timestamp updates
- ✅ **Failed Login Attempts** - Failed login attempt tracking and incrementing
- ✅ **Account Lockout** - Automatic account locking after max failed attempts

#### Data Management Tests
- ✅ **User Deactivation** - Account deactivation and status validation
- ✅ **User Existence Checks** - Email existence validation (case-insensitive)
- ✅ **Error Handling** - Invalid operations and proper error responses
- ✅ **Concurrent Operations** - Multi-threaded user creation and data integrity

#### End-to-End Lifecycle Tests
- ✅ **Complete User Lifecycle** - Full user journey from creation to deactivation

### Cache Integration Tests

Comprehensive testing of all cache implementations and patterns:

#### Core Cache Operations
- ✅ **Basic Operations** - Set, get, delete operations across all cache types
- ✅ **TTL Functionality** - Time-to-live expiration testing
- ✅ **Health Checks** - Cache connectivity and ping operations
- ✅ **Statistics** - Hit/miss ratio calculation and operation tracking
- ✅ **Cache Service** - Service layer with default and custom TTL operations

#### Cache Implementation Testing
- ✅ **Memory Cache** - In-memory LRU cache with cleanup processes
- ✅ **Redis Cache** - Redis server integration and connection handling
- ✅ **No-Op Cache** - Disabled cache implementation for testing
- ✅ **Multi-Level Cache** - Redis primary with memory fallback architecture

#### Advanced Cache Patterns
- ✅ **Get-or-Set Pattern** - Cache-aside pattern with compute functions
- ✅ **Cache Key Utilities** - Structured key generation for different entity types
- ✅ **Concurrent Operations** - Multi-threaded cache access and performance validation
- ✅ **Error Handling** - Graceful degradation and error recovery testing

#### Cache Management
- ✅ **Memory Management** - LRU eviction and capacity limits
- ✅ **Performance Testing** - Operations per second and latency measurement
- ✅ **Complete Cache Workflow** - End-to-end authentication service caching patterns

### Performance and Load Tests

Comprehensive performance validation and load testing across all system components:

#### Database Performance Testing
- ✅ **Operation Performance** - CRUD operation benchmarking across MongoDB, PostgreSQL, MySQL
- ✅ **Response Time Analysis** - P50, P95, P99 percentile measurements
- ✅ **Throughput Measurement** - Operations per second under various loads
- ✅ **Performance Baselines** - Regression detection and baseline establishment

#### Cache Performance Testing  
- ✅ **Cache Operation Benchmarks** - Set, get, delete performance across cache types
- ✅ **Multi-Level Cache Performance** - Redis primary + memory fallback benchmarking
- ✅ **Throughput Analysis** - High-volume cache operation testing (1000+ ops)
- ✅ **Performance Comparison** - Memory vs Redis performance characteristics

#### Service Load Testing
- ✅ **Concurrent User Simulation** - 50+ concurrent users with realistic request patterns
- ✅ **Authentication Service Load** - Registration, login, profile access under load
- ✅ **Sustained Load Testing** - 30-second continuous load at target RPS
- ✅ **Concurrent Registration** - 100+ simultaneous user registrations

#### Resource and Performance Analysis
- ✅ **Memory Usage Patterns** - Memory consumption tracking and leak detection
- ✅ **Response Time Distribution** - Detailed latency analysis and percentiles
- ✅ **Performance Regression Baseline** - CI/CD-ready baseline establishment
- ✅ **Stress Testing** - Extended duration performance under sustained load

#### Performance Metrics and Thresholds
- **Database Operations**: >5 creates/sec, >20 lookups/sec, P95 <2000ms
- **Cache Operations**: >100 sets/sec, >500 gets/sec
- **Service Load**: >50 RPS, >95% success rate, P95 <1000ms
- **Memory Usage**: <100MB growth per 1000 operations

### Security Integration Tests

Comprehensive security testing covering vulnerability scanning, attack simulation, and OWASP Top 10 validation:

#### Authentication Security Tests
- ✅ **Authentication Bypass Prevention** - Direct access attempts without tokens
- ✅ **Invalid Token Rejection** - Malformed JWT tokens and authentication headers
- ✅ **Expired Token Validation** - Token expiration and validation testing
- ✅ **Token Manipulation Detection** - Modified and crafted token attempts
- ✅ **Session Hijacking Prevention** - Unauthorized session access validation

#### Injection Attack Prevention
- ✅ **SQL Injection Protection** - Classic SQL injection attempts across all database adapters
- ✅ **NoSQL Injection Protection** - MongoDB-specific injection patterns
- ✅ **Login Endpoint Security** - Authentication bypass via injection attempts
- ✅ **Registration Security** - User creation via injection prevention
- ✅ **Input Sanitization** - XSS, LDAP, and command injection protection

#### Rate Limiting and DDoS Protection
- ✅ **Brute Force Protection** - Rapid login attempt simulation (50 attempts)
- ✅ **Registration Flood Protection** - Mass user creation prevention (20 attempts)
- ✅ **Request Rate Validation** - High-frequency request testing and throttling
- ✅ **Attack Mitigation** - Sustained attack pattern simulation

#### Password Security Validation
- ✅ **Weak Password Rejection** - 14 common weak password patterns tested
- ✅ **Strong Password Acceptance** - Complex password validation (4 patterns)
- ✅ **Password Policy Enforcement** - Minimum security standards compliance
- ✅ **Dictionary Attack Prevention** - Common password list validation

#### Input Validation and Sanitization
- ✅ **XSS Prevention** - Cross-site scripting payload detection (7 patterns)
- ✅ **LDAP Injection Prevention** - Directory traversal attack protection (4 patterns)
- ✅ **Command Injection Protection** - OS command execution prevention (6 patterns)
- ✅ **Buffer Overflow Prevention** - Oversized input handling (10,000 characters)
- ✅ **Special Character Handling** - Unicode and encoding attack protection

#### Session Security and Token Management
- ✅ **JWT Token Security** - Token-based authentication validation
- ✅ **Session Invalidation** - Post-logout token rejection testing
- ✅ **Concurrent Session Management** - Multiple session handling validation
- ✅ **Token Format Validation** - Malformed token detection (4 manipulation types)
- ✅ **Session Timeout Enforcement** - Automatic session expiration validation

#### Security Headers and CORS Validation
- ✅ **HTTP Security Headers** - 6 critical security headers across 4 endpoints
- ✅ **CORS Policy Validation** - Cross-origin request security enforcement
- ✅ **Content Security Policy** - XSS and injection prevention headers
- ✅ **Security Header Compliance** - Industry standard adherence validation

#### Comprehensive Security Audit
- ✅ **OWASP Top 10 Coverage** - Complete vulnerability assessment
- ✅ **Security Grade Calculation** - Overall security posture scoring (A+ to F)
- ✅ **Vulnerability Detection** - Total security issues identification and reporting
- ✅ **Security Metrics Dashboard** - Comprehensive security monitoring and alerting

#### Security Metrics and Thresholds
- **Authentication Security**: 100% bypass prevention, 98% token rejection
- **Injection Prevention**: 90% attack rejection, 0% successful bypasses
- **Rate Limiting**: 80% attack mitigation, rate limiting activation
- **Password Security**: 95% weak password rejection, 85% strong password acceptance
- **Input Validation**: 85% malicious input rejection, comprehensive sanitization
- **Session Security**: 80% session tests passed, no token vulnerabilities
- **Overall Security**: 75% minimum pass rate, ≤3 vulnerabilities maximum

### Authentication Flow Integration Tests

End-to-end authentication testing with live service:

#### Service Health Tests
- ✅ **Health Endpoint** - Service availability and health check validation
- ✅ **Service Readiness** - Automated waiting for service startup

#### User Management Tests
- ✅ **User Registration** - Complete registration flow with validation
- ✅ **User Login** - Authentication and token generation
- ✅ **Protected Endpoints** - Token-based access control validation
- ✅ **Profile Access** - Authenticated user profile retrieval
- ✅ **Profile Updates** - Authenticated profile modification

#### Validation Tests
- ✅ **Registration Validation** - Email format and password strength validation
- ✅ **Authentication Security** - Unauthorized access prevention
- ✅ **Token Validation** - JWT token verification and expiration

#### Advanced Flow Tests
- ✅ **Complete Authentication Flow** - Multi-step authentication journey
- ✅ **Session Management** - Login, access, update, logout workflow
- ✅ **Token Invalidation** - Logout and token revocation validation
- ✅ **Concurrent Users** - Multiple simultaneous user registration

## Test Data Isolation

All tests use unique, isolated test data:

- **Unique User Generation** - Each test creates users with unique UUIDs
- **Email Isolation** - Test emails use unique prefixes and suffixes
- **Database Separation** - Tests use separate test databases
- **Clean Test Environment** - No shared state between test runs

## Performance Characteristics

Integration tests are designed to validate performance expectations:

- **Response Times** - Database operations < 1000ms
- **Concurrent Operations** - 80%+ success rate for simultaneous operations
- **Health Checks** - Service availability within 30 seconds
- **Authentication Speed** - Sub-100ms authentication responses

## Test Output and Debugging

Tests provide comprehensive output for debugging:

```bash
# Enable debug logging
RUST_LOG=debug cargo test --test database_adapters_integration -- --include-ignored

# Test-specific output patterns
🔍 Testing mongodb user creation
✅ mongodb user creation passed
📊 mongodb Concurrent Operations - Success: 9, Failed: 1
```

### Common Test Patterns

#### Success Indicators
- ✅ Green checkmarks indicate successful test completion
- 📊 Statistics show performance and success rates
- 🚀 Workflow indicators show multi-step test progress

#### Diagnostic Information
- ⚠️ Warnings indicate non-critical issues (e.g., database unavailable)
- ❌ Errors indicate test failures with specific details
- 🔍 Magnifying glass indicates test step in progress

## Continuous Integration

Tests are designed for CI/CD environments:

- **Automated Database Setup** - Docker containers for test databases
- **Environment Validation** - Automatic database availability checking
- **Graceful Degradation** - Skip tests when databases unavailable
- **Parallel Execution** - Safe concurrent test execution

## Adding New Tests

### Test Naming Convention
- Use descriptive test names: `test_user_creation`, `test_password_reset_flow`
- Include database type in multi-adapter tests: `test_mongodb_user_lookup`
- Use `#[ignore]` attribute for integration tests requiring external services

### Test Structure Pattern
```rust
#[tokio::test]
#[ignore]
async fn test_new_functionality() {
    // Setup phase
    let databases = create_test_databases().await;
    
    for db in databases {
        println!("🔍 Testing {} new functionality", db.database_type);
        
        // Test implementation
        let result = test_specific_functionality(&db).await;
        
        // Assertions
        assert!(result.is_ok(), "{} should handle functionality correctly", db.database_type);
        
        println!("✅ {} new functionality passed", db.database_type);
    }
}
```

### Error Handling Guidelines
- Always provide context in error messages
- Include database type in multi-adapter error messages
- Use descriptive assertion messages
- Test both success and failure scenarios

## Troubleshooting

### Common Issues

#### Database Connection Failures
```
⚠️ MongoDB test database unavailable: connection refused
```
**Solution**: Ensure test database is running and environment variables are set

#### Compilation Errors
```
error[E0560]: struct `DatabaseConfig` has no field named `database_type`
```
**Solution**: Check field names match current model definitions

#### Test Timeouts
```
Auth service not available after 30 attempts
```
**Solution**: Ensure auth service is running on expected port (8090)

### Debug Mode
Enable comprehensive debug output:
```bash
RUST_LOG=rust_auth_service=debug,database_adapters_integration=debug cargo test --test database_adapters_integration -- --include-ignored --nocapture
```

## Future Enhancements

### Planned Test Categories

#### CI/CD Integration and Test Automation ✅ COMPLETED
- ✅ **Automated Test Pipeline** - Complete GitHub Actions CI/CD workflow integration
- ✅ **Security Scanning** - Comprehensive vulnerability assessment and OWASP validation
- ✅ **Performance Monitoring** - Automated performance regression detection and load testing
- ✅ **Release Pipeline** - Multi-platform binary builds and Docker image publishing
- ✅ **Test Result Reporting** - Automated PR comments and test result aggregation
- ✅ **Docker Integration** - Multi-stage production-ready containerization
- ✅ **Quality Gates** - Comprehensive validation with A+ to F grading systems

### Test Infrastructure Improvements
- Automated test database provisioning
- Test data factory patterns
- Performance baseline establishment
- Test result analytics and trending