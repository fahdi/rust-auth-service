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

### Performance Tests (Planned)
- Load testing and performance benchmarking

### Security Tests (Planned)
- Security vulnerability and attack simulation testing

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
```

#### Individual Tests
```bash
# Specific authentication test
cargo test --test simple_auth_integration test_user_registration -- --include-ignored

# Specific database test
cargo test --test database_adapters_integration test_user_creation -- --include-ignored
```

### Test Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGODB_TEST_URL` | MongoDB test database connection | `mongodb://localhost:27017/auth_test` |
| `POSTGRESQL_TEST_URL` | PostgreSQL test database connection | `postgresql://user:pass@localhost:5432/auth_test` |
| `MYSQL_TEST_URL` | MySQL test database connection | `mysql://user:pass@localhost:3306/auth_test` |
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

#### Cache Integration Tests (Issue #42)
- Redis cache connectivity and operations
- Cache hit/miss ratio validation
- Cache invalidation and TTL testing
- Multi-level cache hierarchy testing

#### Performance and Load Tests (Issue #43)
- Concurrent user load testing
- Database performance benchmarking
- Memory usage and leak detection
- Response time distribution analysis

#### Security Integration Tests (Issue #44)
- SQL injection attack simulation
- Authentication bypass attempts
- Rate limiting validation
- OWASP Top 10 vulnerability testing

#### CI/CD Integration Tests (Issue #45)
- Automated test pipeline integration
- Test result reporting and metrics
- Performance regression detection
- Automated database migration testing

### Test Infrastructure Improvements
- Automated test database provisioning
- Test data factory patterns
- Performance baseline establishment
- Test result analytics and trending