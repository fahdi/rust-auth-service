# Test Coverage Documentation

## Overview

This document outlines the test coverage standards, reporting mechanisms, and improvement strategies for the Rust Auth Service project.

## Coverage Goals

### Overall Target: 80%
### Minimum Threshold: 70%

## Module-Specific Coverage Targets

### Critical Security Modules (85-90% coverage required)
- **Authentication Handlers** (`src/handlers/auth.rs`) - Target: 85%
  - Login/logout flows
  - Registration processes
  - Token validation
  - Password reset workflows

- **JWT Utilities** (`src/utils/jwt.rs`) - Target: 90%
  - Token generation and validation
  - Refresh token handling
  - Token blacklisting
  - Security claims processing

- **Password Management** (`src/utils/password.rs`) - Target: 85%
  - Password hashing (bcrypt)
  - Password strength validation
  - Token generation
  - Security pattern detection

- **Rate Limiting** (`src/middleware/rate_limit.rs`) - Target: 85%
  - Rate limit enforcement
  - IP-based limiting
  - User-based limiting
  - Brute force protection

### Core Functionality Modules (70-80% coverage required)

- **User Models** (`src/models/user.rs`) - Target: 90%
  - User CRUD operations
  - Data validation
  - Serialization/deserialization
  - Role management

- **Database Layer** (`src/database/`) - Target: 75%
  - MongoDB adapter
  - PostgreSQL adapter
  - MySQL adapter
  - Connection pooling
  - Health checks

- **Cache Layer** (`src/cache/`) - Target: 70%
  - Redis cache implementation
  - Memory cache (LRU)
  - Multi-level caching
  - Cache invalidation strategies

- **Configuration Management** (`src/config/`) - Target: 75%
  - Configuration validation
  - Environment variable handling
  - YAML configuration parsing
  - Security checks

### Feature Modules (60-75% coverage required)

- **Multi-Factor Authentication** (`src/mfa/`) - Target: 80%
  - TOTP implementation
  - WebAuthn support
  - Backup codes
  - SMS verification

- **Email Services** (`src/email/`) - Target: 60%
  - Provider implementations
  - Template rendering
  - Error handling
  - Failover mechanisms

- **User Management** (`src/user_management/`) - Target: 60%
  - User profiles
  - Role-based access control
  - Group management
  - Permission systems

### Infrastructure Modules (50-65% coverage required)

- **Observability** (`src/observability/`) - Target: 50%
  - Metrics collection
  - Logging infrastructure
  - Tracing systems
  - Health monitoring

- **Migration System** (`src/migrations/`) - Target: 65%
  - Database migrations
  - Migration rollbacks
  - Migration validation
  - Cross-database compatibility

## Coverage Reporting

### Automated Reports

1. **HTML Reports** - Interactive coverage visualization
   - Generated in `coverage/tarpaulin-report.html`
   - Shows line-by-line coverage
   - Includes branch coverage information

2. **XML Reports** - CI/CD integration
   - Generated in `coverage/cobertura.xml`
   - Compatible with Codecov, Coveralls
   - Used for external reporting services

3. **JSON Reports** - Programmatic analysis
   - Generated in `coverage/tarpaulin-report.json`
   - Machine-readable coverage data
   - Used for trend analysis

### Manual Coverage Analysis

Use the coverage script for comprehensive analysis:

```bash
# Run complete coverage analysis
./scripts/coverage.sh

# Quick coverage check
cargo tarpaulin --lib --out Stdout

# Module-specific analysis
cargo tarpaulin --lib --packages rust-auth-service --out Html
```

## Coverage Validation

### CI/CD Integration

Coverage validation is integrated into the CI/CD pipeline:

1. **Pull Request Checks**
   - Runs on every PR
   - Enforces minimum 70% coverage
   - Comments coverage results on PR
   - Blocks merge if coverage is insufficient

2. **Push Validation**
   - Runs on main/develop branches
   - Updates coverage trends
   - Uploads to external services
   - Generates coverage badges

3. **Scheduled Analysis**
   - Daily coverage analysis at 2 AM UTC
   - Trend tracking and historical analysis
   - Coverage regression detection

### Pre-commit Hooks

Coverage validation in pre-commit workflow:

```bash
# Install pre-commit hooks
pre-commit install

# Run coverage check before commit
pre-commit run coverage-check
```

## Coverage Improvement Strategies

### 1. Test-Driven Development (TDD)

- Write tests before implementing features
- Ensure all code paths have corresponding tests
- Focus on edge cases and error scenarios

### 2. Integration Testing

- Comprehensive end-to-end test scenarios
- Multi-database testing
- Cross-service integration tests
- Performance regression tests

### 3. Property-Based Testing

- Use `proptest` for property-based testing
- Generate test cases automatically
- Test invariants and properties
- Discover edge cases

### 4. Mutation Testing

- Use `cargo-mutants` for mutation testing
- Verify test effectiveness
- Identify weak test coverage areas
- Improve test quality

## Coverage Analysis Tools

### Primary Tools

1. **cargo-tarpaulin** - Main coverage engine
   - LLVM-based coverage
   - HTML/XML/JSON output
   - CI/CD integration

2. **grcov** - Alternative coverage tool
   - Mozilla's coverage tool
   - LCOV output format
   - Source-based coverage

### Supporting Tools

1. **codecov** - External coverage service
   - Coverage visualization
   - PR integration
   - Historical tracking

2. **cargo-llvm-cov** - LLVM coverage
   - Native LLVM integration
   - Fast coverage generation
   - Multiple output formats

## Coverage Exclusions

### Excluded from Coverage

1. **Binary entry points** (`src/main.rs`, `src/bin/`)
2. **Test files** (`tests/`, `src/**/*test*.rs`)
3. **Generated code** (build artifacts)
4. **Example code** (`examples/`)

### Conditional Exclusions

```rust
// Exclude specific lines
#[cfg(not(tarpaulin_include))]
fn debug_only_function() {
    // This won't be included in coverage
}

// Exclude test-only code
#[cfg(test)]
mod tests {
    // Test code excluded from coverage
}
```

## Coverage Metrics

### Key Performance Indicators

1. **Line Coverage** - Primary metric
   - Percentage of executed lines
   - Target: 80% overall

2. **Branch Coverage** - Decision points
   - Percentage of executed branches
   - Important for conditional logic

3. **Function Coverage** - Function execution
   - Percentage of called functions
   - Ensures API coverage

4. **Module Coverage** - Module-level metrics
   - Per-module coverage tracking
   - Identifies coverage gaps

### Trend Analysis

- **Daily Snapshots** - Coverage trend tracking
- **Historical Comparison** - Month-over-month analysis
- **Regression Detection** - Coverage decrease alerts
- **Goal Progress** - Target achievement tracking

## Contributing Guidelines

### For New Features

1. **Implement with Tests**
   - Write tests alongside implementation
   - Aim for 85%+ coverage on new code
   - Include edge case testing

2. **Update Documentation**
   - Update coverage targets if needed
   - Document testing strategy
   - Update this document

### For Bug Fixes

1. **Reproduce with Tests**
   - Write failing test first
   - Fix the bug
   - Ensure test passes

2. **Regression Prevention**
   - Add comprehensive tests
   - Cover similar scenarios
   - Update test documentation

## Troubleshooting

### Common Issues

1. **Low Coverage Warning**
   ```bash
   # Check specific modules
   cargo tarpaulin --lib --out Stdout | grep "src/module"
   
   # Generate detailed HTML report
   cargo tarpaulin --lib --out Html --output-dir coverage
   ```

2. **CI Coverage Failures**
   ```bash
   # Local validation
   ./scripts/coverage.sh
   
   # Check threshold settings
   grep -r "fail-under" .
   ```

3. **Coverage Regression**
   - Check recent commits
   - Review deleted tests
   - Verify test execution
   - Update coverage targets

### Getting Help

- **GitHub Issues** - Report coverage-related bugs
- **Documentation** - Check project documentation
- **Team Discussion** - Internal team channels
- **External Resources** - Rust testing community

## Resources

### Documentation
- [cargo-tarpaulin Documentation](https://github.com/xd009642/tarpaulin)
- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Codecov Documentation](https://docs.codecov.io/)

### Tools
- [Coverage Script](../scripts/coverage.sh)
- [CI Configuration](../.github/workflows/coverage.yml)
- [Tarpaulin Config](../tarpaulin.toml)

### Badges

![Coverage](https://img.shields.io/codecov/c/github/fahdi/rust-auth-service?style=flat-square&logo=codecov)
![Tests](https://img.shields.io/github/actions/workflow/status/fahdi/rust-auth-service/coverage.yml?style=flat-square&logo=github&label=coverage)

---

*Last updated: $(date)*
*Coverage Target: 80% overall, 85%+ for security-critical modules*