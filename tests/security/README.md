# Security Integration Tests

This directory contains comprehensive security testing for the Rust Authentication Service, covering vulnerability scanning, attack simulation, and OWASP Top 10 validation.

## Security Test Categories

### Authentication Bypass Testing
- **Direct Access Attempts** - Unauthorized access to protected endpoints without tokens
- **Invalid Token Formats** - Malformed JWT tokens and invalid authentication headers
- **Expired Token Simulation** - Testing token expiration and validation
- **Token Manipulation** - Modified and crafted token attempts
- **Session Hijacking Prevention** - Unauthorized session access validation

### SQL/NoSQL Injection Testing
- **SQL Injection Payloads** - Classic SQL injection attempts across all database adapters
- **NoSQL Injection Payloads** - MongoDB-specific injection patterns
- **Login Endpoint Protection** - Authentication bypass via injection
- **Registration Endpoint Protection** - User creation via injection attempts
- **Query Parameter Injection** - URL parameter and form data injection

### Rate Limiting and DDoS Protection
- **Brute Force Protection** - Rapid login attempt simulation
- **Registration Flood Protection** - Mass user creation attempts
- **Request Rate Validation** - High-frequency request testing
- **IP-based Rate Limiting** - Per-IP request throttling
- **Sustained Attack Simulation** - Long-duration attack patterns

### Password Security Validation
- **Weak Password Rejection** - Common weak password patterns
- **Password Complexity Requirements** - Minimum security standards
- **Dictionary Attack Prevention** - Common password list validation
- **Password Strength Scoring** - Entropy and complexity analysis
- **Password Policy Enforcement** - Organizational security requirements

### Input Validation and Sanitization
- **XSS Payload Detection** - Cross-site scripting prevention
- **LDAP Injection Prevention** - Directory traversal attacks
- **Command Injection Protection** - Operating system command execution
- **Buffer Overflow Prevention** - Oversized input handling
- **Special Character Handling** - Unicode and encoding attacks

### Session Security and Token Management
- **Token-based Authentication** - JWT security validation
- **Session Invalidation** - Logout and token revocation
- **Concurrent Session Management** - Multiple session handling
- **Token Format Validation** - Malformed token detection
- **Session Timeout Enforcement** - Automatic session expiration

### Security Headers Validation
- **HTTP Security Headers** - Standard security header presence
- **CORS Policy Validation** - Cross-origin request security
- **Content Security Policy** - XSS and injection prevention
- **HTTPS Enforcement** - Transport layer security
- **Security Header Compliance** - Industry standard adherence

## Security Baselines and Thresholds

### Authentication Security Targets
| Security Area | Target | Critical Threshold |
|---------------|--------|-------------------|
| Authentication Bypass Prevention | 100% | 95% |
| Invalid Token Rejection | 100% | 98% |
| Unauthorized Access Prevention | 100% | 99% |
| Session Security | 95% | 90% |

### Injection Attack Prevention
| Attack Vector | Target | Critical Threshold |
|---------------|--------|-------------------|
| SQL Injection Prevention | 100% | 98% |
| NoSQL Injection Prevention | 100% | 98% |
| XSS Prevention | 95% | 90% |
| Command Injection Prevention | 100% | 99% |

### Rate Limiting Effectiveness
| Protection Type | Target | Critical Threshold |
|-----------------|--------|-------------------|
| Brute Force Protection | 90% | 80% |
| Registration Flood Protection | 85% | 75% |
| DDoS Mitigation | 95% | 90% |
| Per-IP Rate Limiting | 90% | 85% |

### Password Security Standards
| Security Requirement | Target | Critical Threshold |
|---------------------|--------|-------------------|
| Weak Password Rejection | 100% | 95% |
| Strong Password Acceptance | 95% | 90% |
| Password Policy Enforcement | 100% | 98% |
| Dictionary Attack Prevention | 100% | 95% |

### Overall Security Grading
| Grade | Pass Rate | Max Vulnerabilities | Security Level |
|-------|-----------|-------------------|----------------|
| A+ | ≥95% | 0 | Excellent |
| A | ≥90% | ≤1 | Very Good |
| B+ | ≥85% | ≤2 | Good |
| B | ≥80% | ≤3 | Acceptable |
| C+ | ≥75% | ≤5 | Needs Improvement |
| C | ≥70% | ≤7 | Poor |
| D | ≥60% | ≤10 | Very Poor |
| F | <60% | >10 | Critical Issues |

## Running Security Tests

### Prerequisites
Ensure the authentication service is running and all test databases are available:

```bash
# Start authentication service
cargo run --release &

# Verify service is running
curl http://localhost:8090/health

# Start test databases (if needed)
docker run -d --name mongo-test -p 27017:27017 mongo:latest
docker run -d --name postgres-test -p 5432:5432 -e POSTGRES_DB=auth_test -e POSTGRES_PASSWORD=test postgres:latest
docker run -d --name redis-test -p 6379:6379 redis:latest
```

### Individual Security Test Suites

```bash
# Authentication bypass testing
cargo test --test security_integration test_authentication_bypass_attempts -- --include-ignored

# SQL/NoSQL injection testing
cargo test --test security_integration test_sql_injection_attempts -- --include-ignored

# Rate limiting and DDoS protection
cargo test --test security_integration test_rate_limiting_protection -- --include-ignored

# Password security validation
cargo test --test security_integration test_password_security_validation -- --include-ignored

# Input validation and sanitization
cargo test --test security_integration test_input_validation_and_sanitization -- --include-ignored

# Session security and token management
cargo test --test security_integration test_session_security_and_token_management -- --include-ignored

# Security headers validation
cargo test --test security_integration test_security_headers_validation -- --include-ignored

# Comprehensive security audit
cargo test --test security_integration test_comprehensive_security_audit -- --include-ignored
```

### Complete Security Test Suite

```bash
# Run all security tests
cargo test --test security_integration -- --include-ignored

# Run with detailed output and logging
RUST_LOG=debug cargo test --test security_integration -- --include-ignored --nocapture

# Run security tests with performance monitoring
time cargo test --test security_integration -- --include-ignored
```

## Security Test Implementation Details

### Authentication Bypass Testing (`test_authentication_bypass_attempts`)
- **Direct Access**: 10 attempts to access protected endpoints without authentication
- **Invalid Tokens**: 7 different malformed token formats tested
- **Expired Tokens**: Token expiration validation
- **Metrics**: Response codes, rejection rates, vulnerability detection
- **Thresholds**: 100% unauthorized access rejection required

### SQL/NoSQL Injection Testing (`test_sql_injection_attempts`) 
- **SQL Payloads**: 10 classic SQL injection patterns
- **NoSQL Payloads**: 7 MongoDB-specific injection attempts
- **Endpoints**: Login and registration endpoint protection
- **Metrics**: Injection attempt rejection rate, successful bypass detection
- **Thresholds**: >90% injection rejection rate, 0 successful bypasses

### Rate Limiting Protection (`test_rate_limiting_protection`)
- **Brute Force**: 50 rapid login attempts simulation
- **Registration Flood**: 20 rapid registration attempts
- **Metrics**: Rate limiting activation, request throttling effectiveness
- **Thresholds**: Rate limiting must activate, >80% attack mitigation

### Password Security Validation (`test_password_security_validation`)
- **Weak Passwords**: 14 common weak password patterns
- **Strong Passwords**: 4 complex password acceptance tests
- **Metrics**: Weak password rejection rate, strong password acceptance
- **Thresholds**: >95% weak password rejection, >85% strong password acceptance

### Input Validation and Sanitization (`test_input_validation_and_sanitization`)
- **XSS Payloads**: 7 cross-site scripting attempts
- **LDAP Injection**: 4 directory traversal patterns
- **Command Injection**: 6 OS command execution attempts
- **Buffer Overflow**: Oversized input testing (10,000 characters)
- **Metrics**: Malicious input rejection rate, sanitization effectiveness
- **Thresholds**: >85% malicious input rejection, no successful attacks

### Session Security and Token Management (`test_session_security_and_token_management`)
- **Valid Token Access**: Authentication flow validation
- **Token Invalidation**: Post-logout token rejection
- **Concurrent Sessions**: Multiple session handling
- **Malformed Tokens**: 4 token manipulation attempts
- **Metrics**: Session security effectiveness, token validation accuracy
- **Thresholds**: >80% session security tests passed, no token vulnerabilities

### Security Headers Validation (`test_security_headers_validation`)
- **Security Headers**: 6 critical security headers checked across 4 endpoints
- **CORS Policy**: Cross-origin request policy validation
- **Metrics**: Security header presence, policy restrictiveness
- **Thresholds**: >60% security header compliance, restrictive CORS policy

### Comprehensive Security Audit (`test_comprehensive_security_audit`)
- **Complete Coverage**: All security test categories executed
- **Security Scoring**: Overall security grade calculation (A+ to F)
- **Vulnerability Count**: Total security issues identified
- **Pass Rate**: Percentage of security tests passed
- **Metrics**: Comprehensive security posture assessment
- **Thresholds**: >75% overall pass rate, ≤3 total vulnerabilities

## Security Attack Simulation

### Attack Vectors Tested

#### 1. Authentication Attacks
```
Direct Access:
- GET /auth/me (no token)
- PUT /auth/profile (no token)

Invalid Token Formats:
- Bearer invalid_token
- Bearer malformed.jwt.token
- Bearer null
- Bearer undefined
- Bearer (empty)

Token Manipulation:
- Modified signatures
- Truncated tokens
- Double-encoded tokens
- Structure modifications
```

#### 2. Injection Attacks
```
SQL Injection:
- '; DROP TABLE users; --
- ' OR '1'='1
- ' OR 1=1 --
- admin'--
- 1' UNION SELECT null, version(), null--

NoSQL Injection:
- '; return true; //
- ' || true || '
- '; db.users.drop(); //
- '; this.password.match(/.*/) //
```

#### 3. Cross-Site Scripting (XSS)
```
XSS Payloads:
- <script>alert('XSS')</script>
- javascript:alert('XSS')
- <img src=x onerror=alert('XSS')>
- <svg onload=alert('XSS')>
```

#### 4. Rate Limiting Bypass
```
Brute Force Simulation:
- 50 rapid login attempts
- Varying passwords per attempt
- Response time monitoring

Registration Flood:
- 20 rapid user registrations
- Unique email addresses
- Concurrent request timing
```

#### 5. Password Attacks
```
Dictionary Attacks:
- Common passwords (123456, password, admin)
- Weak patterns (abc123, qwerty)
- Short passwords (<8 characters)
- Empty passwords

Password Complexity:
- Strong password acceptance
- Special character requirements
- Minimum length enforcement
```

## Security Monitoring and Alerting

### Real-time Security Monitoring
Security tests should be integrated into continuous monitoring:

```yaml
# Example security monitoring alerts
- name: Authentication Bypass Detection
  condition: failed_auth_bypass_tests > 0
  severity: critical
  action: immediate_investigation

- name: Injection Attack Success
  condition: successful_injection_attacks > 0
  severity: critical
  action: immediate_patching

- name: Rate Limiting Failure
  condition: rate_limiting_effectiveness < 80%
  severity: high
  action: ddos_protection_review

- name: Password Security Degradation
  condition: weak_password_acceptance > 5%
  severity: medium
  action: password_policy_review
```

### Security Metrics Dashboard
Key security metrics to track:
- **Authentication Security**: Token validation success rate
- **Injection Prevention**: Attack rejection percentage
- **Rate Limiting**: Attack mitigation effectiveness
- **Password Security**: Policy enforcement compliance
- **Overall Security**: Aggregate security score and grade

### Incident Response Procedures
1. **Critical Vulnerabilities** (Grade F): Immediate service shutdown and patching
2. **High Risk Issues** (Grade D): Expedited security review and fixes
3. **Medium Risk Issues** (Grade C): Scheduled security improvements
4. **Low Risk Issues** (Grade B): Routine security maintenance
5. **Minimal Risk** (Grade A): Continue monitoring and best practices

## Security Best Practices Validation

### OWASP Top 10 Coverage
The security tests cover OWASP Top 10 vulnerabilities:

1. **A01: Broken Access Control** - Authentication bypass testing
2. **A02: Cryptographic Failures** - Token and session security
3. **A03: Injection** - SQL/NoSQL injection prevention
4. **A04: Insecure Design** - Overall security architecture
5. **A05: Security Misconfiguration** - Security headers validation
6. **A06: Vulnerable Components** - Dependency security (separate audit)
7. **A07: Authentication Failures** - Password and session security
8. **A08: Software Integrity** - Code and deployment security
9. **A09: Logging Failures** - Security event monitoring
10. **A10: Server-Side Request Forgery** - Input validation testing

### Security Compliance Standards
Tests align with security compliance requirements:
- **ISO 27001**: Information security management
- **SOC 2**: Security and availability controls
- **PCI DSS**: Payment card security (where applicable)
- **NIST Cybersecurity Framework**: Security control validation
- **CIS Controls**: Critical security control implementation

## Troubleshooting Security Tests

### Common Security Test Issues

#### High False Positive Rates
```
Issue: Security tests failing due to overly strict thresholds
Solution: Review and adjust security thresholds based on environment
Example: Reduce password complexity requirements for development
```

#### Authentication Service Unavailable
```
Issue: Security tests cannot connect to authentication service
Solution: Ensure service is running and accessible
Command: curl http://localhost:8090/health
```

#### Rate Limiting Too Aggressive
```
Issue: Legitimate security tests being rate limited
Solution: Adjust rate limiting configuration for testing
Config: Increase rate limits during test execution
```

#### Database Connection Failures
```
Issue: Security tests cannot access test databases
Solution: Verify database containers are running and accessible
Commands: docker ps | grep -E "(mongo|postgres|redis)"
```

### Security Test Debugging

Enable comprehensive security test logging:
```bash
# Debug security test execution
RUST_LOG=security_integration=debug,rust_auth_service=debug cargo test --test security_integration -- --include-ignored --nocapture

# Monitor security test network traffic
tcpdump -i lo0 -n port 8090

# Analyze security test performance
time cargo test --test security_integration -- --include-ignored

# Security test memory usage monitoring
/usr/bin/time -v cargo test --test security_integration -- --include-ignored
```

## Security Test Maintenance

### Regular Security Updates
- **Monthly**: Review and update security payloads
- **Quarterly**: Assess security threshold effectiveness
- **Annually**: Complete security test architecture review
- **On Vulnerability Disclosure**: Add specific test cases

### Security Test Evolution
- **New Attack Patterns**: Add emerging attack vector tests
- **Compliance Updates**: Align tests with new compliance requirements
- **Technology Changes**: Update tests for new authentication methods
- **Performance Optimization**: Improve security test execution speed

### Security Documentation Updates
- **Test Results**: Document security test outcomes and trends
- **Vulnerability Reports**: Maintain security issue tracking
- **Compliance Evidence**: Generate security compliance reports
- **Best Practices**: Update security implementation guidelines

This comprehensive security testing framework ensures the Rust Authentication Service maintains enterprise-grade security standards with continuous validation and monitoring.