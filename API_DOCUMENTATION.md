# API Documentation

## 🔒 Ultra-Secure Authentication API

**Security Notice**: This documentation is for our ultra-secure, zero-vulnerability MongoDB-only build. OpenAPI/Swagger UI was removed due to security vulnerabilities in dependencies.

## 📊 API Overview

### Core Authentication Endpoints

#### User Registration
```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response (201 Created):**
```json
{
  "user": {
    "user_id": "user_12345",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user",
    "is_active": true,
    "email_verified": false,
    "created_at": "2025-01-17T10:30:00Z"
  },
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_in": 604800
}
```

#### User Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response (200 OK):**
```json
{
  "user": {
    "user_id": "user_12345",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user",
    "is_active": true,
    "email_verified": true,
    "last_login": "2025-01-17T10:30:00Z"
  },
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_in": 604800
}
```

#### Email Verification
```http
POST /auth/verify
Content-Type: application/json

{
  "token": "verification_token_here"
}
```

#### Password Reset Request
```http
POST /auth/forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Password Reset
```http
POST /auth/reset-password
Content-Type: application/json

{
  "token": "reset_token_here",
  "new_password": "NewSecurePassword123!"
}
```

#### Token Refresh
```http
POST /auth/refresh
Content-Type: application/json
Authorization: Bearer <refresh_token>

{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### Protected Endpoints (Require Authentication)

#### Get User Profile
```http
GET /auth/me
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "user_id": "user_12345",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "role": "user",
  "is_active": true,
  "email_verified": true,
  "last_login": "2025-01-17T10:30:00Z",
  "created_at": "2025-01-17T09:00:00Z",
  "updated_at": "2025-01-17T10:30:00Z"
}
```

#### Update User Profile
```http
PUT /auth/profile
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "first_name": "Johnny",
  "last_name": "Smith"
}
```

#### Logout
```http
POST /auth/logout
Authorization: Bearer <access_token>
```

### System & Monitoring Endpoints

#### Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "environment": "production",
  "database": {
    "status": "connected",
    "type": "mongodb",
    "response_time_ms": 12
  },
  "cache": {
    "status": "connected",
    "type": "redis",
    "response_time_ms": 3
  },
  "timestamp": "2025-01-17T10:30:00Z",
  "uptime_seconds": 86400
}
```

#### Readiness Probe
```http
GET /ready
```

#### Liveness Probe  
```http
GET /live
```

#### Prometheus Metrics
```http
GET /metrics
```

#### System Statistics
```http
GET /stats
```

**Response:**
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "version": "0.1.0"
  },
  "database": {
    "type": "mongodb",
    "status": "connected"
  },
  "cache": {
    "type": "redis",
    "status": "connected"
  },
  "security": {
    "vulnerabilities": 0,
    "build_type": "ultra-secure"
  },
  "performance": {
    "avg_response_time_ms": 45,
    "requests_per_second": 1200
  }
}
```

## 🔐 Authentication

### JWT Bearer Token Authentication

Protected endpoints require authentication via JWT Bearer tokens:

```http
Authorization: Bearer <access_token>
```

### Token Structure

**Access Token Claims:**
```json
{
  "sub": "user_12345",
  "email": "user@example.com", 
  "role": "user",
  "exp": 1737201000,
  "iat": 1737114600,
  "jti": "token_uuid",
  "token_type": "access"
}
```

**Refresh Token Claims:**
```json
{
  "sub": "user_12345",
  "email": "user@example.com",
  "role": "user", 
  "exp": 1739792600,
  "iat": 1737114600,
  "jti": "refresh_uuid",
  "token_type": "refresh"
}
```

### Security Features

- **Token Blacklisting**: Logout immediately invalidates tokens
- **Configurable Expiration**: Default 7 days for access tokens
- **Secure Claims**: All tokens include user context and type validation
- **Rate Limiting**: Prevents brute force attacks
- **bcrypt Hashing**: Secure password storage with configurable rounds

## 📋 Request/Response Models

### User Registration Request
```json
{
  "email": "string (email format, required)",
  "password": "string (min 8 chars, required)",
  "first_name": "string (2-50 chars, required)",
  "last_name": "string (2-50 chars, required)",
  "role": "string (optional, default: user)",
  "metadata": "object (optional)"
}
```

### User Update Request
```json
{
  "email": "string (email format, optional)",
  "first_name": "string (2-50 chars, optional)",
  "last_name": "string (2-50 chars, optional)",
  "role": "string (optional)",
  "is_active": "boolean (optional)",
  "metadata": "object (optional)"
}
```

### Authentication Response
```json
{
  "user": "UserResponse object",
  "access_token": "string (JWT)",
  "refresh_token": "string (JWT)",
  "expires_in": "number (seconds)"
}
```

## ⚠️ Error Responses

### Standard Error Format
```json
{
  "error": "error_code",
  "message": "Human readable error message",
  "details": "Additional error context (optional)"
}
```

### Common HTTP Status Codes

- **200 OK**: Successful request
- **201 Created**: Resource created successfully
- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Missing or invalid authentication
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource already exists
- **422 Unprocessable Entity**: Validation failed
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error
- **503 Service Unavailable**: Database/cache unavailable

## 🧪 Testing Examples

### Using curl

#### Register a new user
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePassword123!",
    "first_name": "Test",
    "last_name": "User"
  }'
```

#### Login
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com", 
    "password": "SecurePassword123!"
  }'
```

#### Access protected endpoint
```bash
curl -X GET http://localhost:8080/auth/me \
  -H "Authorization: Bearer <your_access_token>"
```

#### Check health
```bash
curl http://localhost:8080/health
```

### Using httpie

#### Register
```bash
http POST :8080/auth/register \
  email=test@example.com \
  password=SecurePassword123! \
  first_name=Test \
  last_name=User
```

#### Login
```bash
http POST :8080/auth/login \
  email=test@example.com \
  password=SecurePassword123!
```

## 🔒 Security Considerations

### Environment Setup
```bash
# Required environment variables
export DATABASE_URL="mongodb://localhost:27017/auth"
export JWT_SECRET="your-256-bit-secret-key"

# Optional security settings
export BCRYPT_ROUNDS=12
export RATE_LIMIT_REQUESTS=100
export RATE_LIMIT_WINDOW=60
```

### Production Security
- **Use strong JWT secrets** (256-bit minimum)
- **Enable HTTPS** in production
- **Configure rate limiting** appropriately
- **Use secure MongoDB connection strings**
- **Monitor security metrics** via Prometheus
- **Regular security audits** with `cargo audit`

## 📊 Monitoring

### Prometheus Metrics Available
- Authentication request rates
- Response time histograms  
- Error rate counters
- Database connection status
- Cache hit/miss ratios
- Security event counters

### Health Check Integration
- **Kubernetes**: Use `/ready` and `/live` endpoints
- **Load Balancers**: Use `/health` for backend health
- **Monitoring**: Use `/metrics` for Prometheus scraping

---

**🔒 Built for uncompromising security with zero vulnerabilities.**