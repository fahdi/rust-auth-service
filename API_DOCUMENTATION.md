# API Documentation

## 🚀 Interactive Swagger UI

The Rust Auth Service provides comprehensive interactive API documentation through Swagger UI.

### Access Documentation

**When the server is running:**
- **Interactive Swagger UI**: http://localhost:8080/docs
- **OpenAPI JSON Specification**: http://localhost:8080/api-docs/openapi.json

### Features

- **🔥 Real-time API Testing**: Test all endpoints directly from your browser
- **📋 Complete Schema Documentation**: All request/response models with validation rules
- **🔐 JWT Authentication Integration**: Built-in Bearer token authentication testing
- **📊 Professional Documentation**: Production-ready API reference with examples
- **🛠️ Client SDK Generation**: Download OpenAPI spec for automatic SDK generation

## 📊 API Overview

### Authentication Endpoints
- `POST /auth/register` - User registration with email verification
- `POST /auth/login` - JWT authentication with security analytics  
- `POST /auth/verify` - Email verification with token validation
- `POST /auth/forgot-password` - Password reset request
- `POST /auth/reset-password` - Password reset with token
- `POST /auth/refresh` - JWT token refresh with blacklist check
- `GET /auth/me` - Get authenticated user profile (requires auth)
- `PUT /auth/profile` - Update user profile information (requires auth)
- `POST /auth/logout` - User logout with token blacklisting (requires auth)

### System Endpoints
- `GET /health` - Comprehensive health check with database status
- `GET /ready` - Kubernetes readiness probe
- `GET /live` - Kubernetes liveness probe
- `GET /metrics` - Prometheus metrics endpoint
- `GET /stats` - System statistics in JSON format

### Documentation Endpoints
- `GET /docs` - Interactive Swagger UI
- `GET /api-docs/openapi.json` - OpenAPI 3.0.3 specification

## 🔐 Authentication

### JWT Bearer Token Authentication

Most endpoints require authentication using JWT Bearer tokens:

```bash
# Include the Authorization header with your requests
Authorization: Bearer YOUR_JWT_TOKEN
```

### Getting Started

1. **Register a new user** or **login** to get JWT tokens
2. **Copy the access_token** from the response
3. **Use the "Authorize" button** in Swagger UI to set your Bearer token
4. **Test protected endpoints** directly in the browser

## 📝 Data Models

All API data models are fully documented with:
- **Field descriptions and validation rules**
- **Required vs optional fields**
- **Data types and formats**
- **Example values**

### Core Models
- `CreateUserRequest` - User registration data
- `UpdateUserRequest` - User profile update data
- `AuthResponse` - Authentication response with tokens
- `UserResponse` - User profile information
- `LoginRequest` - Login credentials
- `RefreshTokenRequest` - Token refresh data

## 🧪 Testing the API

### Option 1: Swagger UI (Recommended)
1. Start the server: `cargo run`
2. Open: http://localhost:8080/docs
3. Click "Authorize" and enter your Bearer token
4. Test endpoints directly in the browser

### Option 2: Command Line (curl)
```bash
# Register a new user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe"
  }'

# Login to get tokens
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'

# Use protected endpoints
curl -X GET http://localhost:8080/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Option 3: Client SDK Generation

Download the OpenAPI specification and generate client SDKs:

```bash
# Download OpenAPI spec
curl http://localhost:8080/api-docs/openapi.json > openapi.json

# Generate client SDK (example with OpenAPI Generator)
openapi-generator generate -i openapi.json -g javascript -o ./client-sdk
```

## 🔧 Development

### Adding New Endpoints

When adding new API endpoints, ensure proper documentation:

1. **Add OpenAPI annotations** to handler functions:
```rust
#[utoipa::path(
    post,
    path = "/auth/new-endpoint",
    tag = "authentication"
)]
pub async fn new_endpoint() {
    // implementation
}
```

2. **Add ToSchema derives** to data models:
```rust
#[derive(Serialize, Deserialize, ToSchema)]
pub struct NewRequest {
    // fields
}
```

3. **Update OpenAPI configuration** in `main.rs`:
```rust
#[openapi(
    paths(
        // ... existing paths
        handlers::new_endpoint,
    ),
    // ...
)]
```

4. **Test documentation**:
```bash
cargo test --test openapi_tests
cargo run --bin generate_openapi
```

### Testing Documentation

The API documentation includes comprehensive automated testing:

```bash
# Run OpenAPI documentation tests
cargo test --test openapi_tests

# Generate OpenAPI specification for inspection
cargo run --bin generate_openapi
```

#### Test Coverage
- **8 comprehensive test cases** validating documentation accuracy
- **Schema validation** ensuring all models are properly documented  
- **Endpoint coverage** verification for all API routes
- **JSON serialization** testing for OpenAPI specification
- **Contact and license** metadata validation

## 📖 OpenAPI Specification

### Specification Details
- **Version**: OpenAPI 3.0.3
- **Format**: JSON
- **Security**: JWT Bearer token authentication
- **Contact**: Comprehensive contact and licensing information
- **Servers**: Development and production server configurations

### Client SDK Support
The OpenAPI specification enables automatic client SDK generation for:
- **JavaScript/TypeScript** (axios, fetch)
- **Python** (requests, httpx)
- **Java** (OkHttp, Retrofit)
- **C#** (.NET HttpClient)
- **Go** (net/http)
- **Swift** (URLSession)
- **And many more...**

## 🎯 Production Use

### Benefits for Integration
- **Reduced Integration Time**: Clear documentation and examples
- **Automatic Client Generation**: SDKs for multiple programming languages
- **Interactive Testing**: Developers can test APIs before integration
- **Professional Documentation**: Production-ready API reference
- **Standards Compliance**: OpenAPI 3.0.3 following industry best practices

### API Versioning
The API documentation supports versioning through:
- **Server configurations** for different environments
- **Version-specific OpenAPI specs** for backward compatibility
- **Clear migration guides** for API changes

For production deployments, ensure you:
1. **Configure proper server URLs** in the OpenAPI specification
2. **Set up authentication** with production JWT secrets
3. **Monitor API usage** through the metrics endpoints
4. **Keep documentation updated** with any API changes