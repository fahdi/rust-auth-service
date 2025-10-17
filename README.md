# Rust Auth Service

A high-performance authentication microservice built with Rust and Axum.

## What Works

### API Endpoints
- **POST /auth/register** - User registration with JWT tokens
- **POST /auth/login** - User authentication  
- **POST /auth/verify** - Email verification
- **POST /auth/forgot-password** - Password reset request
- **POST /auth/reset-password** - Password reset with token
- **POST /auth/refresh** - JWT token refresh
- **GET /auth/me** - User profile (authenticated)
- **PUT /auth/profile** - Update profile (authenticated)
- **POST /auth/logout** - User logout (authenticated)

### System Endpoints
- **GET /health** - Health check
- **GET /ready** - Readiness check
- **GET /live** - Liveness check
- **GET /metrics** - Prometheus metrics
- **GET /docs** - Swagger UI documentation

### Database Support
- MongoDB (primary, working)
- PostgreSQL (basic support)
- MySQL (basic support)

### Caching
- Redis caching
- In-memory LRU fallback

## Quick Start

```bash
# Build
cargo build --lib

# Run
cargo run

# Test
cargo test --lib
```

## Configuration

Set `DATABASE_URL` and `JWT_SECRET` environment variables, or use `config.yml`.

## API Documentation

Visit `/docs` when running for interactive Swagger UI.

## Current Limitations

This is a working foundation. Many advanced features are planned but not yet implemented. See the issues for the roadmap.