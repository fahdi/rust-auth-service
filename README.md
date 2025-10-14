# Rust Auth Service

A high-performance authentication microservice built with Rust and Axum.

## Current Status

This project is in early development. The basic project structure and configuration system are implemented.

## What Works

- ✅ Basic Axum web server setup
- ✅ Configuration system with YAML + environment variable support
- ✅ Project structure for modular architecture
- ✅ Database configuration for MongoDB, PostgreSQL, MySQL
- ✅ Cache configuration for Redis and in-memory LRU
- ✅ Email provider configuration framework
- ✅ Basic dependency setup in Cargo.toml

## What's Not Implemented Yet

- Authentication handlers and JWT logic
- Database adapters and operations
- Caching layer
- Email service integrations
- Rate limiting and security middleware
- Comprehensive testing

## Development

### Prerequisites

- Rust 1.70+
- MongoDB, PostgreSQL, or MySQL (depending on your choice)
- Redis (optional, for caching)

### Running

```bash
# Clone the repository
git clone https://github.com/fahdi/rust-auth-service.git
cd rust-auth-service

# Build and run
cargo run
```

The server will start on `localhost:8080` by default.

### Configuration

Copy `config.example.yml` to `config.yml` and modify as needed, or use environment variables:

- `DATABASE_URL` - Database connection string
- `JWT_SECRET` - JWT signing secret
- `REDIS_URL` - Redis connection string (optional)

## Architecture

The service uses a trait-based architecture allowing runtime selection of:
- Database providers (MongoDB, PostgreSQL, MySQL)
- Cache providers (Redis, in-memory LRU)
- Email providers (Brevo, SendGrid, SMTP)

## License

MIT