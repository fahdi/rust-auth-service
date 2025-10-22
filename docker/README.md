# Docker Development Environment

Full-stack Docker Compose setup for Rust Auth Service with frontend examples, databases, and supporting services.

## Quick Start

```bash
# Navigate to docker directory
cd rust-auth-service/docker

# Set up development environment (one command setup)
chmod +x scripts/*.sh
./scripts/setup-dev.sh

# Access your application
open https://localhost
```

## Services Overview

| Service | URL | Description |
|---------|-----|-------------|
| **Main Application** | https://localhost | Next.js frontend application |
| **API** | https://localhost/api | Rust authentication service |
| **Vue.js Example** | https://localhost/vue | Vue.js integration example |
| **API Documentation** | https://localhost/docs | Swagger UI documentation |
| **Email Testing** | https://localhost/mail | MailHog email interface |
| **MongoDB Admin** | https://localhost/admin/mongo | MongoDB Express |
| **Redis Admin** | https://localhost/admin/redis | Redis Insight |

## Development Test Accounts

Use these pre-created accounts for testing:

- **admin@localhost** / Admin123!
- **test@localhost** / Test123!  
- **demo@localhost** / Demo123!

## Directory Structure

```
docker/
├── README.md                   # This documentation
├── docker-compose.yml          # Main orchestration
├── docker-compose.dev.yml      # Development overrides
├── docker-compose.prod.yml     # Production configuration
├── nginx/
│   ├── nginx.conf              # Nginx reverse proxy config
│   └── ssl/                    # SSL certificates directory
├── scripts/
│   ├── setup-dev.sh           # One-command development setup
│   ├── generate-ssl.sh        # SSL certificate generation
│   ├── seed-database.sh       # Development data seeding
│   └── health-check.sh        # Service health verification
├── env/
│   ├── .env.example           # Environment template
│   ├── .env.development       # Development settings
│   └── .env.production        # Production settings
└── auth-service/
    ├── Dockerfile.dev         # Development Dockerfile
    └── Dockerfile.prod        # Production Dockerfile
```

## Commands

### Development Commands
```bash
# Start development environment with hot reload
./scripts/setup-dev.sh

# View logs
docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs -f

# Restart a service
docker-compose -f docker-compose.yml -f docker-compose.dev.yml restart auth-service

# Stop environment
docker-compose -f docker-compose.yml -f docker-compose.dev.yml down

# Clean up everything
docker-compose -f docker-compose.yml -f docker-compose.dev.yml down -v
```

### Production Commands
```bash
# Start production environment
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Start with monitoring
docker-compose -f docker-compose.yml -f docker-compose.prod.yml --profile monitoring up -d
```

### Utility Commands
```bash
# Generate SSL certificates
./scripts/generate-ssl.sh

# Check service health
./scripts/health-check.sh

# Seed development database
./scripts/seed-database.sh
```

## Features

### Development Features
- ✅ **Hot Reload**: Code changes reflect immediately
- ✅ **SSL/HTTPS**: Local development with trusted certificates
- ✅ **Database Seeding**: Pre-populated test data
- ✅ **Email Testing**: MailHog for email debugging
- ✅ **Admin Interfaces**: MongoDB Express, Redis Insight
- ✅ **API Documentation**: Swagger UI integration

### Production Features
- ✅ **Multi-stage Builds**: Optimized Docker images
- ✅ **Security Hardening**: Non-root users, resource limits
- ✅ **Load Balancing**: Nginx reverse proxy
- ✅ **Monitoring**: Prometheus, Grafana, Loki
- ✅ **Health Checks**: Service monitoring
- ✅ **SSL Termination**: Production-ready HTTPS

## Environment Configuration

Copy and customize environment files:

```bash
# Development
cp env/.env.development env/.env

# Production (requires real secrets)
cp env/.env.production env/.env
```

### Key Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | JWT signing secret | `dev-secret-key` |
| `DATABASE_URL` | MongoDB connection | `mongodb://admin:password123@mongodb:27017/auth_service` |
| `REDIS_URL` | Redis connection | `redis://redis:6379` |
| `EMAIL_PROVIDER` | Email service | `smtp` |
| `RUST_LOG` | Logging level | `info` |

## Troubleshooting

### Service Health Check
```bash
./scripts/health-check.sh
```

### Common Issues

**Services won't start:**
```bash
# Check Docker status
docker info

# Check port conflicts
netstat -tulpn | grep :80
netstat -tulpn | grep :443
```

**SSL Certificate Issues:**
```bash
# Regenerate certificates
rm -rf nginx/ssl/*
./scripts/generate-ssl.sh
```

**Database Connection Issues:**
```bash
# Check MongoDB logs
docker-compose logs mongodb

# Reset database
docker-compose down -v
docker-compose up -d
```

## Security Notes

### Development
- Uses self-signed SSL certificates
- Default passwords for database services
- Relaxed CORS policies
- Debug logging enabled

### Production
- Requires valid SSL certificates
- Strong passwords and secrets required
- Strict security headers
- Rate limiting enabled

## Contributing

When modifying the Docker setup:

1. Test both development and production configurations
2. Update this README if adding new services  
3. Ensure security best practices for production
4. Test SSL certificate generation on different platforms
5. Verify health checks work correctly