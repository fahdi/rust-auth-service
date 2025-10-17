# Docker Configuration

This directory contains all Docker-related configuration files for the Rust Auth Service project.

## Directory Structure

```
docker/
├── README.md                    # This file
├── auth-service/               # Main auth service Docker config
│   └── Dockerfile             # Production Dockerfile for auth service
├── nextjs-integration/         # Next.js example Docker config  
│   ├── Dockerfile             # Next.js application Dockerfile
│   └── docker-compose.yml     # Next.js + Auth service compose
└── compose/                   # Docker Compose configurations
    ├── docker-compose.yml     # Main production compose
    └── docker-compose.dev.yml # Development environment compose
```

## Quick Start

### Development Environment
```bash
# Run full development stack
docker-compose -f docker/compose/docker-compose.dev.yml up

# Run with monitoring
docker-compose -f docker/compose/docker-compose.dev.yml -f monitoring/docker-compose.monitoring.yml up
```

### Production Environment
```bash
# Run production stack
docker-compose -f docker/compose/docker-compose.yml up
```

### Next.js Integration Example
```bash
# Run Next.js example with auth service
cd docker/nextjs-integration
docker-compose up
```

## Configuration Files

### Auth Service Dockerfile
- **Location**: `docker/auth-service/Dockerfile`
- **Purpose**: Multi-stage build for the Rust auth service
- **Features**: Optimized production image with minimal dependencies

### Docker Compose Files

#### Development (`docker-compose.dev.yml`)
- Auth service with debug logging
- PostgreSQL database
- Redis cache
- Volume mounts for development

#### Production (`docker-compose.yml`)
- Optimized auth service build
- Production database configuration
- Health checks and restart policies

#### Next.js Integration (`nextjs-integration/docker-compose.yml`)
- Complete full-stack setup
- Auth service + Next.js frontend
- Shared database and cache services

## Environment Variables

Each compose file supports environment variable overrides:
- `DATABASE_URL` - Database connection string
- `JWT_SECRET` - JWT signing secret
- `REDIS_URL` - Redis cache connection
- `RUST_LOG` - Logging level for development

## Build Commands

### Build Auth Service Image
```bash
docker build -f docker/auth-service/Dockerfile -t rust-auth-service .
```

### Build Next.js Integration
```bash
docker build -f docker/nextjs-integration/Dockerfile -t nextjs-auth-example ./examples/nextjs-integration
```

## Networking

All services use the `auth-network` bridge network for internal communication:
- Auth service: `http://auth-service:8080`
- Database: `postgresql://postgres:5432/auth_db`
- Redis: `redis://redis:6379`
- Next.js: `http://nextjs-app:3000`

## Volumes

### Development Volumes
- Source code mounted for hot reload
- Database data persistence
- Redis data persistence

### Production Volumes
- Database data only
- Log file persistence
- SSL certificate storage (if configured)

## Health Checks

All services include health checks:
- Auth service: `GET /health`
- Database: PostgreSQL connection check
- Redis: PING command
- Next.js: Next.js health endpoint

## Monitoring

Monitoring stack is available separately in the `monitoring/` directory:
```bash
# Start monitoring with auth service
docker-compose -f docker/compose/docker-compose.dev.yml -f monitoring/docker-compose.monitoring.yml up
```

Includes:
- Prometheus metrics collection
- Grafana dashboards  
- Alertmanager notifications
- Loki log aggregation

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Ensure ports 3000, 5432, 6379, 8080 are available
2. **Permission Issues**: Check Docker daemon permissions
3. **Build Failures**: Verify Rust toolchain in development environment
4. **Network Issues**: Ensure Docker networks are properly configured

### Debug Commands
```bash
# Check service logs
docker-compose -f docker/compose/docker-compose.dev.yml logs auth-service

# Inspect running containers
docker-compose -f docker/compose/docker-compose.dev.yml ps

# Execute commands in running container
docker-compose -f docker/compose/docker-compose.dev.yml exec auth-service /bin/sh
```