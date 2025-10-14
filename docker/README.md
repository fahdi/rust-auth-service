# Docker Development Environment

This directory contains Docker-related files for the Rust Auth Service development environment.

## Quick Start

1. **Run the setup script:**
   ```bash
   ./scripts/setup-dev.sh
   ```

2. **Or manually start services:**
   ```bash
   # Copy example configs
   cp .env.example .env
   cp config.yml.example config.yml
   
   # Start all services
   docker-compose up --build -d
   
   # Check service status
   docker-compose ps
   ```

## Services

### Core Services
- **Auth Service**: `http://localhost:8080` - Main Rust authentication service
- **MongoDB**: `localhost:27018` - Database with admin panel
- **Redis**: `localhost:6380` - Caching layer
- **MailHog**: `http://localhost:8026` - Email testing UI

### Optional Admin Tools
```bash
# Start with admin tools
docker-compose --profile admin up -d

# Access admin interfaces
# MongoDB Express: http://localhost:8081 (admin/admin)
# Redis Insight: http://localhost:8082
```

## Health Checks

- **Service Health**: `http://localhost:8080/health`
- **Readiness**: `http://localhost:8080/ready` 
- **Liveness**: `http://localhost:8080/live`

## Development

### Hot Reload
The development container automatically reloads when code changes:
```bash
# Watch logs
docker-compose logs -f auth-service

# Manual restart
docker-compose restart auth-service
```

### Testing
```bash
# Run tests in container
docker-compose exec auth-service cargo test

# Shell access
docker-compose exec auth-service bash
```

### Database Access
```bash
# MongoDB shell
docker-compose exec mongodb mongosh -u admin -p password123

# Check collections
docker-compose exec mongodb mongosh -u admin -p password123 auth_service --eval "db.users.find().limit(5)"
```

## Troubleshooting

### Port Conflicts
If ports are in use, modify `docker-compose.yml`:
- Auth Service: Change `8080:8080` to `8081:8080`
- MongoDB: Change `27018:27017` to `27019:27017`
- Redis: Change `6380:6379` to `6381:6379`

### Container Issues
```bash
# Restart everything
docker-compose down && docker-compose up -d

# Clean rebuild
docker-compose down --volumes
docker-compose build --no-cache
docker-compose up -d
```

### Logs
```bash
# All services
docker-compose logs

# Specific service
docker-compose logs auth-service
docker-compose logs mongodb
docker-compose logs redis
```

## Production Deployment

Use the production Dockerfile for optimized builds:
```bash
# Build production image
docker build -t rust-auth-service:latest .

# Run production container
docker run -p 8080:8080 \
  -e DATABASE_URL="mongodb://user:pass@mongo:27017/auth" \
  -e JWT_SECRET="production-secret" \
  rust-auth-service:latest
```