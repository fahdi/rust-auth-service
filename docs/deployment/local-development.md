# Local Development Deployment Guide

This guide walks you through setting up the Rust Auth Service for local development using Docker Compose.

## 🎯 Overview

The local development environment provides:
- **One-command setup** with automated configuration
- **HTTPS support** with self-signed certificates
- **Hot reload** for rapid development
- **Complete service stack** including databases and admin tools
- **Pre-seeded data** for immediate testing

## 🔧 Prerequisites

### Required Software
- **Docker**: Version 20.0+ with Docker Compose
- **Git**: For cloning the repository
- **Web Browser**: For accessing admin dashboard and documentation

### System Requirements
- **CPU**: 2+ cores
- **Memory**: 4GB+ RAM
- **Storage**: 10GB+ free space
- **Network**: Internet connection for image downloads

### Verification Commands
```bash
# Check Docker installation
docker --version
docker-compose --version  # or docker compose version

# Check available resources
docker system df
```

## 🚀 Quick Start (2 Minutes)

### 1. Clone Repository
```bash
git clone https://github.com/fahdi/rust-auth-service.git
cd rust-auth-service/docker
```

### 2. One-Command Setup
```bash
# Make scripts executable and run setup
chmod +x scripts/*.sh
./scripts/setup-dev.sh
```

### 3. Verify Services
```bash
# Check service health
./scripts/health-check.sh

# View running services
docker-compose -f docker-compose.yml -f docker-compose.dev.yml ps
```

### 4. Access Services
- **Main Application**: https://localhost
- **API Documentation**: https://localhost/docs
- **Admin Dashboard**: https://localhost/admin
- **Email Testing**: https://localhost/mail

## 📋 Detailed Setup Instructions

### Step 1: Environment Configuration

#### Default Configuration
The setup script automatically creates development environment files:

```bash
# View environment settings
cat env/.env.development
```

#### Custom Configuration (Optional)
```bash
# Copy and customize environment
cp env/.env.development env/.env.local
nano env/.env.local

# Use custom environment
export COMPOSE_FILE="docker-compose.yml:docker-compose.dev.yml"
export ENV_FILE="env/.env.local"
```

#### Key Environment Variables
```bash
# Database Configuration
DATABASE_URL=mongodb://admin:password123@mongodb:27017/auth_service?authSource=admin
REDIS_URL=redis://redis:6379

# JWT Configuration (Development Only)
JWT_SECRET=dev-secret-key-change-in-production
JWT_EXPIRATION=3600

# Email Configuration
EMAIL_PROVIDER=smtp
SMTP_HOST=mailhog
SMTP_PORT=1025

# Logging
RUST_LOG=debug
RUST_BACKTRACE=1
```

### Step 2: SSL Certificate Generation

#### Automatic Certificate Creation
```bash
# Generate self-signed certificates
./scripts/generate-ssl.sh

# Verify certificates
ls -la nginx/ssl/
```

#### Manual Certificate Generation (If Needed)
```bash
# Create SSL directory
mkdir -p nginx/ssl

# Generate private key
openssl genrsa -out nginx/ssl/localhost.key 2048

# Generate certificate signing request
openssl req -new -key nginx/ssl/localhost.key -out nginx/ssl/localhost.csr \
  -subj "/C=US/ST=Dev/L=Development/O=AuthService/OU=IT/CN=localhost"

# Create certificate extensions
cat > nginx/ssl/localhost.ext << EOF
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# Generate self-signed certificate
openssl x509 -req -in nginx/ssl/localhost.csr \
  -signkey nginx/ssl/localhost.key \
  -out nginx/ssl/localhost.crt \
  -days 365 \
  -extensions v3_req \
  -extfile nginx/ssl/localhost.ext
```

#### Trust Certificate (Optional)
```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain nginx/ssl/localhost.crt

# Linux (Ubuntu/Debian)
sudo cp nginx/ssl/localhost.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Windows (Run as Administrator)
certlm.msc # Import certificate to Trusted Root Certification Authorities
```

### Step 3: Service Startup

#### Start All Services
```bash
# Start in background
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Start with logs (foreground)
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
```

#### Start Individual Services
```bash
# Start only essential services
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d nginx mongodb redis auth-service

# Start with frontend examples
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d nextjs-app vue-app
```

### Step 4: Database Seeding

#### Automatic Seeding
```bash
# Seed with test data
./scripts/seed-database.sh
```

#### Manual Database Setup
```bash
# Run migrations
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec auth-service cargo run --bin migrate up

# Create admin user manually
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec auth-service curl -X POST http://localhost:8090/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@localhost",
    "password": "Admin123!",
    "first_name": "Admin",
    "last_name": "User"
  }'
```

## 🌐 Service Access

### Main Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **Main App** | https://localhost | - |
| **API Base** | https://localhost/api | JWT Token |
| **API Docs** | https://localhost/docs | - |
| **Admin Dashboard** | https://localhost/admin | admin@localhost / Admin123! |

### Development Tools

| Service | URL | Credentials |
|---------|-----|-------------|
| **MailHog** | https://localhost/mail | - |
| **MongoDB Express** | https://localhost/admin/mongo | admin / password123 |
| **Redis Insight** | https://localhost/admin/redis | - |

### Frontend Examples

| Service | URL | Description |
|---------|-----|-------------|
| **Next.js App** | https://localhost | TypeScript integration example |
| **Vue.js App** | https://localhost/vue | Vue.js integration example |

### Test Accounts

Pre-created accounts for testing:

```bash
# Admin Account
Email: admin@localhost
Password: Admin123!
Role: admin

# Test User
Email: test@localhost
Password: Test123!
Role: user

# Demo User
Email: demo@localhost
Password: Demo123!
Role: user
```

## 🔧 Development Workflow

### Hot Reload Development

#### Rust Service Development
```bash
# View real-time logs
docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs -f auth-service

# The service automatically reloads on code changes
# Edit files in src/ and see changes applied immediately
```

#### Frontend Development
```bash
# Next.js development
cd examples/nextjs-integration
npm run dev

# Vue.js development  
cd examples/vue-integration
npm run serve
```

### Testing Changes

#### API Testing
```bash
# Test authentication flow
curl -k -X POST https://localhost/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@localhost",
    "password": "SecurePass123!",
    "first_name": "New",
    "last_name": "User"
  }'

# Test with admin credentials
curl -k -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@localhost",
    "password": "Admin123!"
  }'
```

#### Database Testing
```bash
# Connect to MongoDB
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec mongodb mongosh auth_service_dev

# Connect to Redis
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec redis redis-cli
```

### Performance Testing

#### Load Testing
```bash
# Install artillery (if not installed)
npm install -g artillery

# Run load test
artillery quick --count 10 --num 100 https://localhost/api/health
```

#### Resource Monitoring
```bash
# Monitor resource usage
docker stats

# Monitor service health
watch -n 5 './scripts/health-check.sh'
```

## 🛠️ Management Commands

### Service Management

#### View Service Status
```bash
# Show all services
docker-compose -f docker-compose.yml -f docker-compose.dev.yml ps

# Show only running services
docker-compose -f docker-compose.yml -f docker-compose.dev.yml ps --services --filter "status=running"
```

#### Restart Services
```bash
# Restart specific service
docker-compose -f docker-compose.yml -f docker-compose.dev.yml restart auth-service

# Restart all services
docker-compose -f docker-compose.yml -f docker-compose.dev.yml restart
```

#### View Logs
```bash
# View all logs
docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs

# Follow specific service logs
docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs -f auth-service

# View last 100 lines
docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs --tail=100
```

#### Stop Services
```bash
# Stop all services
docker-compose -f docker-compose.yml -f docker-compose.dev.yml down

# Stop and remove volumes (clean slate)
docker-compose -f docker-compose.yml -f docker-compose.dev.yml down -v

# Stop specific service
docker-compose -f docker-compose.yml -f docker-compose.dev.yml stop auth-service
```

### Database Management

#### Backup Database
```bash
# Create backup
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec mongodb mongodump --db auth_service_dev --out /backup

# Copy backup to host
docker cp $(docker-compose -f docker-compose.yml -f docker-compose.dev.yml ps -q mongodb):/backup ./backup
```

#### Restore Database
```bash
# Restore from backup
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec mongodb mongorestore --db auth_service_dev /backup/auth_service_dev
```

#### Reset Database
```bash
# Stop services and remove volumes
docker-compose -f docker-compose.yml -f docker-compose.dev.yml down -v

# Start services (fresh database)
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Re-seed with test data
./scripts/seed-database.sh
```

## 🐛 Troubleshooting

### Common Issues

#### 1. Port Conflicts
```bash
# Check what's using ports
lsof -i :80,443,27017,6379,8025,8090

# Kill processes using required ports
sudo lsof -ti:80 | xargs kill -9
```

#### 2. SSL Certificate Issues
```bash
# Remove and regenerate certificates
rm -rf nginx/ssl/*
./scripts/generate-ssl.sh

# Restart nginx
docker-compose -f docker-compose.yml -f docker-compose.dev.yml restart nginx
```

#### 3. Database Connection Issues
```bash
# Check MongoDB status
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec mongodb mongosh --eval "db.adminCommand('ping')"

# Check Redis status
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec redis redis-cli ping
```

#### 4. Service Won't Start
```bash
# Check service logs
docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs auth-service

# Check Docker resources
docker system df
docker system prune # Clean up if needed
```

#### 5. Hot Reload Not Working
```bash
# Verify volume mounts
docker-compose -f docker-compose.yml -f docker-compose.dev.yml config | grep -A 5 volumes

# Restart auth service
docker-compose -f docker-compose.yml -f docker-compose.dev.yml restart auth-service
```

### Performance Issues

#### 1. Slow Response Times
```bash
# Check resource usage
docker stats

# Monitor service health
./scripts/health-check.sh

# Check database performance
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec mongodb mongosh --eval "db.runCommand({serverStatus: 1})"
```

#### 2. Memory Issues
```bash
# Increase Docker memory limit (Docker Desktop)
# Docker Desktop -> Settings -> Resources -> Memory

# Monitor memory usage
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

### Network Issues

#### 1. Cannot Access Services
```bash
# Check Docker networks
docker network ls
docker network inspect rust-auth-service_default

# Verify container connectivity
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec auth-service ping nginx
```

#### 2. DNS Resolution Issues
```bash
# Check /etc/hosts (if using custom domains)
cat /etc/hosts

# Test DNS resolution
nslookup localhost
```

## 📊 Monitoring and Debugging

### Health Monitoring
```bash
# Comprehensive health check
./scripts/health-check.sh

# Individual service health
curl -k https://localhost/api/health
curl -k https://localhost/api/ready
curl -k https://localhost/api/live
```

### Metrics Access
```bash
# Prometheus metrics
curl -k https://localhost/api/metrics

# Service statistics
curl -k https://localhost/api/stats
```

### Debug Logging
```bash
# Enable debug logging
echo "RUST_LOG=debug" >> env/.env.development

# Restart services
docker-compose -f docker-compose.yml -f docker-compose.dev.yml restart

# View debug logs
docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs -f auth-service
```

## 🚀 Next Steps

### Development Ready Checklist
- [ ] All services running and healthy
- [ ] SSL certificates generated and trusted
- [ ] Database seeded with test accounts
- [ ] Admin dashboard accessible
- [ ] API documentation available
- [ ] Hot reload working for code changes

### Moving to Production
1. **Review [Production Best Practices](./production-best-practices.md)**
2. **Set up [Kubernetes Deployment](./kubernetes.md)**
3. **Configure [Cloud Deployment](./aws.md) or [GCP](./gcp.md)**
4. **Implement proper secret management**
5. **Set up monitoring and alerting**

### Integration Development
1. **Use [API Documentation](../api/README.md)** for integration
2. **Check [Integration Examples](../api/INTEGRATION_GUIDE.md)**
3. **Test with provided client libraries**
4. **Implement error handling and retry logic**

Happy coding with the Rust Auth Service! 🦀⚡