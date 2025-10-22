# 🚀 Getting Started with Rust Auth Service

Welcome to the Rust Auth Service! This guide will help you get up and running quickly, whether you're setting up for development, testing, or production deployment.

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows
- **Memory**: 4GB RAM minimum (8GB recommended)
- **Storage**: 10GB free space
- **Network**: Internet connection for dependencies

### Required Software
- **Rust**: Version 1.70 or higher
- **Docker**: Version 20.0+ with Docker Compose
- **Git**: For cloning the repository

### Database (Choose One)
- **MongoDB**: 4.4+ (recommended for performance)
- **PostgreSQL**: 12+ (for SQL compatibility)
- **MySQL**: 8.0+ (for existing MySQL infrastructure)

### Optional Components
- **Redis**: 6.0+ (for distributed caching)
- **Nginx**: (for reverse proxy and SSL termination)

## 🎯 Quick Start Options

Choose the setup method that best fits your needs:

### Option 1: 🐳 Docker Compose (Recommended for Beginners)
**Perfect for:** Local development, testing, quick demos

### Option 2: 🦀 Local Rust Development
**Perfect for:** Rust developers, custom configurations, performance testing

### Option 3: ☸️ Kubernetes Deployment
**Perfect for:** Production deployments, scalable infrastructure

---

## 🐳 Option 1: Docker Compose Setup (5 Minutes)

This is the fastest way to get started with a complete development environment.

### 1. Clone the Repository
```bash
git clone https://github.com/fahdi/rust-auth-service.git
cd rust-auth-service
```

### 2. One-Command Setup
```bash
cd docker
chmod +x scripts/*.sh
./scripts/setup-dev.sh
```

This script will:
- ✅ Generate SSL certificates for HTTPS
- ✅ Start MongoDB database
- ✅ Start Redis cache
- ✅ Build and start the auth service
- ✅ Set up Nginx reverse proxy
- ✅ Configure MailHog for email testing
- ✅ Seed the database with test users

### 3. Verify Everything is Working
```bash
# Check service health
./scripts/health-check.sh

# View running services
docker-compose -f docker-compose.yml -f docker-compose.dev.yml ps
```

### 4. Access Your Services
Open your browser and visit:

| Service | URL | Purpose |
|---------|-----|---------|
| **Main API** | https://localhost/api | Authentication endpoints |
| **API Docs** | https://localhost/docs | Interactive API documentation |
| **Admin Dashboard** | https://localhost/admin | User management interface |
| **Email Testing** | https://localhost/mail | MailHog email interface |

### 5. Test Authentication
```bash
# Register a new user
curl -k -X POST https://localhost/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "first_name": "Test",
    "last_name": "User"
  }'

# Login with the user
curl -k -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
```

### Pre-configured Test Accounts
| Email | Password | Role |
|-------|----------|------|
| admin@localhost | Admin123! | admin |
| test@localhost | Test123! | user |
| demo@localhost | Demo123! | user |

---

## 🦀 Option 2: Local Rust Development

For developers who want to run the service directly with Rust.

### 1. Install Rust and Dependencies
```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version
```

### 2. Clone and Build
```bash
git clone https://github.com/fahdi/rust-auth-service.git
cd rust-auth-service

# Build the project
cargo build --release
```

### 3. Set Up Database

#### MongoDB (Recommended)
```bash
# Install MongoDB
# Ubuntu/Debian:
sudo apt-get install mongodb

# macOS:
brew install mongodb/brew/mongodb-community

# Start MongoDB
sudo systemctl start mongod  # Linux
brew services start mongodb-community  # macOS

# Create database
mongosh
use auth_service
db.createUser({
  user: "auth_user",
  pwd: "secure_password",
  roles: ["readWrite"]
})
```

#### PostgreSQL (Alternative)
```bash
# Install PostgreSQL
# Ubuntu/Debian:
sudo apt-get install postgresql postgresql-contrib

# macOS:
brew install postgresql

# Start PostgreSQL
sudo systemctl start postgresql  # Linux
brew services start postgresql   # macOS

# Create database and user
sudo -u postgres psql
CREATE DATABASE auth_service;
CREATE USER auth_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE auth_service TO auth_user;
```

### 4. Configure Environment
```bash
# Copy example configuration
cp config.yml.example config.yml

# Set environment variables
export DATABASE_URL="mongodb://auth_user:secure_password@localhost:27017/auth_service"
# OR for PostgreSQL:
# export DATABASE_URL="postgresql://auth_user:secure_password@localhost:5432/auth_service"

export JWT_SECRET="your-super-secure-jwt-secret-key-must-be-256-bits-long"
export REDIS_URL="redis://localhost:6379"
```

### 5. Run Database Migrations
```bash
# For MongoDB
cargo run --bin migrate -- --database mongodb up

# For PostgreSQL
cargo run --bin migrate -- --database postgresql up
```

### 6. Start the Service
```bash
# Development mode with debug logging
RUST_LOG=debug cargo run

# Production mode
cargo run --release
```

### 7. Verify Installation
```bash
# Health check
curl http://localhost:8090/health

# API documentation
open http://localhost:8090/docs
```

---

## ☸️ Option 3: Kubernetes Deployment

For production-ready deployments with scalability and high availability.

### 1. Prerequisites
```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Verify you have a Kubernetes cluster
kubectl cluster-info
```

### 2. Create Namespace
```bash
kubectl create namespace auth-service
```

### 3. Deploy with Helm (Recommended)
```bash
# Add secrets
kubectl create secret generic auth-secrets \
  --from-literal=jwt-secret=your-jwt-secret \
  --from-literal=database-url=mongodb://user:pass@mongo:27017/auth \
  -n auth-service

# Install with Helm
helm install auth-service ./helm/auth-service \
  --namespace auth-service \
  --set image.tag=latest \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=auth.yourdomain.com
```

### 4. Deploy with Kubectl (Alternative)
```bash
# Apply all manifests
kubectl apply -f k8s/ -n auth-service

# Check deployment status
kubectl get pods -n auth-service
kubectl get services -n auth-service
```

### 5. Configure Ingress
```bash
# Get external IP
kubectl get ingress -n auth-service

# Update DNS to point to the ingress IP
# auth.yourdomain.com -> <EXTERNAL_IP>
```

### 6. Verify Deployment
```bash
# Check pods are running
kubectl get pods -n auth-service

# Check service health
kubectl port-forward service/rust-auth-service 8080:80 -n auth-service
curl http://localhost:8080/health
```

---

## 🔧 Configuration Guide

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | ✅ | - | Database connection string |
| `JWT_SECRET` | ✅ | - | JWT signing secret (256-bit) |
| `REDIS_URL` | ❌ | - | Redis cache connection |
| `SERVER_HOST` | ❌ | 0.0.0.0 | Server bind address |
| `SERVER_PORT` | ❌ | 8090 | Server port |
| `RUST_LOG` | ❌ | info | Log level (debug, info, warn, error) |
| `EMAIL_PROVIDER` | ❌ | - | Email provider (sendgrid, brevo, smtp) |

### Database URLs

#### MongoDB
```bash
# Local MongoDB
DATABASE_URL="mongodb://localhost:27017/auth_service"

# MongoDB with authentication
DATABASE_URL="mongodb://username:password@localhost:27017/auth_service?authSource=admin"

# MongoDB Atlas (cloud)
DATABASE_URL="mongodb+srv://username:password@cluster.mongodb.net/auth_service"
```

#### PostgreSQL
```bash
# Local PostgreSQL
DATABASE_URL="postgresql://username:password@localhost:5432/auth_service"

# PostgreSQL with SSL
DATABASE_URL="postgresql://username:password@localhost:5432/auth_service?sslmode=require"

# Cloud PostgreSQL (AWS RDS, GCP Cloud SQL)
DATABASE_URL="postgresql://username:password@host:5432/auth_service?sslmode=require"
```

#### MySQL
```bash
# Local MySQL
DATABASE_URL="mysql://username:password@localhost:3306/auth_service"

# MySQL with SSL
DATABASE_URL="mysql://username:password@localhost:3306/auth_service?ssl-mode=REQUIRED"
```

### Email Configuration

#### SendGrid
```bash
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=your-sendgrid-api-key
SENDGRID_FROM_EMAIL=noreply@yourdomain.com
```

#### Brevo (Sendinblue)
```bash
EMAIL_PROVIDER=brevo
BREVO_API_KEY=your-brevo-api-key
BREVO_FROM_EMAIL=noreply@yourdomain.com
```

#### SMTP
```bash
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_EMAIL=noreply@yourdomain.com
```

---

## 🧪 Testing Your Setup

### 1. Health Check
```bash
curl http://localhost:8090/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2024-10-22T10:00:00Z",
  "checks": {
    "database": "healthy",
    "cache": "healthy",
    "email": "healthy"
  }
}
```

### 2. User Registration Flow
```bash
# 1. Register a new user
curl -X POST http://localhost:8090/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "password": "SecurePass123!",
    "first_name": "New",
    "last_name": "User"
  }'

# 2. Login with the user
curl -X POST http://localhost:8090/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "password": "SecurePass123!"
  }'

# 3. Use the JWT token from login response
TOKEN="your-jwt-token-here"

# 4. Get user profile (protected endpoint)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8090/api/auth/me
```

### 3. Load Testing (Optional)
```bash
# Install Artillery for load testing
npm install -g artillery

# Run basic load test
artillery quick --count 10 --num 100 http://localhost:8090/health
```

---

## 🛠️ Development Workflow

### 1. Making Changes
```bash
# Start development environment
cd docker && ./scripts/setup-dev.sh

# Make your changes in src/

# Test your changes
cargo test

# Check formatting and linting
cargo fmt
cargo clippy

# Run security audit
cargo audit
```

### 2. Hot Reload Development
```bash
# Install cargo-watch for hot reload
cargo install cargo-watch

# Start with hot reload
cargo watch -x run
```

### 3. Testing Different Databases
```bash
# Test with MongoDB
export DATABASE_TYPE=mongodb
cargo test

# Test with PostgreSQL  
export DATABASE_TYPE=postgresql
cargo test

# Test with MySQL
export DATABASE_TYPE=mysql
cargo test
```

---

## 🐛 Troubleshooting

### Common Issues

#### Issue: "Database connection failed"
```bash
# Check if database is running
# MongoDB:
mongosh --eval "db.runCommand('ping')"

# PostgreSQL:
pg_isready -h localhost -p 5432

# MySQL:
mysqladmin ping -h localhost
```

#### Issue: "Port already in use"
```bash
# Check what's using the port
lsof -i :8090

# Kill the process
sudo kill -9 <PID>

# Or use a different port
export SERVER_PORT=8091
```

#### Issue: "SSL certificate errors"
```bash
# Regenerate SSL certificates
cd docker
rm -rf nginx/ssl/*
./scripts/generate-ssl.sh
```

#### Issue: "Email not sending"
```bash
# Check email configuration
curl http://localhost:8090/health

# For development, use MailHog
# Check emails at: http://localhost:8025
```

### Getting Help

1. **Check the logs**: `docker-compose logs auth-service` or `cargo run` output
2. **Health check**: `curl http://localhost:8090/health`
3. **GitHub Issues**: [Report bugs](https://github.com/fahdi/rust-auth-service/issues)
4. **Documentation**: Browse the [docs/](docs/) directory

---

## 🚀 Next Steps

### For Developers
1. **Explore the API**: Visit http://localhost:8090/docs
2. **Try the Examples**: Check out [examples/](examples/) directory
3. **Read the Integration Guide**: [docs/api/INTEGRATION_GUIDE.md](docs/api/INTEGRATION_GUIDE.md)
4. **Contribute**: See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)

### For DevOps/Production
1. **Security Setup**: Review [docs/deployment/production-best-practices.md](docs/deployment/production-best-practices.md)
2. **Monitoring**: Set up Prometheus and Grafana
3. **Backup Strategy**: Configure database backups
4. **SSL Certificates**: Set up valid SSL certificates

### For Integration
1. **Choose Your Framework**: React, Vue.js, Python examples available
2. **Client Libraries**: Use the provided client libraries
3. **Custom Integration**: Follow the OpenAPI specification
4. **Testing**: Set up automated testing with your integration

---

**🎉 Congratulations! You now have a working Rust Auth Service. Ready to build secure authentication into your applications!**

For more detailed information, explore our comprehensive documentation in the [docs/](docs/) directory.