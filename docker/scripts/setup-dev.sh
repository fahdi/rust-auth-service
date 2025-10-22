#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Setting up Rust Auth Service Development Environment${NC}"
echo "=================================================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not available. Please install Docker Compose.${NC}"
    exit 1
fi

# Determine Docker Compose command
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

echo -e "${GREEN}✅ Docker and Docker Compose are available${NC}"

# Create necessary directories
echo -e "${YELLOW}📁 Creating necessary directories...${NC}"
mkdir -p ../nginx/ssl
mkdir -p ../logs
mkdir -p ../data/mongodb
mkdir -p ../data/redis

# Generate SSL certificates for local HTTPS
echo -e "${YELLOW}🔐 Generating SSL certificates for local development...${NC}"
./generate-ssl.sh

# Copy environment file
if [ ! -f "../env/.env" ]; then
    echo -e "${YELLOW}📝 Creating environment file...${NC}"
    cp ../env/.env.development ../env/.env
    echo -e "${GREEN}✅ Environment file created from development template${NC}"
    echo -e "${YELLOW}💡 You can customize settings in docker/env/.env${NC}"
else
    echo -e "${BLUE}ℹ️  Environment file already exists${NC}"
fi

# Pull required images
echo -e "${YELLOW}📦 Pulling Docker images...${NC}"
cd ..
$DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml pull

# Build custom images
echo -e "${YELLOW}🔨 Building custom images...${NC}"
$DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml build

# Start the development environment
echo -e "${YELLOW}🚀 Starting development environment...${NC}"
$DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml up -d

# Wait for services to be healthy
echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"
sleep 10

# Check service health
echo -e "${YELLOW}🔍 Checking service health...${NC}"
./health-check.sh

# Run database migrations
echo -e "${YELLOW}📊 Running database migrations...${NC}"
$DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml exec auth-service cargo run --bin migrate up

# Seed development database
echo -e "${YELLOW}🌱 Seeding development database...${NC}"
./seed-database.sh

echo -e "${GREEN}🎉 Development environment is ready!${NC}"
echo ""
echo "Available services:"
echo -e "${BLUE}🌐 Main Application:     https://localhost${NC}"
echo -e "${BLUE}🔌 API Endpoint:         https://localhost/api${NC}"
echo -e "${BLUE}📚 API Documentation:    https://localhost/docs${NC}"
echo -e "${BLUE}🎨 Vue.js Example:       https://localhost/vue${NC}"
echo -e "${BLUE}📧 Email Testing:        https://localhost/mail${NC}"
echo -e "${BLUE}🗄️  MongoDB Admin:        https://localhost/admin/mongo${NC}"
echo -e "${BLUE}🔄 Redis Admin:          https://localhost/admin/redis${NC}"
echo ""
echo -e "${YELLOW}💡 To view logs: $DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml logs -f${NC}"
echo -e "${YELLOW}💡 To stop: $DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml down${NC}"
echo -e "${YELLOW}💡 To rebuild: $DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml up --build${NC}"