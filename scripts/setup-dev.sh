#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Setting up Rust Auth Service Development Environment${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
echo -e "${YELLOW}📋 Checking prerequisites...${NC}"

if ! command_exists docker; then
    echo -e "${RED}❌ Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

if ! command_exists docker-compose; then
    echo -e "${RED}❌ Docker Compose is not installed. Please install Docker Compose first.${NC}"
    exit 1
fi

if ! command_exists rust; then
    echo -e "${YELLOW}⚠️  Rust is not installed. Installing via rustup...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source "$HOME/.cargo/env"
fi

echo -e "${GREEN}✅ Prerequisites check passed${NC}"
echo ""

# Create environment file if it doesn't exist
echo -e "${YELLOW}🔧 Setting up environment configuration...${NC}"

if [ ! -f .env ]; then
    echo "Creating .env file..."
    cp .env.example .env
    echo -e "${GREEN}✅ Created .env file from template${NC}"
else
    echo -e "${GREEN}✅ .env file already exists${NC}"
fi

# Create config file if it doesn't exist
if [ ! -f config.yml ]; then
    echo "Creating config.yml file..."
    cp config.yml.example config.yml
    echo -e "${GREEN}✅ Created config.yml file from template${NC}"
else
    echo -e "${GREEN}✅ config.yml file already exists${NC}"
fi

echo ""

# Stop any existing containers
echo -e "${YELLOW}🛑 Stopping existing containers...${NC}"
docker-compose down --remove-orphans

# Build and start services
echo -e "${YELLOW}🏗️  Building and starting services...${NC}"
docker-compose up --build -d

echo ""
echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"

# Wait for MongoDB
echo -n "Waiting for MongoDB to be ready"
while ! docker-compose exec -T mongodb mongosh --quiet --eval "db.adminCommand('ping')" >/dev/null 2>&1; do
    echo -n "."
    sleep 2
done
echo -e " ${GREEN}✅${NC}"

# Wait for Redis
echo -n "Waiting for Redis to be ready"
while ! docker-compose exec -T redis redis-cli ping >/dev/null 2>&1; do
    echo -n "."
    sleep 2
done
echo -e " ${GREEN}✅${NC}"

# Wait for Auth Service
echo -n "Waiting for Auth Service to be ready"
for i in {1..30}; do
    if curl -f http://localhost:8080/health >/dev/null 2>&1; then
        echo -e " ${GREEN}✅${NC}"
        break
    fi
    echo -n "."
    sleep 3
    if [ $i -eq 30 ]; then
        echo -e " ${YELLOW}⚠️  Timeout, but continuing...${NC}"
    fi
done

echo ""
echo -e "${GREEN}🎉 Development environment is ready!${NC}"
echo ""
echo -e "${BLUE}📋 Services Status:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "🔐 Auth Service:     ${GREEN}http://localhost:8080${NC}"
echo -e "📊 Health Check:     ${GREEN}http://localhost:8080/health${NC}"
echo -e "🍃 MongoDB:          ${GREEN}localhost:27017${NC} (admin/password123)"
echo -e "🔴 Redis:            ${GREEN}localhost:6379${NC} (password: redis_password)"
echo -e "📧 MailHog UI:       ${GREEN}http://localhost:8025${NC}"
echo -e "📧 SMTP Server:      ${GREEN}localhost:1025${NC}"
echo ""
echo -e "${BLUE}🛠️  Optional Admin UIs (run with admin profile):${NC}"
echo "docker-compose --profile admin up -d"
echo -e "🍃 MongoDB Express:  ${GREEN}http://localhost:8081${NC} (admin/admin)"
echo -e "🔴 Redis Insight:    ${GREEN}http://localhost:8082${NC}"
echo ""
echo -e "${BLUE}📝 Useful Commands:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "• View logs:           docker-compose logs -f"
echo "• View auth logs:      docker-compose logs -f auth-service"
echo "• Restart auth service: docker-compose restart auth-service"
echo "• Run tests:           docker-compose exec auth-service cargo test"
echo "• Shell into container: docker-compose exec auth-service bash"
echo "• Stop all services:   docker-compose down"
echo ""
echo -e "${GREEN}✨ Happy coding!${NC}"