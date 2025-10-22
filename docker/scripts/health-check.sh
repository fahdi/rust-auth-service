#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Checking service health...${NC}"

# Determine Docker Compose command
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

cd ..

# Function to check if a service is healthy
check_service() {
    local service=$1
    local url=$2
    local max_attempts=30
    local attempt=1
    
    echo -n -e "${YELLOW}Checking $service...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if $DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml exec $service $url &> /dev/null; then
            echo -e " ${GREEN}✅ Healthy${NC}"
            return 0
        fi
        
        if [ $((attempt % 5)) -eq 0 ]; then
            echo -n -e "${YELLOW}.${NC}"
        fi
        
        sleep 2
        ((attempt++))
    done
    
    echo -e " ${RED}❌ Failed${NC}"
    return 1
}

# Function to check HTTP endpoint
check_http() {
    local service=$1
    local url=$2
    local max_attempts=30
    local attempt=1
    
    echo -n -e "${YELLOW}Checking $service...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "$url" > /dev/null 2>&1; then
            echo -e " ${GREEN}✅ Healthy${NC}"
            return 0
        fi
        
        if [ $((attempt % 5)) -eq 0 ]; then
            echo -n -e "${YELLOW}.${NC}"
        fi
        
        sleep 2
        ((attempt++))
    done
    
    echo -e " ${RED}❌ Failed${NC}"
    return 1
}

# Check MongoDB
check_service "mongodb" "mongosh --eval 'db.adminCommand(\"ping\")' --quiet"

# Check Redis  
check_service "redis" "redis-cli ping"

# Check MailHog
check_http "MailHog" "http://localhost:8025"

# Wait a bit more for auth service to be ready
echo -e "${YELLOW}⏳ Waiting for auth service to initialize...${NC}"
sleep 10

# Check Auth Service
check_http "Auth Service" "http://localhost/api/health"

# Check frontend services
check_http "Next.js App" "http://localhost"
check_http "Vue.js App" "http://localhost/vue"

# Check admin services if they're running
if $DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml ps mongo-express | grep -q "Up"; then
    check_http "MongoDB Express" "http://localhost/admin/mongo"
fi

if $DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml ps redis-insight | grep -q "Up"; then
    check_http "Redis Insight" "http://localhost/admin/redis"
fi

echo ""
echo -e "${GREEN}🎉 Health check completed!${NC}"
echo ""
echo -e "${BLUE}Service URLs:${NC}"
echo -e "${YELLOW}🌐 Main App:     https://localhost${NC}"
echo -e "${YELLOW}🔌 API:          https://localhost/api${NC}"
echo -e "${YELLOW}📚 Docs:         https://localhost/docs${NC}"
echo -e "${YELLOW}🎨 Vue App:      https://localhost/vue${NC}"
echo -e "${YELLOW}📧 MailHog:      https://localhost/mail${NC}"

# Show container status
echo ""
echo -e "${BLUE}Container Status:${NC}"
$DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml ps