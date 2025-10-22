#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🌱 Seeding development database...${NC}"

# Determine Docker Compose command
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

# Wait for database to be ready
echo -e "${YELLOW}⏳ Waiting for database to be ready...${NC}"
cd ..
$DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml exec mongodb mongosh --eval "db.adminCommand('ping')" --quiet

# Create development users
echo -e "${YELLOW}👤 Creating development users...${NC}"

# Admin user
$DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml exec auth-service curl -X POST http://localhost:8090/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@localhost",
    "password": "Admin123!",
    "first_name": "Admin",
    "last_name": "User"
  }' || true

# Test user
$DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml exec auth-service curl -X POST http://localhost:8090/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@localhost", 
    "password": "Test123!",
    "first_name": "Test",
    "last_name": "User"
  }' || true

# Demo user for frontend examples
$DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml exec auth-service curl -X POST http://localhost:8090/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "demo@localhost",
    "password": "Demo123!",
    "first_name": "Demo",
    "last_name": "User"
  }' || true

# Create sample data using MongoDB shell
echo -e "${YELLOW}📊 Creating sample data...${NC}"
$DOCKER_COMPOSE -f docker-compose.yml -f docker-compose.dev.yml exec mongodb mongosh auth_service_dev --eval '
// Create some sample user sessions
db.user_sessions.insertMany([
  {
    user_id: "admin@localhost",
    session_id: "admin_session_123",
    created_at: new Date(),
    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
    device_info: {
      browser: "Chrome",
      os: "macOS",
      ip_address: "127.0.0.1"
    }
  },
  {
    user_id: "test@localhost", 
    session_id: "test_session_456",
    created_at: new Date(),
    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
    device_info: {
      browser: "Firefox",
      os: "Linux",
      ip_address: "127.0.0.1"
    }
  }
]);

// Create sample metrics data
db.auth_metrics.insertMany([
  {
    event_type: "login",
    user_id: "test@localhost",
    timestamp: new Date(),
    metadata: {
      success: true,
      ip_address: "127.0.0.1",
      user_agent: "Mozilla/5.0"
    }
  },
  {
    event_type: "registration",
    user_id: "demo@localhost",
    timestamp: new Date(),
    metadata: {
      success: true,
      ip_address: "127.0.0.1",
      registration_source: "web"
    }
  }
]);

print("✅ Sample data created successfully");
' || echo -e "${YELLOW}⚠️  Some sample data creation may have failed - this is normal for fresh installations${NC}"

echo -e "${GREEN}🎉 Database seeding completed!${NC}"
echo ""
echo -e "${BLUE}Development accounts created:${NC}"
echo -e "${YELLOW}📧 admin@localhost / Admin123!${NC}"
echo -e "${YELLOW}📧 test@localhost / Test123!${NC}"
echo -e "${YELLOW}📧 demo@localhost / Demo123!${NC}"
echo ""
echo -e "${BLUE}💡 You can use these accounts to test the application${NC}"