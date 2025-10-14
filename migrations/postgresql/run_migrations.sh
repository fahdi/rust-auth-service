#!/bin/bash

# PostgreSQL Migration Runner Script
# Usage: ./run_migrations.sh [database_url]

set -e

# Default database URL (can be overridden)
DATABASE_URL="${1:-postgresql://postgres:password@localhost:5432/auth_service}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🗄️  PostgreSQL Migration Runner${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo -e "${RED}❌ Error: psql is not installed or not in PATH${NC}"
    echo "Please install PostgreSQL client tools"
    exit 1
fi

# Check if database is accessible
echo -e "${YELLOW}🔍 Testing database connection...${NC}"
if ! psql "$DATABASE_URL" -c "SELECT 1;" &> /dev/null; then
    echo -e "${RED}❌ Error: Cannot connect to database${NC}"
    echo "Database URL: $DATABASE_URL"
    echo ""
    echo "Make sure PostgreSQL is running and the database exists."
    echo "You can create the database with:"
    echo "  createdb auth_service"
    exit 1
fi

echo -e "${GREEN}✅ Database connection successful${NC}"
echo ""

# Create migrations table if it doesn't exist
echo -e "${YELLOW}📋 Creating migrations tracking table...${NC}"
psql "$DATABASE_URL" -c "
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(50) PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
" > /dev/null

echo -e "${GREEN}✅ Migrations table ready${NC}"
echo ""

# Get list of migration files
MIGRATION_DIR="$(dirname "$0")"
MIGRATION_FILES=$(ls "$MIGRATION_DIR"/*.sql 2>/dev/null | sort)

if [ -z "$MIGRATION_FILES" ]; then
    echo -e "${YELLOW}⚠️  No migration files found in $MIGRATION_DIR${NC}"
    exit 0
fi

echo -e "${BLUE}🚀 Running migrations...${NC}"
echo ""

# Run each migration
for migration_file in $MIGRATION_FILES; do
    filename=$(basename "$migration_file")
    version="${filename%.*}"  # Remove .sql extension
    
    # Check if migration has already been applied
    if psql "$DATABASE_URL" -t -c "SELECT version FROM schema_migrations WHERE version = '$version';" | grep -q "$version"; then
        echo -e "${BLUE}⏭️  Skipping $filename (already applied)${NC}"
        continue
    fi
    
    echo -e "${YELLOW}⚡ Applying $filename...${NC}"
    
    # Run the migration in a transaction
    if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$migration_file" > /dev/null; then
        # Record successful migration
        psql "$DATABASE_URL" -c "INSERT INTO schema_migrations (version) VALUES ('$version');" > /dev/null
        echo -e "${GREEN}✅ Successfully applied $filename${NC}"
    else
        echo -e "${RED}❌ Failed to apply $filename${NC}"
        exit 1
    fi
done

echo ""
echo -e "${GREEN}🎉 All migrations completed successfully!${NC}"
echo ""

# Show applied migrations
echo -e "${BLUE}📊 Applied migrations:${NC}"
psql "$DATABASE_URL" -c "
SELECT 
    version,
    applied_at AT TIME ZONE 'UTC' as applied_at_utc
FROM schema_migrations 
ORDER BY applied_at;
"

echo ""
echo -e "${BLUE}📈 Database statistics:${NC}"
psql "$DATABASE_URL" -c "
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"