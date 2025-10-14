#!/bin/bash

# MySQL Migration Runner Script
# Usage: ./run_migrations.sh [database_url]

set -e

# Default database URL (can be overridden)
DATABASE_URL="${1:-mysql://root:password@localhost:3306/auth_service}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🗄️  MySQL Migration Runner${NC}"
echo -e "${BLUE}=============================${NC}"
echo ""

# Check if mysql client is available
if ! command -v mysql &> /dev/null; then
    echo -e "${RED}❌ Error: mysql client is not installed or not in PATH${NC}"
    echo "Please install MySQL client tools"
    exit 1
fi

# Parse connection string for mysql client
# Convert mysql://user:pass@host:port/db to individual components
if [[ $DATABASE_URL =~ mysql://([^:]+):([^@]+)@([^:]+):([^/]+)/(.+) ]]; then
    DB_USER="${BASH_REMATCH[1]}"
    DB_PASS="${BASH_REMATCH[2]}"
    DB_HOST="${BASH_REMATCH[3]}"
    DB_PORT="${BASH_REMATCH[4]}"
    DB_NAME="${BASH_REMATCH[5]}"
else
    echo -e "${RED}❌ Error: Invalid database URL format${NC}"
    echo "Expected format: mysql://user:password@host:port/database"
    exit 1
fi

# Check if database is accessible
echo -e "${YELLOW}🔍 Testing database connection...${NC}"
if ! mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" -e "SELECT 1;" "$DB_NAME" &> /dev/null; then
    echo -e "${RED}❌ Error: Cannot connect to database${NC}"
    echo "Database URL: $DATABASE_URL"
    echo ""
    echo "Make sure MySQL is running and the database exists."
    echo "You can create the database with:"
    echo "  mysql -h$DB_HOST -P$DB_PORT -u$DB_USER -p$DB_PASS -e \"CREATE DATABASE $DB_NAME;\""
    exit 1
fi

echo -e "${GREEN}✅ Database connection successful${NC}"
echo ""

# Create migrations table if it doesn't exist
echo -e "${YELLOW}📋 Creating migrations tracking table...${NC}"
mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(50) PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
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
    if mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -N -e "SELECT version FROM schema_migrations WHERE version = '$version';" 2>/dev/null | grep -q "$version"; then
        echo -e "${BLUE}⏭️  Skipping $filename (already applied)${NC}"
        continue
    fi
    
    echo -e "${YELLOW}⚡ Applying $filename...${NC}"
    
    # Run the migration
    if mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" < "$migration_file" > /dev/null 2>&1; then
        # Record successful migration
        mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "INSERT INTO schema_migrations (version) VALUES ('$version');" > /dev/null
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
mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
SELECT 
    version,
    applied_at
FROM schema_migrations 
ORDER BY applied_at;
"

echo ""
echo -e "${BLUE}📈 Database statistics:${NC}"
mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
SELECT 
    table_name,
    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'Size (MB)'
FROM information_schema.tables 
WHERE table_schema = '$DB_NAME'
ORDER BY (data_length + index_length) DESC;
"