#!/bin/bash

#
# Auth Service Restore Script
# Automated restore solution for production databases and critical data
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/../config/backup.conf}"
LOG_FILE="${LOG_FILE:-/var/log/auth-service/restore.log}"

# Default values
RESTORE_TYPE="${RESTORE_TYPE:-full}"
DRY_RUN="${DRY_RUN:-false}"
FORCE_RESTORE="${FORCE_RESTORE:-false}"
VERIFY_BEFORE_RESTORE="${VERIFY_BEFORE_RESTORE:-true}"

# Load configuration if exists
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    send_notification "RESTORE_FAILED" "$1"
    exit 1
}

# Success notification
success_notification() {
    log "INFO" "$1"
    send_notification "RESTORE_SUCCESS" "$1"
}

# Send notification
send_notification() {
    local status="$1"
    local message="$2"
    
    if [[ "$NOTIFICATION_ENABLED" == "true" ]]; then
        # Send to monitoring system
        if command -v curl >/dev/null 2>&1 && [[ -n "${WEBHOOK_URL:-}" ]]; then
            curl -s -X POST "$WEBHOOK_URL" \
                -H "Content-Type: application/json" \
                -d "{
                    \"text\": \"Restore $status: $message\",
                    \"restore_type\": \"$RESTORE_TYPE\",
                    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
                    \"status\": \"$status\"
                }" || log "WARN" "Failed to send webhook notification"
        fi
        
        # Send email if configured
        if [[ -n "${EMAIL_TO:-}" ]] && command -v mail >/dev/null 2>&1; then
            echo "Restore $status: $message" | mail -s "Auth Service Restore $status" "$EMAIL_TO" || \
                log "WARN" "Failed to send email notification"
        fi
    fi
}

# Verify backup integrity
verify_backup() {
    local backup_file="$1"
    
    log "INFO" "Verifying backup integrity: $(basename "$backup_file")"
    
    if [[ ! -f "$backup_file" ]]; then
        error_exit "Backup file not found: $backup_file"
    fi
    
    # Check if encrypted
    if [[ "$backup_file" == *.enc ]]; then
        log "INFO" "Backup is encrypted, verifying encryption integrity"
        
        if [[ -z "${BACKUP_ENCRYPTION_KEY:-}" ]]; then
            error_exit "BACKUP_ENCRYPTION_KEY not set but backup is encrypted"
        fi
        
        # Create temporary decrypted file for verification
        local temp_file="/tmp/verify_$(basename "$backup_file" .enc)"
        if ! openssl enc -aes-256-cbc -d -in "$backup_file" -out "$temp_file" \
             -pass pass:"$BACKUP_ENCRYPTION_KEY"; then
            error_exit "Failed to decrypt backup file"
        fi
        
        backup_file="$temp_file"
    fi
    
    # Check if compressed
    if [[ "$backup_file" == *.tar.gz ]]; then
        log "INFO" "Verifying compressed backup"
        if ! tar -tzf "$backup_file" >/dev/null 2>&1; then
            error_exit "Backup file is corrupted (tar verification failed)"
        fi
    fi
    
    # Extract and verify manifest
    local temp_extract_dir="/tmp/backup_verify_$$"
    mkdir -p "$temp_extract_dir"
    
    if [[ "$backup_file" == *.tar.gz ]]; then
        tar -xzf "$backup_file" -C "$temp_extract_dir" || error_exit "Failed to extract backup"
    else
        cp -r "$backup_file"/* "$temp_extract_dir/" 2>/dev/null || \
            error_exit "Failed to access backup contents"
    fi
    
    # Check manifest
    local manifest_file="$temp_extract_dir"/*/manifest.json
    if [[ -f $manifest_file ]]; then
        log "INFO" "Backup manifest found and valid"
        cat "$manifest_file" | jq . >/dev/null 2>&1 || error_exit "Invalid manifest JSON"
    else
        log "WARN" "No manifest file found in backup"
    fi
    
    # Cleanup
    rm -rf "$temp_extract_dir"
    [[ -f "/tmp/verify_$(basename "${backup_file%.*}" .enc)" ]] && rm -f "/tmp/verify_$(basename "${backup_file%.*}" .enc)"
    
    log "INFO" "Backup verification completed successfully"
}

# Extract backup
extract_backup() {
    local backup_file="$1"
    local extract_dir="$2"
    
    log "INFO" "Extracting backup to: $extract_dir"
    
    mkdir -p "$extract_dir"
    
    local working_file="$backup_file"
    
    # Decrypt if needed
    if [[ "$backup_file" == *.enc ]]; then
        log "INFO" "Decrypting backup"
        
        if [[ -z "${BACKUP_ENCRYPTION_KEY:-}" ]]; then
            error_exit "BACKUP_ENCRYPTION_KEY not set but backup is encrypted"
        fi
        
        local decrypted_file="${backup_file%.enc}"
        if ! openssl enc -aes-256-cbc -d -in "$backup_file" -out "$decrypted_file" \
             -pass pass:"$BACKUP_ENCRYPTION_KEY"; then
            error_exit "Failed to decrypt backup file"
        fi
        
        working_file="$decrypted_file"
    fi
    
    # Extract if compressed
    if [[ "$working_file" == *.tar.gz ]]; then
        log "INFO" "Extracting compressed backup"
        if ! tar -xzf "$working_file" -C "$extract_dir"; then
            error_exit "Failed to extract backup"
        fi
    else
        # Copy uncompressed backup
        cp -r "$working_file"/* "$extract_dir/" || error_exit "Failed to copy backup contents"
    fi
    
    # Cleanup temporary files
    if [[ "$working_file" != "$backup_file" ]]; then
        rm -f "$working_file"
    fi
    
    log "INFO" "Backup extracted successfully"
}

# Stop services
stop_services() {
    log "INFO" "Stopping Auth Service for restore operation"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would stop auth service"
        return
    fi
    
    # Stop using systemd if available
    if systemctl is-active --quiet auth-service 2>/dev/null; then
        systemctl stop auth-service || log "WARN" "Failed to stop auth-service via systemctl"
    fi
    
    # Stop using Docker if running in container
    if command -v docker >/dev/null 2>&1; then
        docker stop auth-service 2>/dev/null || log "WARN" "Failed to stop auth-service container"
    fi
    
    # Stop using Kubernetes if in cluster
    if command -v kubectl >/dev/null 2>&1; then
        kubectl scale deployment auth-service --replicas=0 2>/dev/null || \
            log "WARN" "Failed to scale down auth-service deployment"
    fi
    
    # Wait for services to stop
    sleep 5
    
    log "INFO" "Services stopped"
}

# Start services
start_services() {
    log "INFO" "Starting Auth Service after restore operation"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would start auth service"
        return
    fi
    
    # Start using systemd if available
    if systemctl list-unit-files | grep -q "^auth-service.service"; then
        systemctl start auth-service || log "WARN" "Failed to start auth-service via systemctl"
    fi
    
    # Start using Docker if configured
    if command -v docker >/dev/null 2>&1 && [[ -n "${DOCKER_COMPOSE_FILE:-}" ]]; then
        docker-compose -f "$DOCKER_COMPOSE_FILE" up -d auth-service || \
            log "WARN" "Failed to start auth-service container"
    fi
    
    # Start using Kubernetes if in cluster
    if command -v kubectl >/dev/null 2>&1; then
        kubectl scale deployment auth-service --replicas="${REPLICA_COUNT:-2}" 2>/dev/null || \
            log "WARN" "Failed to scale up auth-service deployment"
    fi
    
    log "INFO" "Services started"
}

# Restore MongoDB
restore_mongodb() {
    local backup_dir="$1"
    
    log "INFO" "Restoring MongoDB from backup"
    
    local mongo_backup_dir="$backup_dir/mongodb"
    if [[ ! -d "$mongo_backup_dir" ]]; then
        error_exit "MongoDB backup directory not found: $mongo_backup_dir"
    fi
    
    local mongo_url="${MONGODB_URL:-$DATABASE_URL}"
    if [[ -z "$mongo_url" ]]; then
        error_exit "MongoDB URL not configured"
    fi
    
    # Get database name from backup info
    local db_name="auth_service"
    if [[ -f "$mongo_backup_dir/backup_info.json" ]]; then
        db_name=$(jq -r '.database_name // "auth_service"' "$mongo_backup_dir/backup_info.json")
    fi
    
    # Find the actual backup directory (mongodump creates a subdirectory)
    local actual_backup_dir="$mongo_backup_dir"
    if [[ -d "$mongo_backup_dir/$db_name" ]]; then
        actual_backup_dir="$mongo_backup_dir"
    elif [[ -d "$mongo_backup_dir"/*/ ]]; then
        actual_backup_dir=$(find "$mongo_backup_dir" -type d -mindepth 1 -maxdepth 1 | head -n1)
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would restore MongoDB from: $actual_backup_dir"
        return
    fi
    
    # Drop existing database if force restore
    if [[ "$FORCE_RESTORE" == "true" ]]; then
        log "WARN" "Force restore enabled - dropping existing database"
        mongosh "$mongo_url" --eval "db.dropDatabase()" || log "WARN" "Failed to drop existing database"
    fi
    
    # Restore database
    if ! mongorestore --uri="$mongo_url" --dir="$actual_backup_dir" --drop; then
        error_exit "MongoDB restore failed"
    fi
    
    log "INFO" "MongoDB restore completed"
}

# Restore PostgreSQL
restore_postgresql() {
    local backup_dir="$1"
    
    log "INFO" "Restoring PostgreSQL from backup"
    
    local pg_backup_file="$backup_dir/postgresql_backup.sql"
    if [[ ! -f "$pg_backup_file" ]]; then
        error_exit "PostgreSQL backup file not found: $pg_backup_file"
    fi
    
    local pg_url="${POSTGRESQL_URL:-$DATABASE_URL}"
    if [[ -z "$pg_url" ]]; then
        error_exit "PostgreSQL URL not configured"
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would restore PostgreSQL from: $pg_backup_file"
        return
    fi
    
    # Drop and recreate database if force restore
    if [[ "$FORCE_RESTORE" == "true" ]]; then
        log "WARN" "Force restore enabled - recreating database"
        local db_name=$(echo "$pg_url" | sed -n 's|.*/\([^?]*\).*|\1|p')
        local pg_admin_url="${pg_url%/*}/postgres"
        
        psql "$pg_admin_url" -c "DROP DATABASE IF EXISTS $db_name;" || log "WARN" "Failed to drop database"
        psql "$pg_admin_url" -c "CREATE DATABASE $db_name;" || error_exit "Failed to create database"
    fi
    
    # Restore database
    if ! psql "$pg_url" < "$pg_backup_file"; then
        error_exit "PostgreSQL restore failed"
    fi
    
    log "INFO" "PostgreSQL restore completed"
}

# Restore MySQL
restore_mysql() {
    local backup_dir="$1"
    
    log "INFO" "Restoring MySQL from backup"
    
    local mysql_backup_file="$backup_dir/mysql_backup.sql"
    if [[ ! -f "$mysql_backup_file" ]]; then
        error_exit "MySQL backup file not found: $mysql_backup_file"
    fi
    
    local mysql_url="${MYSQL_URL:-$DATABASE_URL}"
    if [[ -z "$mysql_url" ]]; then
        error_exit "MySQL URL not configured"
    fi
    
    # Parse MySQL URL
    local mysql_host=$(echo "$mysql_url" | sed -n 's|mysql://[^@]*@\([^:]*\):.*|\1|p')
    local mysql_port=$(echo "$mysql_url" | sed -n 's|mysql://[^@]*@[^:]*:\([0-9]*\)/.*|\1|p')
    local mysql_user=$(echo "$mysql_url" | sed -n 's|mysql://\([^:]*\):.*|\1|p')
    local mysql_pass=$(echo "$mysql_url" | sed -n 's|mysql://[^:]*:\([^@]*\)@.*|\1|p')
    local mysql_db=$(echo "$mysql_url" | sed -n 's|mysql://[^/]*/\(.*\)|\1|p')
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would restore MySQL from: $mysql_backup_file"
        return
    fi
    
    # Drop and recreate database if force restore
    if [[ "$FORCE_RESTORE" == "true" ]]; then
        log "WARN" "Force restore enabled - recreating database"
        mysql -h"$mysql_host" -P"$mysql_port" -u"$mysql_user" -p"$mysql_pass" \
              -e "DROP DATABASE IF EXISTS $mysql_db; CREATE DATABASE $mysql_db;" || \
              error_exit "Failed to recreate database"
    fi
    
    # Restore database
    if ! mysql -h"$mysql_host" -P"$mysql_port" -u"$mysql_user" -p"$mysql_pass" \
         "$mysql_db" < "$mysql_backup_file"; then
        error_exit "MySQL restore failed"
    fi
    
    log "INFO" "MySQL restore completed"
}

# Restore application data
restore_application_data() {
    local backup_dir="$1"
    
    log "INFO" "Restoring application data from backup"
    
    local app_data_dir="$backup_dir/application"
    if [[ ! -d "$app_data_dir" ]]; then
        log "WARN" "Application data directory not found in backup"
        return
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would restore application data from: $app_data_dir"
        return
    fi
    
    # Restore configuration files
    if [[ -d "$app_data_dir/config" ]]; then
        log "INFO" "Restoring configuration files"
        cp -r "$app_data_dir/config"/* /app/config/ 2>/dev/null || \
            log "WARN" "Failed to restore some configuration files"
    fi
    
    # Restore certificates
    if [[ -d "$app_data_dir/certificates" ]]; then
        log "INFO" "Restoring certificates"
        cp -r "$app_data_dir/certificates"/* /etc/ssl/auth-service/ 2>/dev/null || \
            log "WARN" "Failed to restore some certificates"
    fi
    
    log "INFO" "Application data restore completed"
}

# Validate restore
validate_restore() {
    log "INFO" "Validating restore operation"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would validate restore"
        return
    fi
    
    # Wait for services to start up
    sleep 10
    
    # Basic health check
    local health_url="${HEALTH_CHECK_URL:-http://localhost:8090/health}"
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -s -f "$health_url" >/dev/null 2>&1; then
            log "INFO" "Health check passed (attempt $attempt)"
            break
        fi
        
        log "INFO" "Health check failed, retrying in 10 seconds (attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done
    
    if [[ $attempt -gt $max_attempts ]]; then
        error_exit "Health check failed after $max_attempts attempts"
    fi
    
    # Database connectivity check
    case "${DATABASE_TYPE:-}" in
        "mongodb")
            mongosh "${MONGODB_URL:-$DATABASE_URL}" --eval "db.adminCommand('ping')" >/dev/null 2>&1 || \
                error_exit "MongoDB connectivity check failed"
            ;;
        "postgresql")
            psql "${POSTGRESQL_URL:-$DATABASE_URL}" -c "SELECT 1;" >/dev/null 2>&1 || \
                error_exit "PostgreSQL connectivity check failed"
            ;;
        "mysql")
            local mysql_url="${MYSQL_URL:-$DATABASE_URL}"
            local mysql_host=$(echo "$mysql_url" | sed -n 's|mysql://[^@]*@\([^:]*\):.*|\1|p')
            local mysql_port=$(echo "$mysql_url" | sed -n 's|mysql://[^@]*@[^:]*:\([0-9]*\)/.*|\1|p')
            local mysql_user=$(echo "$mysql_url" | sed -n 's|mysql://\([^:]*\):.*|\1|p')
            local mysql_pass=$(echo "$mysql_url" | sed -n 's|mysql://[^:]*:\([^@]*\)@.*|\1|p')
            
            mysql -h"$mysql_host" -P"$mysql_port" -u"$mysql_user" -p"$mysql_pass" \
                  -e "SELECT 1;" >/dev/null 2>&1 || \
                  error_exit "MySQL connectivity check failed"
            ;;
    esac
    
    log "INFO" "Restore validation completed successfully"
}

# Perform restore
perform_restore() {
    local backup_file="$1"
    
    log "INFO" "Starting restore from: $(basename "$backup_file")"
    
    # Verify backup if enabled
    if [[ "$VERIFY_BEFORE_RESTORE" == "true" ]]; then
        verify_backup "$backup_file"
    fi
    
    # Extract backup
    local extract_dir="/tmp/restore_$$"
    extract_backup "$backup_file" "$extract_dir"
    
    # Find the actual backup directory
    local backup_dir=$(find "$extract_dir" -type d -name "auth-service-backup-*" | head -n1)
    if [[ -z "$backup_dir" ]]; then
        backup_dir="$extract_dir"
    fi
    
    # Read backup manifest
    local manifest_file="$backup_dir/manifest.json"
    if [[ -f "$manifest_file" ]]; then
        log "INFO" "Reading backup manifest"
        local backup_db_type=$(jq -r '.database_type // "unknown"' "$manifest_file")
        local backup_timestamp=$(jq -r '.timestamp // "unknown"' "$manifest_file")
        log "INFO" "Backup info - Type: $backup_db_type, Timestamp: $backup_timestamp"
    fi
    
    # Confirm restore unless force mode
    if [[ "$FORCE_RESTORE" != "true" ]] && [[ "$DRY_RUN" != "true" ]]; then
        echo
        echo "WARNING: This will restore from backup and may overwrite existing data!"
        echo "Backup file: $(basename "$backup_file")"
        echo "Database type: ${DATABASE_TYPE:-unknown}"
        echo "Restore type: $RESTORE_TYPE"
        echo
        read -p "Are you sure you want to continue? (yes/no): " -r confirm
        
        if [[ "$confirm" != "yes" ]]; then
            log "INFO" "Restore cancelled by user"
            rm -rf "$extract_dir"
            exit 0
        fi
    fi
    
    # Stop services
    stop_services
    
    # Perform database restore
    case "${DATABASE_TYPE:-}" in
        "mongodb")
            restore_mongodb "$backup_dir"
            ;;
        "postgresql")
            restore_postgresql "$backup_dir"
            ;;
        "mysql")
            restore_mysql "$backup_dir"
            ;;
        *)
            log "WARN" "Unknown database type: ${DATABASE_TYPE:-}, skipping database restore"
            ;;
    esac
    
    # Restore application data
    restore_application_data "$backup_dir"
    
    # Start services
    start_services
    
    # Validate restore
    validate_restore
    
    # Cleanup
    rm -rf "$extract_dir"
    
    success_notification "Restore completed successfully from: $(basename "$backup_file")"
}

# List available backups
list_backups() {
    log "INFO" "Listing available backups"
    
    echo "Local backups:"
    if [[ -n "${BACKUP_DIR:-}" ]] && [[ -d "$BACKUP_DIR" ]]; then
        find "$BACKUP_DIR" -name "auth-service-backup-*" -type f | sort -r | head -20
    else
        echo "  No local backup directory configured"
    fi
    
    echo
    echo "S3 backups:"
    if [[ -n "${S3_BUCKET:-}" ]] && command -v aws >/dev/null 2>&1; then
        aws s3 ls "s3://$S3_BUCKET/" | grep "auth-service-backup-" | sort -r | head -20
    else
        echo "  No S3 bucket configured or AWS CLI not available"
    fi
    
    echo
    echo "GCS backups:"
    if [[ -n "${GCS_BUCKET:-}" ]] && command -v gsutil >/dev/null 2>&1; then
        gsutil ls "gs://$GCS_BUCKET/auth-service-backup-*" | sort -r | head -20
    else
        echo "  No GCS bucket configured or gsutil not available"
    fi
}

# Main execution
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --backup-file)
                BACKUP_FILE="$2"
                shift 2
                ;;
            --type)
                RESTORE_TYPE="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force)
                FORCE_RESTORE=true
                shift
                ;;
            --no-verify)
                VERIFY_BEFORE_RESTORE=false
                shift
                ;;
            --list)
                list_backups
                exit 0
                ;;
            --help)
                cat <<EOF
Auth Service Restore Script

Usage: $0 --backup-file FILE [OPTIONS]

Options:
    --backup-file FILE     Backup file to restore from (required)
    --type TYPE           Restore type (full, database, config)
    --dry-run             Show what would be done without actually doing it
    --force               Force restore without confirmation
    --no-verify           Skip backup verification before restore
    --list                List available backups
    --help                Show this help message

Environment Variables:
    DATABASE_TYPE         Database type (mongodb, postgresql, mysql)
    DATABASE_URL          Database connection URL
    BACKUP_ENCRYPTION_KEY Encryption key for backups
    FORCE_RESTORE         Force restore without confirmation (true/false)
    DRY_RUN              Dry run mode (true/false)

Examples:
    $0 --backup-file /backups/auth-service-backup-20240115_020000.tar.gz.enc
    $0 --backup-file backup.tar.gz --dry-run
    $0 --list

EOF
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
    
    # Check required arguments
    if [[ -z "${BACKUP_FILE:-}" ]]; then
        error_exit "Backup file is required. Use --backup-file option or --help for usage."
    fi
    
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Load configuration
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    fi
    
    # Perform restore
    perform_restore "$BACKUP_FILE"
}

# Execute main function
main "$@"