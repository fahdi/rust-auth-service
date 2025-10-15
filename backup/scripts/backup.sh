#!/bin/bash

#
# Auth Service Backup Script
# Automated backup solution for production databases and critical data
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/../config/backup.conf}"
LOG_FILE="${LOG_FILE:-/var/log/auth-service/backup.log}"

# Default values
BACKUP_TYPE="${BACKUP_TYPE:-full}"
ENCRYPTION_ENABLED="${ENCRYPTION_ENABLED:-true}"
COMPRESSION_ENABLED="${COMPRESSION_ENABLED:-true}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
NOTIFICATION_ENABLED="${NOTIFICATION_ENABLED:-true}"

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
    send_notification "FAILED" "$1"
    exit 1
}

# Success notification
success_notification() {
    log "INFO" "$1"
    send_notification "SUCCESS" "$1"
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
                    \"text\": \"Backup $status: $message\",
                    \"backup_type\": \"$BACKUP_TYPE\",
                    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
                    \"status\": \"$status\"
                }" || log "WARN" "Failed to send webhook notification"
        fi
        
        # Send email if configured
        if [[ -n "${EMAIL_TO:-}" ]] && command -v mail >/dev/null 2>&1; then
            echo "Backup $status: $message" | mail -s "Auth Service Backup $status" "$EMAIL_TO" || \
                log "WARN" "Failed to send email notification"
        fi
    fi
}

# Check prerequisites
check_prerequisites() {
    log "INFO" "Checking prerequisites for backup operation"
    
    # Check required tools
    local required_tools=("mongodump" "pg_dump" "mysqldump" "aws" "gzip" "openssl")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log "WARN" "$tool not found, some backup types may not work"
        fi
    done
    
    # Check backup directory
    if [[ -n "${BACKUP_DIR:-}" ]]; then
        mkdir -p "$BACKUP_DIR" || error_exit "Failed to create backup directory: $BACKUP_DIR"
        
        # Check disk space (require at least 5GB free)
        local available_space=$(df "$BACKUP_DIR" | awk 'NR==2 {print $4}')
        if [[ "$available_space" -lt 5242880 ]]; then  # 5GB in KB
            error_exit "Insufficient disk space in $BACKUP_DIR (less than 5GB available)"
        fi
    fi
    
    # Check environment variables
    if [[ "$BACKUP_TYPE" == "full" ]]; then
        [[ -n "${DATABASE_TYPE:-}" ]] || error_exit "DATABASE_TYPE not set"
        [[ -n "${DATABASE_URL:-}" ]] || error_exit "DATABASE_URL not set"
    fi
    
    log "INFO" "Prerequisites check completed"
}

# MongoDB backup
backup_mongodb() {
    local backup_name="$1"
    local backup_path="$2"
    
    log "INFO" "Starting MongoDB backup"
    
    # Parse MongoDB URL
    local mongo_url="${MONGODB_URL:-$DATABASE_URL}"
    if [[ -z "$mongo_url" ]]; then
        error_exit "MongoDB URL not configured"
    fi
    
    # Create backup
    local mongo_backup_dir="$backup_path/mongodb"
    mkdir -p "$mongo_backup_dir"
    
    if ! mongodump --uri="$mongo_url" --out="$mongo_backup_dir" --quiet; then
        error_exit "MongoDB backup failed"
    fi
    
    # Create metadata
    cat > "$mongo_backup_dir/backup_info.json" <<EOF
{
    "backup_type": "mongodb",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "version": "$(mongod --version | head -n1)",
    "database_url": "${mongo_url%/*}/*****",
    "backup_method": "mongodump"
}
EOF
    
    log "INFO" "MongoDB backup completed"
}

# PostgreSQL backup
backup_postgresql() {
    local backup_name="$1"
    local backup_path="$2"
    
    log "INFO" "Starting PostgreSQL backup"
    
    local pg_url="${POSTGRESQL_URL:-$DATABASE_URL}"
    if [[ -z "$pg_url" ]]; then
        error_exit "PostgreSQL URL not configured"
    fi
    
    # Create backup
    local pg_backup_file="$backup_path/postgresql_backup.sql"
    
    if ! pg_dump "$pg_url" > "$pg_backup_file"; then
        error_exit "PostgreSQL backup failed"
    fi
    
    # Create metadata
    cat > "$backup_path/postgresql_backup_info.json" <<EOF
{
    "backup_type": "postgresql",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "version": "$(pg_dump --version | head -n1)",
    "database_url": "${pg_url%/*}/*****",
    "backup_method": "pg_dump",
    "backup_file": "postgresql_backup.sql"
}
EOF
    
    log "INFO" "PostgreSQL backup completed"
}

# MySQL backup
backup_mysql() {
    local backup_name="$1"
    local backup_path="$2"
    
    log "INFO" "Starting MySQL backup"
    
    local mysql_url="${MYSQL_URL:-$DATABASE_URL}"
    if [[ -z "$mysql_url" ]]; then
        error_exit "MySQL URL not configured"
    fi
    
    # Parse MySQL URL (mysql://user:pass@host:port/database)
    local mysql_host=$(echo "$mysql_url" | sed -n 's|mysql://[^@]*@\([^:]*\):.*|\1|p')
    local mysql_port=$(echo "$mysql_url" | sed -n 's|mysql://[^@]*@[^:]*:\([0-9]*\)/.*|\1|p')
    local mysql_user=$(echo "$mysql_url" | sed -n 's|mysql://\([^:]*\):.*|\1|p')
    local mysql_pass=$(echo "$mysql_url" | sed -n 's|mysql://[^:]*:\([^@]*\)@.*|\1|p')
    local mysql_db=$(echo "$mysql_url" | sed -n 's|mysql://[^/]*/\(.*\)|\1|p')
    
    # Create backup
    local mysql_backup_file="$backup_path/mysql_backup.sql"
    
    if ! mysqldump -h"$mysql_host" -P"$mysql_port" -u"$mysql_user" -p"$mysql_pass" \
         --single-transaction --routines --triggers "$mysql_db" > "$mysql_backup_file"; then
        error_exit "MySQL backup failed"
    fi
    
    # Create metadata
    cat > "$backup_path/mysql_backup_info.json" <<EOF
{
    "backup_type": "mysql",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "version": "$(mysqldump --version | head -n1)",
    "database_url": "${mysql_url%/*}/*****",
    "backup_method": "mysqldump",
    "backup_file": "mysql_backup.sql"
}
EOF
    
    log "INFO" "MySQL backup completed"
}

# Application data backup
backup_application_data() {
    local backup_name="$1"
    local backup_path="$2"
    
    log "INFO" "Starting application data backup"
    
    local app_data_dir="$backup_path/application"
    mkdir -p "$app_data_dir"
    
    # Backup configuration files
    if [[ -d "/app/config" ]]; then
        cp -r /app/config "$app_data_dir/" || log "WARN" "Failed to backup config directory"
    fi
    
    # Backup logs (last 7 days)
    if [[ -d "/var/log/auth-service" ]]; then
        find /var/log/auth-service -type f -mtime -7 -exec cp {} "$app_data_dir/" \; || \
            log "WARN" "Failed to backup some log files"
    fi
    
    # Backup certificates
    if [[ -d "/etc/ssl/auth-service" ]]; then
        cp -r /etc/ssl/auth-service "$app_data_dir/certificates/" || \
            log "WARN" "Failed to backup certificates"
    fi
    
    # Create application metadata
    cat > "$app_data_dir/app_info.json" <<EOF
{
    "backup_type": "application",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "version": "${APP_VERSION:-unknown}",
    "environment": "${ENVIRONMENT:-unknown}",
    "instance_id": "${INSTANCE_ID:-unknown}",
    "git_commit": "${GIT_COMMIT:-unknown}"
}
EOF
    
    log "INFO" "Application data backup completed"
}

# Compress backup
compress_backup() {
    local backup_path="$1"
    local compressed_file="$2"
    
    if [[ "$COMPRESSION_ENABLED" == "true" ]]; then
        log "INFO" "Compressing backup"
        
        if ! tar -czf "$compressed_file" -C "$(dirname "$backup_path")" "$(basename "$backup_path")"; then
            error_exit "Backup compression failed"
        fi
        
        # Remove uncompressed directory
        rm -rf "$backup_path"
        
        log "INFO" "Backup compressed to $(basename "$compressed_file")"
    fi
}

# Encrypt backup
encrypt_backup() {
    local backup_file="$1"
    local encrypted_file="$2"
    
    if [[ "$ENCRYPTION_ENABLED" == "true" ]]; then
        log "INFO" "Encrypting backup"
        
        if [[ -z "${BACKUP_ENCRYPTION_KEY:-}" ]]; then
            error_exit "BACKUP_ENCRYPTION_KEY not set but encryption is enabled"
        fi
        
        if ! openssl enc -aes-256-cbc -salt -in "$backup_file" -out "$encrypted_file" \
             -pass pass:"$BACKUP_ENCRYPTION_KEY"; then
            error_exit "Backup encryption failed"
        fi
        
        # Remove unencrypted file
        rm -f "$backup_file"
        
        log "INFO" "Backup encrypted"
    fi
}

# Upload to S3
upload_to_s3() {
    local backup_file="$1"
    local s3_key="$2"
    
    if [[ -n "${S3_BUCKET:-}" ]]; then
        log "INFO" "Uploading backup to S3"
        
        if ! aws s3 cp "$backup_file" "s3://$S3_BUCKET/$s3_key" \
             ${S3_STORAGE_CLASS:+--storage-class "$S3_STORAGE_CLASS"} \
             ${S3_SERVER_SIDE_ENCRYPTION:+--sse "$S3_SERVER_SIDE_ENCRYPTION"}; then
            error_exit "S3 upload failed"
        fi
        
        log "INFO" "Backup uploaded to s3://$S3_BUCKET/$s3_key"
    fi
}

# Upload to Google Cloud Storage
upload_to_gcs() {
    local backup_file="$1"
    local gcs_key="$2"
    
    if [[ -n "${GCS_BUCKET:-}" ]]; then
        log "INFO" "Uploading backup to Google Cloud Storage"
        
        if ! gsutil cp "$backup_file" "gs://$GCS_BUCKET/$gcs_key"; then
            error_exit "GCS upload failed"
        fi
        
        log "INFO" "Backup uploaded to gs://$GCS_BUCKET/$gcs_key"
    fi
}

# Cleanup old backups
cleanup_old_backups() {
    log "INFO" "Cleaning up old backups (older than $RETENTION_DAYS days)"
    
    # Local cleanup
    if [[ -n "${BACKUP_DIR:-}" ]] && [[ -d "$BACKUP_DIR" ]]; then
        find "$BACKUP_DIR" -type f -name "*.tar.gz*" -mtime +$RETENTION_DAYS -delete || \
            log "WARN" "Failed to clean up some local backup files"
    fi
    
    # S3 cleanup
    if [[ -n "${S3_BUCKET:-}" ]]; then
        local cutoff_date=$(date -d "-${RETENTION_DAYS} days" +%Y-%m-%d)
        aws s3api list-objects-v2 --bucket "$S3_BUCKET" --prefix "auth-service-backup-" \
            --query "Contents[?LastModified<='${cutoff_date}'].Key" --output text | \
        while read -r key; do
            if [[ -n "$key" ]]; then
                aws s3 rm "s3://$S3_BUCKET/$key" || log "WARN" "Failed to delete s3://$S3_BUCKET/$key"
            fi
        done
    fi
    
    # GCS cleanup
    if [[ -n "${GCS_BUCKET:-}" ]]; then
        gsutil -m rm -r "gs://$GCS_BUCKET/auth-service-backup-$(date -d "-${RETENTION_DAYS} days" +%Y-%m-%d)*" 2>/dev/null || \
            log "WARN" "No old GCS backups to clean up or cleanup failed"
    fi
    
    log "INFO" "Backup cleanup completed"
}

# Main backup function
perform_backup() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_name="auth-service-backup-$timestamp"
    local backup_path="${BACKUP_DIR:-/tmp/backups}/$backup_name"
    
    log "INFO" "Starting backup: $backup_name (type: $BACKUP_TYPE)"
    
    # Create backup directory
    mkdir -p "$backup_path"
    
    # Perform database backup based on type
    case "${DATABASE_TYPE:-}" in
        "mongodb")
            backup_mongodb "$backup_name" "$backup_path"
            ;;
        "postgresql")
            backup_postgresql "$backup_name" "$backup_path"
            ;;
        "mysql")
            backup_mysql "$backup_name" "$backup_path"
            ;;
        *)
            if [[ "$BACKUP_TYPE" == "full" ]]; then
                error_exit "Unknown database type: ${DATABASE_TYPE:-}"
            fi
            ;;
    esac
    
    # Always backup application data
    backup_application_data "$backup_name" "$backup_path"
    
    # Create backup manifest
    cat > "$backup_path/manifest.json" <<EOF
{
    "backup_name": "$backup_name",
    "backup_type": "$BACKUP_TYPE",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "database_type": "${DATABASE_TYPE:-none}",
    "compression_enabled": $COMPRESSION_ENABLED,
    "encryption_enabled": $ENCRYPTION_ENABLED,
    "environment": "${ENVIRONMENT:-unknown}",
    "version": "${APP_VERSION:-unknown}"
}
EOF
    
    local final_backup_file="$backup_path"
    
    # Compress if enabled
    if [[ "$COMPRESSION_ENABLED" == "true" ]]; then
        local compressed_file="${backup_path}.tar.gz"
        compress_backup "$backup_path" "$compressed_file"
        final_backup_file="$compressed_file"
    fi
    
    # Encrypt if enabled
    if [[ "$ENCRYPTION_ENABLED" == "true" ]]; then
        local encrypted_file="${final_backup_file}.enc"
        encrypt_backup "$final_backup_file" "$encrypted_file"
        final_backup_file="$encrypted_file"
    fi
    
    # Upload to cloud storage
    local cloud_key="$(basename "$final_backup_file")"
    upload_to_s3 "$final_backup_file" "$cloud_key"
    upload_to_gcs "$final_backup_file" "$cloud_key"
    
    # Get final backup size
    local backup_size=$(du -h "$final_backup_file" | cut -f1)
    
    success_notification "Backup completed successfully: $backup_name (size: $backup_size)"
    
    # Cleanup old backups
    cleanup_old_backups
}

# Restore function
restore_backup() {
    local backup_file="$1"
    local restore_type="${2:-full}"
    
    log "INFO" "Starting restore from: $backup_file"
    
    if [[ ! -f "$backup_file" ]]; then
        error_exit "Backup file not found: $backup_file"
    fi
    
    # TODO: Implement restore functionality
    # This would involve:
    # 1. Decrypting the backup if needed
    # 2. Decompressing the backup
    # 3. Restoring database based on type
    # 4. Restoring application data
    # 5. Validating the restore
    
    log "INFO" "Restore functionality not yet implemented"
    error_exit "Restore functionality coming soon"
}

# Verify backup
verify_backup() {
    local backup_file="$1"
    
    log "INFO" "Verifying backup: $backup_file"
    
    if [[ ! -f "$backup_file" ]]; then
        error_exit "Backup file not found: $backup_file"
    fi
    
    # Basic file integrity check
    if [[ "$backup_file" == *.tar.gz ]]; then
        if ! tar -tzf "$backup_file" >/dev/null 2>&1; then
            error_exit "Backup file is corrupted (tar verification failed)"
        fi
    fi
    
    # TODO: Implement deeper verification
    # - Check manifest.json
    # - Verify database dump integrity
    # - Check encryption integrity
    
    success_notification "Backup verification completed: $backup_file"
}

# Main execution
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                BACKUP_TYPE="$2"
                shift 2
                ;;
            --restore)
                restore_backup "$2" "${3:-full}"
                exit 0
                ;;
            --verify)
                verify_backup "$2"
                exit 0
                ;;
            --help)
                cat <<EOF
Auth Service Backup Script

Usage: $0 [OPTIONS]

Options:
    --type TYPE         Backup type (full, incremental, config)
    --restore FILE      Restore from backup file
    --verify FILE       Verify backup file integrity
    --help             Show this help message

Environment Variables:
    BACKUP_DIR         Local backup directory
    DATABASE_TYPE      Database type (mongodb, postgresql, mysql)
    DATABASE_URL       Database connection URL
    BACKUP_ENCRYPTION_KEY  Encryption key for backups
    S3_BUCKET         S3 bucket for backup storage
    GCS_BUCKET        Google Cloud Storage bucket
    RETENTION_DAYS    Days to keep backups (default: 30)

EOF
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
    
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Run backup
    check_prerequisites
    perform_backup
}

# Execute main function
main "$@"