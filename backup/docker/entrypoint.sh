#!/bin/bash

#
# Backup Container Entrypoint
# Sets up the backup environment and starts the specified service
#

set -euo pipefail

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ENTRYPOINT] $*"
}

# Initialize backup environment
init_backup_env() {
    log "Initializing backup environment"
    
    # Create required directories
    mkdir -p /var/backups/auth-service
    mkdir -p /var/log/auth-service
    
    # Set proper permissions
    chmod 755 /var/backups/auth-service
    chmod 755 /var/log/auth-service
    
    # Initialize log file
    touch /var/log/auth-service/backup.log
    chmod 644 /var/log/auth-service/backup.log
    
    # Test backup script
    if /app/backup/scripts/backup.sh --help >/dev/null 2>&1; then
        log "Backup script is working"
    else
        log "ERROR: Backup script test failed"
        exit 1
    fi
    
    # Test restore script
    if /app/backup/scripts/restore.sh --help >/dev/null 2>&1; then
        log "Restore script is working"
    else
        log "ERROR: Restore script test failed"
        exit 1
    fi
    
    # Test disaster recovery script
    if /app/backup/scripts/disaster-recovery.sh --help >/dev/null 2>&1; then
        log "Disaster recovery script is working"
    else
        log "ERROR: Disaster recovery script test failed"
        exit 1
    fi
    
    log "Backup environment initialized successfully"
}

# Setup AWS credentials if provided
setup_aws() {
    if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]] && [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
        log "Setting up AWS credentials"
        mkdir -p ~/.aws
        cat > ~/.aws/credentials <<EOF
[default]
aws_access_key_id = $AWS_ACCESS_KEY_ID
aws_secret_access_key = $AWS_SECRET_ACCESS_KEY
EOF
        
        if [[ -n "${AWS_DEFAULT_REGION:-}" ]]; then
            cat > ~/.aws/config <<EOF
[default]
region = $AWS_DEFAULT_REGION
EOF
        fi
        
        chmod 600 ~/.aws/credentials ~/.aws/config
        log "AWS credentials configured"
    fi
}

# Setup Google Cloud credentials if provided
setup_gcp() {
    if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]] && [[ -f "$GOOGLE_APPLICATION_CREDENTIALS" ]]; then
        log "Setting up Google Cloud credentials"
        gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS"
        log "Google Cloud credentials configured"
    fi
}

# Setup cron jobs
setup_cron() {
    log "Setting up cron jobs"
    
    # Start rsyslog for cron logging
    rsyslogd
    
    # Install crontab if it exists
    if [[ -f /app/backup/cron/backup-crontab ]]; then
        crontab /app/backup/cron/backup-crontab
        log "Backup crontab installed"
    fi
    
    # Create cron log
    touch /var/log/cron.log
    chmod 644 /var/log/cron.log
    
    log "Cron setup completed"
}

# Validate environment
validate_environment() {
    log "Validating environment"
    
    # Check required tools
    local required_tools=("mongodump" "mongorestore" "pg_dump" "psql" "mysqldump" "mysql" "aws" "gsutil" "jq" "curl")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log "WARNING: $tool not found"
        else
            log "$tool is available"
        fi
    done
    
    # Check configuration
    if [[ -f "${CONFIG_FILE:-/app/backup/config/backup.conf}" ]]; then
        log "Configuration file found"
    else
        log "WARNING: Configuration file not found"
    fi
    
    # Check backup directory
    if [[ -w "${BACKUP_DIR:-/var/backups/auth-service}" ]]; then
        log "Backup directory is writable"
    else
        log "ERROR: Backup directory is not writable"
        exit 1
    fi
    
    log "Environment validation completed"
}

# Run one-time backup
run_backup() {
    local backup_type="${1:-full}"
    log "Running one-time backup (type: $backup_type)"
    
    /app/backup/scripts/backup.sh --type "$backup_type" || {
        log "ERROR: Backup failed"
        exit 1
    }
    
    log "One-time backup completed"
}

# Run restore
run_restore() {
    local backup_file="$1"
    local restore_options="${2:-}"
    
    log "Running restore from: $backup_file"
    
    if [[ ! -f "$backup_file" ]]; then
        log "ERROR: Backup file not found: $backup_file"
        exit 1
    fi
    
    /app/backup/scripts/restore.sh --backup-file "$backup_file" $restore_options || {
        log "ERROR: Restore failed"
        exit 1
    }
    
    log "Restore completed"
}

# Run disaster recovery
run_dr() {
    local dr_command="$1"
    local dr_options="${2:-}"
    
    log "Running disaster recovery: $dr_command"
    
    /app/backup/scripts/disaster-recovery.sh "$dr_command" $dr_options || {
        log "ERROR: Disaster recovery operation failed"
        exit 1
    }
    
    log "Disaster recovery operation completed"
}

# Monitor mode
run_monitor() {
    log "Starting backup monitoring mode"
    
    while true; do
        # Check backup health
        if ! /app/backup/scripts/backup.sh --type config --dry-run >/dev/null 2>&1; then
            log "WARNING: Backup system health check failed"
        fi
        
        # Check disk space
        local available_space=$(df "${BACKUP_DIR:-/var/backups/auth-service}" | awk 'NR==2 {print $4}')
        if [[ "$available_space" -lt 1048576 ]]; then  # Less than 1GB
            log "WARNING: Low disk space: ${available_space}KB available"
        fi
        
        # Check old backups
        local old_backups=$(find "${BACKUP_DIR:-/var/backups/auth-service}" -name "*.tar.gz*" -mtime +30 | wc -l)
        if [[ "$old_backups" -gt 0 ]]; then
            log "INFO: Found $old_backups old backups (>30 days)"
        fi
        
        sleep 3600  # Check every hour
    done
}

# Main execution
main() {
    log "Starting Auth Service Backup Container"
    
    # Parse command line arguments
    case "${1:-cron}" in
        "cron")
            init_backup_env
            setup_aws
            setup_gcp
            validate_environment
            setup_cron
            log "Starting cron daemon"
            exec cron -f
            ;;
        "backup")
            init_backup_env
            setup_aws
            setup_gcp
            validate_environment
            run_backup "${2:-full}"
            ;;
        "restore")
            if [[ -z "${2:-}" ]]; then
                log "ERROR: Backup file required for restore"
                exit 1
            fi
            init_backup_env
            setup_aws
            setup_gcp
            validate_environment
            run_restore "$2" "${3:-}"
            ;;
        "dr")
            if [[ -z "${2:-}" ]]; then
                log "ERROR: DR command required"
                exit 1
            fi
            init_backup_env
            setup_aws
            setup_gcp
            validate_environment
            run_dr "$2" "${3:-}"
            ;;
        "monitor")
            init_backup_env
            setup_aws
            setup_gcp
            validate_environment
            run_monitor
            ;;
        "test")
            init_backup_env
            setup_aws
            setup_gcp
            validate_environment
            log "Running backup system tests"
            /app/backup/scripts/backup.sh --type config --dry-run
            /app/backup/scripts/disaster-recovery.sh --test
            log "Backup system tests completed"
            ;;
        "shell")
            init_backup_env
            setup_aws
            setup_gcp
            log "Starting interactive shell"
            exec /bin/bash
            ;;
        *)
            log "ERROR: Unknown command: $1"
            echo "Usage: $0 [cron|backup|restore|dr|monitor|test|shell]"
            echo
            echo "Commands:"
            echo "  cron               Start cron daemon for scheduled backups"
            echo "  backup [type]      Run one-time backup (full, incremental, config)"
            echo "  restore FILE       Restore from backup file"
            echo "  dr COMMAND         Run disaster recovery command"
            echo "  monitor            Start monitoring mode"
            echo "  test               Run backup system tests"
            echo "  shell              Start interactive shell"
            exit 1
            ;;
    esac
}

# Handle signals
trap 'log "Received SIGTERM, shutting down gracefully"; exit 0' TERM
trap 'log "Received SIGINT, shutting down gracefully"; exit 0' INT

# Execute main function
main "$@"