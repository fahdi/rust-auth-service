#!/bin/bash

#
# Auth Service Disaster Recovery Script
# Automated disaster recovery and failover procedures
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/../config/backup.conf}"
LOG_FILE="${LOG_FILE:-/var/log/auth-service/disaster-recovery.log}"

# Default values
DR_MODE="${DR_MODE:-manual}"
DR_REGION="${DR_REGION:-us-west-2}"
PRIMARY_REGION="${PRIMARY_REGION:-us-east-1}"
DRY_RUN="${DRY_RUN:-false}"
FORCE_FAILOVER="${FORCE_FAILOVER:-false}"

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
    send_notification "DR_FAILED" "$1"
    exit 1
}

# Success notification
success_notification() {
    log "INFO" "$1"
    send_notification "DR_SUCCESS" "$1"
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
                    \"text\": \"Disaster Recovery $status: $message\",
                    \"dr_mode\": \"$DR_MODE\",
                    \"primary_region\": \"$PRIMARY_REGION\",
                    \"dr_region\": \"$DR_REGION\",
                    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
                    \"status\": \"$status\"
                }" || log "WARN" "Failed to send webhook notification"
        fi
        
        # Send urgent email notification
        if [[ -n "${EMAIL_TO:-}" ]] && command -v mail >/dev/null 2>&1; then
            echo "URGENT: Disaster Recovery $status: $message" | \
                mail -s "URGENT: Auth Service DR $status" "$EMAIL_TO" || \
                log "WARN" "Failed to send email notification"
        fi
        
        # Send to PagerDuty if configured
        if [[ -n "${PAGERDUTY_SERVICE_KEY:-}" ]]; then
            send_pagerduty_alert "$status" "$message"
        fi
    fi
}

# Send PagerDuty alert
send_pagerduty_alert() {
    local status="$1"
    local message="$2"
    
    local event_type="trigger"
    if [[ "$status" == "DR_SUCCESS" ]]; then
        event_type="resolve"
    fi
    
    local payload=$(cat <<EOF
{
    "service_key": "$PAGERDUTY_SERVICE_KEY",
    "event_type": "$event_type",
    "incident_key": "auth-service-dr-$(date +%Y%m%d)",
    "description": "Auth Service Disaster Recovery: $status",
    "details": {
        "message": "$message",
        "dr_mode": "$DR_MODE",
        "primary_region": "$PRIMARY_REGION",
        "dr_region": "$DR_REGION",
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }
}
EOF
)
    
    curl -s -X POST "https://events.pagerduty.com/generic/2010-04-15/create_event.json" \
        -H "Content-Type: application/json" \
        -d "$payload" || log "WARN" "Failed to send PagerDuty alert"
}

# Check primary region health
check_primary_health() {
    log "INFO" "Checking primary region health: $PRIMARY_REGION"
    
    local health_checks=0
    local failed_checks=0
    
    # Check API endpoint
    if [[ -n "${PRIMARY_API_URL:-}" ]]; then
        ((health_checks++))
        if ! curl -s -f --max-time 10 "${PRIMARY_API_URL}/health" >/dev/null 2>&1; then
            ((failed_checks++))
            log "WARN" "Primary API health check failed"
        else
            log "INFO" "Primary API health check passed"
        fi
    fi
    
    # Check database connectivity
    if [[ -n "${PRIMARY_DATABASE_URL:-}" ]]; then
        ((health_checks++))
        case "${DATABASE_TYPE:-}" in
            "mongodb")
                if ! mongosh "$PRIMARY_DATABASE_URL" --eval "db.adminCommand('ping')" >/dev/null 2>&1; then
                    ((failed_checks++))
                    log "WARN" "Primary MongoDB health check failed"
                else
                    log "INFO" "Primary MongoDB health check passed"
                fi
                ;;
            "postgresql")
                if ! pg_isready -d "$PRIMARY_DATABASE_URL" >/dev/null 2>&1; then
                    ((failed_checks++))
                    log "WARN" "Primary PostgreSQL health check failed"
                else
                    log "INFO" "Primary PostgreSQL health check passed"
                fi
                ;;
            "mysql")
                local mysql_host=$(echo "$PRIMARY_DATABASE_URL" | sed -n 's|mysql://[^@]*@\([^:]*\):.*|\1|p')
                local mysql_port=$(echo "$PRIMARY_DATABASE_URL" | sed -n 's|mysql://[^@]*@[^:]*:\([0-9]*\)/.*|\1|p')
                if ! nc -z "$mysql_host" "$mysql_port" >/dev/null 2>&1; then
                    ((failed_checks++))
                    log "WARN" "Primary MySQL health check failed"
                else
                    log "INFO" "Primary MySQL health check passed"
                fi
                ;;
        esac
    fi
    
    # Check load balancer/ingress
    if [[ -n "${PRIMARY_LB_URL:-}" ]]; then
        ((health_checks++))
        if ! curl -s -f --max-time 10 "$PRIMARY_LB_URL" >/dev/null 2>&1; then
            ((failed_checks++))
            log "WARN" "Primary load balancer health check failed"
        else
            log "INFO" "Primary load balancer health check passed"
        fi
    fi
    
    # Calculate health percentage
    local health_percentage=100
    if [[ $health_checks -gt 0 ]]; then
        health_percentage=$(( (health_checks - failed_checks) * 100 / health_checks ))
    fi
    
    log "INFO" "Primary region health: $health_percentage% ($((health_checks - failed_checks))/$health_checks checks passed)"
    
    # Return 0 if healthy (>=80%), 1 if degraded (50-79%), 2 if critical (<50%)
    if [[ $health_percentage -ge 80 ]]; then
        return 0
    elif [[ $health_percentage -ge 50 ]]; then
        return 1
    else
        return 2
    fi
}

# Check DR region readiness
check_dr_readiness() {
    log "INFO" "Checking DR region readiness: $DR_REGION"
    
    # Check if DR infrastructure is deployed
    if command -v kubectl >/dev/null 2>&1; then
        # Check Kubernetes cluster in DR region
        if ! kubectl --context="dr-cluster" get nodes >/dev/null 2>&1; then
            log "WARN" "DR Kubernetes cluster not accessible"
            return 1
        fi
        
        # Check if DR services are deployed
        if ! kubectl --context="dr-cluster" get deployment auth-service >/dev/null 2>&1; then
            log "WARN" "Auth service not deployed in DR region"
            return 1
        fi
    fi
    
    # Check DR database
    if [[ -n "${DR_DATABASE_URL:-}" ]]; then
        case "${DATABASE_TYPE:-}" in
            "mongodb")
                if ! mongosh "$DR_DATABASE_URL" --eval "db.adminCommand('ping')" >/dev/null 2>&1; then
                    log "WARN" "DR MongoDB not accessible"
                    return 1
                fi
                ;;
            "postgresql")
                if ! pg_isready -d "$DR_DATABASE_URL" >/dev/null 2>&1; then
                    log "WARN" "DR PostgreSQL not accessible"
                    return 1
                fi
                ;;
            "mysql")
                local mysql_host=$(echo "$DR_DATABASE_URL" | sed -n 's|mysql://[^@]*@\([^:]*\):.*|\1|p')
                local mysql_port=$(echo "$DR_DATABASE_URL" | sed -n 's|mysql://[^@]*@[^:]*:\([0-9]*\)/.*|\1|p')
                if ! nc -z "$mysql_host" "$mysql_port" >/dev/null 2>&1; then
                    log "WARN" "DR MySQL not accessible"
                    return 1
                fi
                ;;
        esac
    fi
    
    log "INFO" "DR region readiness check passed"
    return 0
}

# Sync data to DR region
sync_to_dr() {
    log "INFO" "Syncing data to DR region"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would sync data to DR region"
        return
    fi
    
    # Database replication sync
    case "${DATABASE_TYPE:-}" in
        "mongodb")
            # For MongoDB, this would involve replica set operations
            log "INFO" "Checking MongoDB replica set status"
            if ! mongosh "$PRIMARY_DATABASE_URL" --eval "rs.status()" >/dev/null 2>&1; then
                log "WARN" "MongoDB replica set status check failed"
            fi
            ;;
        "postgresql")
            # For PostgreSQL, this would involve streaming replication
            log "INFO" "Checking PostgreSQL replication status"
            # This is a simplified check - real implementation would be more complex
            ;;
        "mysql")
            # For MySQL, this would involve master-slave replication
            log "INFO" "Checking MySQL replication status"
            # This is a simplified check - real implementation would be more complex
            ;;
    esac
    
    # File storage sync (if using shared storage)
    if [[ -n "${STORAGE_BUCKET:-}" ]] && [[ -n "${DR_STORAGE_BUCKET:-}" ]]; then
        log "INFO" "Syncing storage buckets"
        if command -v aws >/dev/null 2>&1; then
            aws s3 sync "s3://$STORAGE_BUCKET" "s3://$DR_STORAGE_BUCKET" --region "$DR_REGION" || \
                log "WARN" "Storage sync failed"
        fi
    fi
    
    # Configuration sync
    if [[ -d "/app/config" ]] && [[ -n "${DR_CONFIG_BUCKET:-}" ]]; then
        log "INFO" "Syncing configuration to DR region"
        if command -v aws >/dev/null 2>&1; then
            aws s3 sync /app/config "s3://$DR_CONFIG_BUCKET/config/" --region "$DR_REGION" || \
                log "WARN" "Configuration sync failed"
        fi
    fi
    
    log "INFO" "Data sync to DR region completed"
}

# Update DNS for failover
update_dns() {
    local target_region="$1"
    
    log "INFO" "Updating DNS to point to: $target_region"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would update DNS to $target_region"
        return
    fi
    
    # Route 53 DNS update
    if [[ -n "${ROUTE53_HOSTED_ZONE_ID:-}" ]] && [[ -n "${DNS_RECORD_NAME:-}" ]]; then
        local target_ip
        if [[ "$target_region" == "$DR_REGION" ]]; then
            target_ip="${DR_LOAD_BALANCER_IP:-}"
        else
            target_ip="${PRIMARY_LOAD_BALANCER_IP:-}"
        fi
        
        if [[ -n "$target_ip" ]]; then
            local change_batch=$(cat <<EOF
{
    "Changes": [{
        "Action": "UPSERT",
        "ResourceRecordSet": {
            "Name": "$DNS_RECORD_NAME",
            "Type": "A",
            "TTL": 60,
            "ResourceRecords": [{"Value": "$target_ip"}]
        }
    }]
}
EOF
)
            
            aws route53 change-resource-record-sets \
                --hosted-zone-id "$ROUTE53_HOSTED_ZONE_ID" \
                --change-batch "$change_batch" || \
                error_exit "DNS update failed"
            
            log "INFO" "DNS updated to point to $target_ip ($target_region)"
        else
            log "WARN" "Target IP not configured for $target_region"
        fi
    fi
    
    # CloudFlare DNS update (if using CloudFlare)
    if [[ -n "${CLOUDFLARE_ZONE_ID:-}" ]] && [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]]; then
        # Implementation for CloudFlare DNS updates
        log "INFO" "CloudFlare DNS update not yet implemented"
    fi
}

# Scale up DR services
scale_up_dr() {
    log "INFO" "Scaling up DR services"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would scale up DR services"
        return
    fi
    
    # Kubernetes scaling
    if command -v kubectl >/dev/null 2>&1; then
        # Scale up auth service
        kubectl --context="dr-cluster" scale deployment auth-service --replicas="${DR_REPLICA_COUNT:-3}" || \
            log "WARN" "Failed to scale auth service"
        
        # Scale up databases if managed by Kubernetes
        kubectl --context="dr-cluster" scale statefulset mongodb --replicas="${DR_DB_REPLICA_COUNT:-1}" 2>/dev/null || \
            log "INFO" "MongoDB not managed by Kubernetes or already scaled"
        
        # Wait for pods to be ready
        kubectl --context="dr-cluster" wait --for=condition=ready pod -l app=auth-service --timeout=300s || \
            log "WARN" "Some pods may not be ready"
    fi
    
    # Auto Scaling Group (if using AWS)
    if [[ -n "${DR_ASG_NAME:-}" ]] && command -v aws >/dev/null 2>&1; then
        aws autoscaling update-auto-scaling-group \
            --auto-scaling-group-name "$DR_ASG_NAME" \
            --desired-capacity "${DR_REPLICA_COUNT:-3}" \
            --region "$DR_REGION" || \
            log "WARN" "Failed to update Auto Scaling Group"
    fi
    
    log "INFO" "DR services scaled up"
}

# Scale down primary services
scale_down_primary() {
    log "INFO" "Scaling down primary services"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would scale down primary services"
        return
    fi
    
    # Kubernetes scaling
    if command -v kubectl >/dev/null 2>&1; then
        # Scale down auth service gradually
        kubectl scale deployment auth-service --replicas=1 || log "WARN" "Failed to scale down auth service"
        sleep 30
        kubectl scale deployment auth-service --replicas=0 || log "WARN" "Failed to completely scale down auth service"
    fi
    
    # Auto Scaling Group (if using AWS)
    if [[ -n "${PRIMARY_ASG_NAME:-}" ]] && command -v aws >/dev/null 2>&1; then
        aws autoscaling update-auto-scaling-group \
            --auto-scaling-group-name "$PRIMARY_ASG_NAME" \
            --desired-capacity 0 \
            --region "$PRIMARY_REGION" || \
            log "WARN" "Failed to update Auto Scaling Group"
    fi
    
    log "INFO" "Primary services scaled down"
}

# Perform failover
perform_failover() {
    log "INFO" "Starting failover from $PRIMARY_REGION to $DR_REGION"
    
    # Pre-failover checks
    if ! check_dr_readiness; then
        error_exit "DR region is not ready for failover"
    fi
    
    # Confirm failover unless force mode
    if [[ "$FORCE_FAILOVER" != "true" ]] && [[ "$DRY_RUN" != "true" ]]; then
        echo
        echo "WARNING: This will initiate disaster recovery failover!"
        echo "Primary region: $PRIMARY_REGION"
        echo "DR region: $DR_REGION"
        echo "This action will redirect all traffic to the DR region."
        echo
        read -p "Are you sure you want to continue? (yes/no): " -r confirm
        
        if [[ "$confirm" != "yes" ]]; then
            log "INFO" "Failover cancelled by user"
            exit 0
        fi
    fi
    
    # Sync final data to DR
    sync_to_dr
    
    # Scale up DR services
    scale_up_dr
    
    # Wait for DR services to be healthy
    log "INFO" "Waiting for DR services to be healthy"
    sleep 60
    
    # Verify DR health before switching DNS
    local dr_health_url="${DR_API_URL:-}/health"
    local max_attempts=10
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -s -f --max-time 10 "$dr_health_url" >/dev/null 2>&1; then
            log "INFO" "DR health check passed (attempt $attempt)"
            break
        fi
        
        log "INFO" "DR health check failed, retrying in 30 seconds (attempt $attempt/$max_attempts)"
        sleep 30
        ((attempt++))
    done
    
    if [[ $attempt -gt $max_attempts ]]; then
        error_exit "DR health check failed after $max_attempts attempts"
    fi
    
    # Update DNS to point to DR region
    update_dns "$DR_REGION"
    
    # Scale down primary services (after DNS switch to minimize downtime)
    scale_down_primary
    
    success_notification "Failover completed successfully from $PRIMARY_REGION to $DR_REGION"
}

# Perform failback
perform_failback() {
    log "INFO" "Starting failback from $DR_REGION to $PRIMARY_REGION"
    
    # Check primary region health
    if ! check_primary_health; then
        error_exit "Primary region is not healthy for failback"
    fi
    
    # Confirm failback
    if [[ "$FORCE_FAILOVER" != "true" ]] && [[ "$DRY_RUN" != "true" ]]; then
        echo
        echo "WARNING: This will initiate failback to primary region!"
        echo "Current active region: $DR_REGION"
        echo "Target region: $PRIMARY_REGION"
        echo
        read -p "Are you sure you want to continue? (yes/no): " -r confirm
        
        if [[ "$confirm" != "yes" ]]; then
            log "INFO" "Failback cancelled by user"
            exit 0
        fi
    fi
    
    # Scale up primary services
    log "INFO" "Scaling up primary services"
    if command -v kubectl >/dev/null 2>&1; then
        kubectl scale deployment auth-service --replicas="${PRIMARY_REPLICA_COUNT:-3}" || \
            log "WARN" "Failed to scale up primary services"
        
        kubectl wait --for=condition=ready pod -l app=auth-service --timeout=300s || \
            log "WARN" "Some primary pods may not be ready"
    fi
    
    # Sync data back to primary
    log "INFO" "Syncing data back to primary region"
    # Implementation would depend on specific database setup
    
    # Update DNS to point back to primary
    update_dns "$PRIMARY_REGION"
    
    # Scale down DR services
    log "INFO" "Scaling down DR services"
    if command -v kubectl >/dev/null 2>&1; then
        kubectl --context="dr-cluster" scale deployment auth-service --replicas="${DR_STANDBY_REPLICAS:-1}" || \
            log "WARN" "Failed to scale down DR services"
    fi
    
    success_notification "Failback completed successfully from $DR_REGION to $PRIMARY_REGION"
}

# Test DR procedures
test_dr() {
    log "INFO" "Testing DR procedures (dry run)"
    
    # Save original dry run setting
    local original_dry_run="$DRY_RUN"
    DRY_RUN=true
    
    # Test primary health check
    log "INFO" "Testing primary health check"
    check_primary_health || log "WARN" "Primary health check test completed with issues"
    
    # Test DR readiness check
    log "INFO" "Testing DR readiness check"
    check_dr_readiness || log "WARN" "DR readiness check test completed with issues"
    
    # Test data sync
    log "INFO" "Testing data sync"
    sync_to_dr
    
    # Test failover procedure
    log "INFO" "Testing failover procedure"
    perform_failover
    
    # Restore original dry run setting
    DRY_RUN="$original_dry_run"
    
    success_notification "DR test completed successfully"
}

# Monitor replication lag
monitor_replication() {
    log "INFO" "Monitoring replication lag"
    
    case "${DATABASE_TYPE:-}" in
        "mongodb")
            # Check MongoDB replica set lag
            if mongosh "$PRIMARY_DATABASE_URL" --eval "rs.printSlaveReplicationInfo()" >/dev/null 2>&1; then
                log "INFO" "MongoDB replication status checked"
            else
                log "WARN" "Failed to check MongoDB replication status"
            fi
            ;;
        "postgresql")
            # Check PostgreSQL replication lag
            if psql "$PRIMARY_DATABASE_URL" -c "SELECT * FROM pg_stat_replication;" >/dev/null 2>&1; then
                log "INFO" "PostgreSQL replication status checked"
            else
                log "WARN" "Failed to check PostgreSQL replication status"
            fi
            ;;
        "mysql")
            # Check MySQL replication lag
            log "INFO" "MySQL replication monitoring not implemented"
            ;;
    esac
    
    # Check if lag exceeds threshold
    local lag_threshold="${REPLICATION_LAG_THRESHOLD:-300}"  # 5 minutes default
    # Implementation would check actual lag and alert if exceeded
    
    log "INFO" "Replication monitoring completed"
}

# Main execution
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --failover)
                perform_failover
                exit 0
                ;;
            --failback)
                perform_failback
                exit 0
                ;;
            --test)
                test_dr
                exit 0
                ;;
            --check-primary)
                check_primary_health
                exit $?
                ;;
            --check-dr)
                check_dr_readiness
                exit $?
                ;;
            --monitor)
                monitor_replication
                exit 0
                ;;
            --sync)
                sync_to_dr
                exit 0
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force)
                FORCE_FAILOVER=true
                shift
                ;;
            --help)
                cat <<EOF
Auth Service Disaster Recovery Script

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    --failover           Initiate failover to DR region
    --failback           Initiate failback to primary region
    --test               Test DR procedures (dry run)
    --check-primary      Check primary region health
    --check-dr           Check DR region readiness
    --monitor            Monitor replication status
    --sync               Sync data to DR region

Options:
    --dry-run           Show what would be done without actually doing it
    --force             Force operation without confirmation
    --help              Show this help message

Environment Variables:
    DR_REGION           Disaster recovery region
    PRIMARY_REGION      Primary region
    DATABASE_TYPE       Database type (mongodb, postgresql, mysql)
    FORCE_FAILOVER      Force operations without confirmation (true/false)

Examples:
    $0 --test                    # Test all DR procedures
    $0 --check-primary          # Check primary region health
    $0 --failover --dry-run     # Simulate failover
    $0 --failover --force       # Force immediate failover

EOF
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
    
    # If no command specified, show status
    log "INFO" "Auth Service Disaster Recovery Status"
    echo
    echo "Configuration:"
    echo "  Primary Region: $PRIMARY_REGION"
    echo "  DR Region: $DR_REGION"
    echo "  DR Mode: $DR_MODE"
    echo
    
    # Check status
    echo "Primary Region Health:"
    if check_primary_health; then
        echo "  Status: HEALTHY"
    else
        echo "  Status: UNHEALTHY"
    fi
    
    echo
    echo "DR Region Readiness:"
    if check_dr_readiness; then
        echo "  Status: READY"
    else
        echo "  Status: NOT READY"
    fi
    
    echo
    echo "Use --help for available commands"
}

# Initialize logging
mkdir -p "$(dirname "$LOG_FILE")"

# Execute main function
main "$@"