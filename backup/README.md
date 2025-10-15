# Auth Service Backup and Disaster Recovery

Comprehensive backup and disaster recovery solution for the Auth Service with automated scheduling, multi-cloud storage, and failover capabilities.

## Overview

This backup system provides:

- **Automated Backups**: Scheduled full, incremental, and configuration backups
- **Multi-Cloud Storage**: Support for AWS S3, Google Cloud Storage, and local storage
- **Disaster Recovery**: Automated failover and failback procedures
- **Monitoring**: Health checks and alerting for backup operations
- **Security**: Encryption, compression, and secure credential management

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Auth Service  │───▶│  Backup System  │───▶│  Cloud Storage  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   DR Region     │
                       └─────────────────┘
```

## Quick Start

### 1. Using Docker Compose

```bash
# Start backup scheduler
docker-compose -f docker-compose.backup.yml up -d backup-scheduler

# Run one-time backup
docker-compose -f docker-compose.backup.yml run --rm backup-scheduler backup full

# List available backups
docker-compose -f docker-compose.backup.yml run --rm backup-restore restore --list

# Restore from backup
docker-compose -f docker-compose.backup.yml run --rm backup-restore restore \
  --backup-file /var/backups/auth-service/auth-service-backup-20240115_020000.tar.gz.enc
```

### 2. Using Scripts Directly

```bash
# Full backup
./backup/scripts/backup.sh --type full

# Restore from backup
./backup/scripts/restore.sh --backup-file /path/to/backup.tar.gz.enc

# Test disaster recovery
./backup/scripts/disaster-recovery.sh --test
```

## Configuration

### Environment Variables

```bash
# Database
DATABASE_TYPE=mongodb
DATABASE_URL=mongodb://localhost:27017/auth_service
MONGODB_URL=mongodb://localhost:27017/auth_service

# Backup settings
BACKUP_DIR=/var/backups/auth-service
RETENTION_DAYS=30
COMPRESSION_ENABLED=true
ENCRYPTION_ENABLED=true
BACKUP_ENCRYPTION_KEY=your-encryption-key

# Cloud storage
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
S3_BUCKET=auth-service-backups
GCS_BUCKET=auth-service-backups-gcs

# Notifications
NOTIFICATION_ENABLED=true
WEBHOOK_URL=https://hooks.slack.com/your-webhook
EMAIL_TO=admin@yourcompany.com
PAGERDUTY_SERVICE_KEY=your-pagerduty-key

# Disaster recovery
DR_ENABLED=true
DR_REGION=us-west-2
PRIMARY_REGION=us-east-1
```

### Configuration File

Edit `backup/config/backup.conf`:

```bash
# Backup schedule
BACKUP_SCHEDULE_FULL="0 2 * * *"      # Daily at 2 AM
BACKUP_SCHEDULE_INCREMENTAL="0 */6 * * *"  # Every 6 hours
BACKUP_SCHEDULE_CONFIG="0 4 * * 0"     # Weekly on Sunday

# Storage settings
S3_STORAGE_CLASS="STANDARD_IA"
S3_SERVER_SIDE_ENCRYPTION="AES256"

# Monitoring
BACKUP_METRICS_ENABLED=true
PROMETHEUS_PUSHGATEWAY_URL=http://pushgateway:9091
```

## Backup Types

### Full Backup
- Complete database dump
- Application configuration
- SSL certificates
- Recent logs
- Scheduled daily at 2 AM

### Incremental Backup
- Database changes since last backup
- Application logs
- Scheduled every 6 hours

### Configuration Backup
- Application configuration files
- Environment settings
- SSL certificates
- Scheduled weekly

## Storage Destinations

### Local Storage
```bash
BACKUP_DIR=/var/backups/auth-service
```

### AWS S3
```bash
S3_BUCKET=auth-service-backups
S3_STORAGE_CLASS=STANDARD_IA
S3_SERVER_SIDE_ENCRYPTION=AES256
```

### Google Cloud Storage
```bash
GCS_BUCKET=auth-service-backups-gcs
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

## Disaster Recovery

### Automatic Failover

The system monitors primary region health and can automatically failover to DR region:

```bash
# Check primary region health
./backup/scripts/disaster-recovery.sh --check-primary

# Check DR region readiness
./backup/scripts/disaster-recovery.sh --check-dr

# Initiate failover
./backup/scripts/disaster-recovery.sh --failover

# Failback to primary
./backup/scripts/disaster-recovery.sh --failback
```

### Manual Failover

```bash
# Test failover procedures
./backup/scripts/disaster-recovery.sh --test

# Force immediate failover
./backup/scripts/disaster-recovery.sh --failover --force

# Dry run failover
./backup/scripts/disaster-recovery.sh --failover --dry-run
```

## Monitoring and Alerting

### Health Checks

- Backup system health
- Database connectivity
- Cloud storage access
- Disk space monitoring
- Replication lag monitoring

### Notifications

The system sends notifications via:

- **Slack**: Real-time backup status
- **Email**: Daily/weekly reports and failures
- **PagerDuty**: Critical alerts and DR events
- **Webhooks**: Custom integrations

### Metrics

Prometheus metrics are exposed for:

- Backup success/failure rates
- Backup duration and size
- Storage usage
- Replication lag
- System health

## Security

### Encryption

All backups are encrypted using AES-256-CBC:

```bash
ENCRYPTION_ENABLED=true
BACKUP_ENCRYPTION_KEY=your-strong-encryption-key
```

### Access Control

- Non-root container execution
- Separate backup user with minimal privileges
- Secure credential management
- Network isolation

### Audit

- Comprehensive logging
- Backup integrity verification
- Access logging
- Change tracking

## Restore Procedures

### Database Restore

```bash
# List available backups
./backup/scripts/restore.sh --list

# Restore latest backup
./backup/scripts/restore.sh --backup-file /path/to/latest-backup.tar.gz.enc

# Force restore (overwrites existing data)
./backup/scripts/restore.sh --backup-file /path/to/backup.tar.gz.enc --force

# Dry run restore
./backup/scripts/restore.sh --backup-file /path/to/backup.tar.gz.enc --dry-run
```

### Point-in-Time Recovery

For MongoDB with replica sets:
```bash
# Restore to specific timestamp
mongorestore --uri="mongodb://localhost:27017" --oplogReplay --oplogLimit=1640995200:1
```

For PostgreSQL with WAL:
```bash
# Configure recovery target
echo "recovery_target_time = '2024-01-15 14:30:00'" >> recovery.conf
```

## Troubleshooting

### Common Issues

1. **Backup Fails with Permission Error**
   ```bash
   # Check backup directory permissions
   ls -la /var/backups/auth-service
   
   # Fix permissions
   sudo chown -R backup:backup /var/backups/auth-service
   ```

2. **Cloud Upload Fails**
   ```bash
   # Test AWS credentials
   aws s3 ls s3://your-backup-bucket/
   
   # Test GCS credentials
   gsutil ls gs://your-backup-bucket/
   ```

3. **Restore Fails**
   ```bash
   # Verify backup integrity
   ./backup/scripts/restore.sh --verify /path/to/backup.tar.gz.enc
   
   # Check database connectivity
   mongosh $DATABASE_URL --eval "db.adminCommand('ping')"
   ```

### Logs

Check logs for debugging:

```bash
# Backup logs
tail -f /var/log/auth-service/backup.log

# Restore logs
tail -f /var/log/auth-service/restore.log

# Disaster recovery logs
tail -f /var/log/auth-service/disaster-recovery.log
```

## Testing

### Regular Testing

```bash
# Test backup system
./backup/scripts/backup.sh --type config --dry-run

# Test restore procedures
./backup/scripts/restore.sh --backup-file /path/to/test-backup.tar.gz --dry-run

# Test disaster recovery
./backup/scripts/disaster-recovery.sh --test
```

### Monthly DR Tests

1. Restore latest backup to test environment
2. Verify application functionality
3. Test failover procedures
4. Document results and improvements

## Kubernetes Integration

### Backup CronJobs

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: auth-service-backup
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: auth-service-backup:latest
            command: ["/app/backup/scripts/backup.sh", "--type", "full"]
```

### Helm Chart

```bash
# Install backup system
helm install auth-service-backup ./helm/backup-chart/

# Upgrade with new configuration
helm upgrade auth-service-backup ./helm/backup-chart/ \
  --set backup.schedule="0 1 * * *" \
  --set storage.s3.bucket="new-backup-bucket"
```

## Performance Optimization

### Backup Performance

- Use incremental backups for large databases
- Compress backups to reduce storage costs
- Parallel uploads to multiple storage destinations
- Database read replicas for backup operations

### Restore Performance

- Parallel restore operations where possible
- Staged restore for large datasets
- Network optimization for cloud downloads
- Pre-warmed DR environment

## Compliance

### Data Retention

- Configurable retention policies
- Automatic cleanup of old backups
- Compliance with GDPR, HIPAA, SOX requirements
- Audit trail for all operations

### Encryption Standards

- AES-256 encryption for data at rest
- TLS 1.2+ for data in transit
- Key rotation capabilities
- HSM integration support

## Support

For issues or questions:

1. Check the troubleshooting section
2. Review logs in `/var/log/auth-service/`
3. Test configurations with `--dry-run`
4. Contact the DevOps team for complex issues

## Contributing

When modifying backup scripts:

1. Test with `--dry-run` first
2. Update documentation
3. Add appropriate logging
4. Follow security best practices
5. Test restore procedures