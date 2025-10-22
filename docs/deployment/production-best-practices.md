# Production Best Practices Guide

This guide covers essential best practices for deploying and operating the Rust Auth Service in production environments.

## 🛡️ Security Hardening

### SSL/TLS Configuration

#### Certificate Management
```bash
# Use strong cipher suites
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

# Enable HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

# Certificate pinning
add_header Public-Key-Pins 'pin-sha256="base64+primary=="; pin-sha256="base64+backup=="; max-age=5184000; includeSubDomains';
```

#### Automated Certificate Renewal
```bash
# Let's Encrypt with cert-manager
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@yourdomain.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

### Secrets Management

#### Kubernetes Secrets Best Practices
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: rust-auth-service-secrets
  namespace: auth-service
type: Opaque
data:
  # Use external secret management
  jwt-secret: <base64-encoded-secret>
  database-password: <base64-encoded-password>
stringData:
  # Never store secrets in plain text in manifests
  # Use external tools like:
  # - HashiCorp Vault
  # - AWS Secrets Manager
  # - Azure Key Vault
  # - Google Secret Manager
```

#### Environment-Specific Secret Rotation
```bash
#!/bin/bash
# Secret rotation script
NEW_JWT_SECRET=$(openssl rand -base64 32)
NEW_DB_PASSWORD=$(openssl rand -base64 16)

# Update secrets in external vault
vault kv put secret/auth-service \
  jwt_secret="$NEW_JWT_SECRET" \
  database_password="$NEW_DB_PASSWORD"

# Trigger rolling update
kubectl rollout restart deployment/rust-auth-service -n auth-service
```

### Network Security

#### Network Policies
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: auth-service-network-policy
  namespace: auth-service
spec:
  podSelector:
    matchLabels:
      app: rust-auth-service
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8090
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 5432  # PostgreSQL
    - protocol: TCP
      port: 6379  # Redis
    - protocol: TCP
      port: 443   # HTTPS (email, monitoring)
    - protocol: TCP
      port: 53    # DNS
    - protocol: UDP
      port: 53    # DNS
```

#### Firewall Rules
```bash
# Cloud provider firewall examples

# AWS Security Groups
aws ec2 authorize-security-group-ingress \
  --group-id sg-auth-service \
  --protocol tcp \
  --port 443 \
  --source-group sg-load-balancer

# GCP Firewall Rules
gcloud compute firewall-rules create allow-auth-service-ingress \
  --allow tcp:443 \
  --source-ranges 10.0.0.0/8 \
  --target-tags auth-service

# Azure Network Security Groups
az network nsg rule create \
  --resource-group auth-service-rg \
  --nsg-name auth-service-nsg \
  --name allow-https \
  --protocol tcp \
  --priority 1000 \
  --destination-port-range 443
```

### Container Security

#### Security Contexts
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rust-auth-service
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: auth-service
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE  # Only if binding to privileged ports
```

#### Image Security Scanning
```bash
# Scan container images
trivy image rust-auth-service:latest

# Example CI/CD integration
name: Security Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'rust-auth-service:latest'
        format: 'sarif'
        output: 'trivy-results.sarif'
```

## ⚡ Performance Optimization

### Resource Allocation

#### CPU and Memory Tuning
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rust-auth-service
spec:
  template:
    spec:
      containers:
      - name: auth-service
        resources:
          requests:
            # Start conservative, measure, then optimize
            cpu: "100m"      # 0.1 CPU core
            memory: "64Mi"   # 64 MB RAM
          limits:
            cpu: "500m"      # 0.5 CPU core max
            memory: "256Mi"  # 256 MB RAM max
        env:
        - name: RUST_LOG
          value: "info"  # Reduce to 'warn' or 'error' in production
```

#### Vertical Pod Autoscaler
```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: rust-auth-service-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: rust-auth-service
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: auth-service
      maxAllowed:
        cpu: "1"
        memory: "512Mi"
      minAllowed:
        cpu: "50m"
        memory: "32Mi"
```

### Database Optimization

#### Connection Pooling
```rust
// Application configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub max_connections: u32,     // 20-50 for typical workloads
    pub min_connections: u32,     // 5-10 to maintain baseline
    pub connection_timeout: u64,  // 30 seconds
    pub idle_timeout: Option<u64>, // 300 seconds (5 minutes)
    pub max_lifetime: Option<u64>, // 1800 seconds (30 minutes)
}
```

#### Database Tuning Parameters
```sql
-- PostgreSQL optimization
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET work_mem = '4MB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;

-- MongoDB optimization
db.adminCommand({
  setParameter: 1,
  wiredTigerCacheSizeGB: 1,
  wiredTigerMaxCacheOverflowFileSizeGB: 0,
  journalCommitInterval: 100
})
```

### Caching Strategy

#### Multi-Level Caching
```rust
// Application-level caching configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    // In-memory LRU cache
    pub memory_cache_size: usize,     // 1000 entries
    pub memory_cache_ttl: u64,        // 300 seconds (5 minutes)
    
    // Redis distributed cache
    pub redis_url: String,
    pub redis_pool_size: u32,         // 10-20 connections
    pub redis_default_ttl: u64,       // 3600 seconds (1 hour)
    pub redis_timeout: u64,           // 5 seconds
    
    // Cache warming strategy
    pub enable_cache_warming: bool,
    pub warm_cache_on_startup: bool,
}
```

#### Redis Configuration
```redis
# Redis production configuration
maxmemory 256mb
maxmemory-policy allkeys-lru
timeout 300
tcp-keepalive 300
tcp-backlog 511

# Persistence settings for durability
save 900 1    # Save after 900 sec if at least 1 key changed
save 300 10   # Save after 300 sec if at least 10 keys changed
save 60 10000 # Save after 60 sec if at least 10000 keys changed

# AOF for better durability
appendonly yes
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
```

### Auto-Scaling Configuration

#### Horizontal Pod Autoscaler
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: rust-auth-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: rust-auth-service
  minReplicas: 3
  maxReplicas: 50
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: custom_metric_rps
      target:
        type: AverageValue
        averageValue: "100"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 4
        periodSeconds: 15
      selectPolicy: Max
```

## 📊 Monitoring & Observability

### Comprehensive Metrics

#### Prometheus Metrics Configuration
```rust
// Custom metrics for business logic
use prometheus::{Counter, Histogram, Gauge, Registry};

lazy_static! {
    // Authentication metrics
    static ref AUTH_REQUESTS_TOTAL: Counter = Counter::new(
        "auth_requests_total", "Total authentication requests"
    ).expect("metric can be created");
    
    static ref AUTH_REQUEST_DURATION: Histogram = Histogram::with_opts(
        prometheus::HistogramOpts::new(
            "auth_request_duration_seconds",
            "Authentication request duration"
        ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0])
    ).expect("metric can be created");
    
    static ref ACTIVE_SESSIONS: Gauge = Gauge::new(
        "active_sessions_total", "Currently active user sessions"
    ).expect("metric can be created");
    
    // Database metrics
    static ref DB_CONNECTIONS_ACTIVE: Gauge = Gauge::new(
        "database_connections_active", "Active database connections"
    ).expect("metric can be created");
    
    static ref DB_QUERY_DURATION: Histogram = Histogram::with_opts(
        prometheus::HistogramOpts::new(
            "database_query_duration_seconds",
            "Database query duration"
        ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0])
    ).expect("metric can be created");
    
    // Cache metrics
    static ref CACHE_HITS_TOTAL: Counter = Counter::new(
        "cache_hits_total", "Total cache hits"
    ).expect("metric can be created");
    
    static ref CACHE_MISSES_TOTAL: Counter = Counter::new(
        "cache_misses_total", "Total cache misses"
    ).expect("metric can be created");
}
```

#### Service Monitor Configuration
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: rust-auth-service-monitor
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: rust-auth-service
  namespaceSelector:
    matchNames:
    - auth-service
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
    relabelings:
    - sourceLabels: [__meta_kubernetes_pod_name]
      targetLabel: pod
    - sourceLabels: [__meta_kubernetes_pod_node_name]
      targetLabel: node
```

### Structured Logging

#### Log Configuration
```rust
use tracing::{info, warn, error, debug};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Production logging setup
fn init_logging() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_auth_service=info,tower_http=info".into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .json()  // Structured JSON logs
                .with_current_span(false)
                .with_span_list(true)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
        )
        .init();
}

// Example structured logging
#[tracing::instrument(skip(user_credentials))]
async fn authenticate_user(user_credentials: UserCredentials) -> Result<AuthToken, AuthError> {
    info!(
        user_email = %user_credentials.email,
        user_agent = %user_credentials.user_agent,
        ip_address = %user_credentials.ip,
        "User authentication attempt"
    );
    
    // ... authentication logic ...
    
    match result {
        Ok(token) => {
            info!(
                user_id = %token.user_id,
                token_expiry = %token.expires_at,
                "User authenticated successfully"
            );
            Ok(token)
        }
        Err(e) => {
            warn!(
                error = %e,
                user_email = %user_credentials.email,
                "Authentication failed"
            );
            Err(e)
        }
    }
}
```

#### Log Aggregation
```yaml
# Fluent Bit configuration for log shipping
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: logging
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         1
        Log_Level     info
        Daemon        off
        Parsers_File  parsers.conf
        HTTP_Server   On
        HTTP_Listen   0.0.0.0
        HTTP_Port     2020

    [INPUT]
        Name              tail
        Path              /var/log/containers/rust-auth-service*.log
        Parser            docker
        Tag               kube.*
        Refresh_Interval  5
        Mem_Buf_Limit     50MB
        Skip_Long_Lines   On

    [FILTER]
        Name                kubernetes
        Match               kube.*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Merge_Log           On
        Keep_Log            Off
        K8S-Logging.Parser  On
        K8S-Logging.Exclude On

    [OUTPUT]
        Name  es
        Match *
        Host  elasticsearch.logging.svc.cluster.local
        Port  9200
        Index fluentbit
```

### Health Checks

#### Advanced Health Check Implementation
```rust
use axum::{http::StatusCode, response::Json};
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct HealthChecker {
    database: Arc<dyn AuthDatabase>,
    cache: Arc<dyn CacheProvider>,
    email: Arc<dyn EmailProvider>,
}

impl HealthChecker {
    pub async fn comprehensive_health_check(&self) -> Result<Value, StatusCode> {
        let mut health_status = json!({
            "status": "healthy",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "version": env!("CARGO_PKG_VERSION"),
            "checks": {}
        });

        // Database health check
        let db_health = self.check_database_health().await;
        health_status["checks"]["database"] = json!({
            "status": if db_health.is_ok() { "healthy" } else { "unhealthy" },
            "latency_ms": db_health.as_ref().map(|d| d.as_millis()).unwrap_or(0),
            "details": db_health.as_ref().err().map(|e| e.to_string())
        });

        // Cache health check
        let cache_health = self.check_cache_health().await;
        health_status["checks"]["cache"] = json!({
            "status": if cache_health.is_ok() { "healthy" } else { "degraded" },
            "latency_ms": cache_health.as_ref().map(|d| d.as_millis()).unwrap_or(0),
            "details": cache_health.as_ref().err().map(|e| e.to_string())
        });

        // Email service health check
        let email_health = self.check_email_health().await;
        health_status["checks"]["email"] = json!({
            "status": if email_health.is_ok() { "healthy" } else { "degraded" },
            "details": email_health.as_ref().err().map(|e| e.to_string())
        });

        // Determine overall health
        let overall_healthy = db_health.is_ok() && 
                             (cache_health.is_ok() || email_health.is_ok());
        
        if !overall_healthy {
            health_status["status"] = json!("unhealthy");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }

        Ok(health_status)
    }

    async fn check_database_health(&self) -> Result<Duration, Box<dyn std::error::Error>> {
        let start = Instant::now();
        self.database.health_check().await?;
        Ok(start.elapsed())
    }

    async fn check_cache_health(&self) -> Result<Duration, Box<dyn std::error::Error>> {
        let start = Instant::now();
        self.cache.health_check().await?;
        Ok(start.elapsed())
    }

    async fn check_email_health(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.email.health_check().await
    }
}
```

#### Kubernetes Health Check Configuration
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rust-auth-service
spec:
  template:
    spec:
      containers:
      - name: auth-service
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8090
            httpHeaders:
            - name: Host
              value: localhost
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
          successThreshold: 1
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8090
            httpHeaders:
            - name: Host
              value: localhost
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
          successThreshold: 1
        startupProbe:
          httpGet:
            path: /health/startup
            port: 8090
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 30
          successThreshold: 1
```

### Alerting Strategies

#### Critical Alerts
```yaml
# High-priority alerts that require immediate attention
groups:
- name: rust-auth-service.critical
  rules:
  - alert: AuthServiceDown
    expr: up{job="rust-auth-service"} == 0
    for: 1m
    labels:
      severity: critical
      service: rust-auth-service
    annotations:
      summary: "Auth service is down"
      description: "Auth service has been down for more than 1 minute"

  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 2m
    labels:
      severity: critical
      service: rust-auth-service
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }} errors per second"

  - alert: DatabaseConnectionFailure
    expr: database_connections_active == 0
    for: 30s
    labels:
      severity: critical
      service: rust-auth-service
    annotations:
      summary: "Database connection failure"
      description: "No active database connections"

  - alert: HighLatency
    expr: histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) > 1.0
    for: 5m
    labels:
      severity: warning
      service: rust-auth-service
    annotations:
      summary: "High latency detected"
      description: "99th percentile latency is {{ $value }}s"
```

## 🔐 Backup & Recovery

### Database Backup Strategy

#### Automated Backup Scripts
```bash
#!/bin/bash
# Comprehensive backup script

set -euo pipefail

# Configuration
BACKUP_RETENTION_DAYS=30
BACKUP_S3_BUCKET="auth-service-backups"
BACKUP_ENCRYPTION_KEY="/etc/backup/encryption.key"

# PostgreSQL backup
backup_postgresql() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_file="postgresql_backup_${timestamp}.sql.gz"
    
    echo "Starting PostgreSQL backup..."
    
    # Create backup with compression
    PGPASSWORD="$DB_PASSWORD" pg_dump \
        -h "$DB_HOST" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        --verbose \
        --no-owner \
        --no-privileges \
        | gzip > "/tmp/${backup_file}"
    
    # Encrypt backup
    openssl enc -aes-256-cbc -salt \
        -in "/tmp/${backup_file}" \
        -out "/tmp/${backup_file}.enc" \
        -pass file:"$BACKUP_ENCRYPTION_KEY"
    
    # Upload to S3
    aws s3 cp "/tmp/${backup_file}.enc" \
        "s3://${BACKUP_S3_BUCKET}/postgresql/${backup_file}.enc" \
        --storage-class STANDARD_IA
    
    # Cleanup local files
    rm "/tmp/${backup_file}" "/tmp/${backup_file}.enc"
    
    echo "PostgreSQL backup completed: ${backup_file}.enc"
}

# MongoDB backup
backup_mongodb() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_dir="/tmp/mongodb_backup_${timestamp}"
    
    echo "Starting MongoDB backup..."
    
    # Create backup
    mongodump \
        --host "$MONGO_HOST" \
        --username "$MONGO_USER" \
        --password "$MONGO_PASSWORD" \
        --authenticationDatabase admin \
        --db "$MONGO_DB" \
        --out "$backup_dir"
    
    # Compress and encrypt
    tar -czf "${backup_dir}.tar.gz" -C "$backup_dir" .
    openssl enc -aes-256-cbc -salt \
        -in "${backup_dir}.tar.gz" \
        -out "${backup_dir}.tar.gz.enc" \
        -pass file:"$BACKUP_ENCRYPTION_KEY"
    
    # Upload to S3
    aws s3 cp "${backup_dir}.tar.gz.enc" \
        "s3://${BACKUP_S3_BUCKET}/mongodb/mongodb_backup_${timestamp}.tar.gz.enc" \
        --storage-class STANDARD_IA
    
    # Cleanup
    rm -rf "$backup_dir" "${backup_dir}.tar.gz" "${backup_dir}.tar.gz.enc"
    
    echo "MongoDB backup completed: mongodb_backup_${timestamp}.tar.gz.enc"
}

# Redis backup
backup_redis() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_file="redis_backup_${timestamp}.rdb"
    
    echo "Starting Redis backup..."
    
    # Create Redis backup
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" \
        --rdb "/tmp/${backup_file}"
    
    # Encrypt and upload
    openssl enc -aes-256-cbc -salt \
        -in "/tmp/${backup_file}" \
        -out "/tmp/${backup_file}.enc" \
        -pass file:"$BACKUP_ENCRYPTION_KEY"
    
    aws s3 cp "/tmp/${backup_file}.enc" \
        "s3://${BACKUP_S3_BUCKET}/redis/${backup_file}.enc" \
        --storage-class STANDARD_IA
    
    # Cleanup
    rm "/tmp/${backup_file}" "/tmp/${backup_file}.enc"
    
    echo "Redis backup completed: ${backup_file}.enc"
}

# Cleanup old backups
cleanup_old_backups() {
    echo "Cleaning up backups older than ${BACKUP_RETENTION_DAYS} days..."
    
    aws s3 ls "s3://${BACKUP_S3_BUCKET}/" --recursive | \
    while read -r line; do
        backup_date=$(echo "$line" | awk '{print $1" "$2}')
        backup_path=$(echo "$line" | awk '{print $4}')
        
        if [[ $(date -d "$backup_date" +%s) -lt $(date -d "${BACKUP_RETENTION_DAYS} days ago" +%s) ]]; then
            aws s3 rm "s3://${BACKUP_S3_BUCKET}/${backup_path}"
            echo "Deleted old backup: ${backup_path}"
        fi
    done
}

# Main execution
main() {
    case "${DB_TYPE}" in
        "postgresql")
            backup_postgresql
            ;;
        "mongodb")
            backup_mongodb
            ;;
        *)
            echo "Unsupported database type: ${DB_TYPE}"
            exit 1
            ;;
    esac
    
    backup_redis
    cleanup_old_backups
    
    echo "Backup process completed successfully"
}

main "$@"
```

#### Kubernetes CronJob for Automated Backups
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: auth-service-backup
  namespace: auth-service
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  timeZone: "UTC"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: backup-service-account
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            fsGroup: 1000
          containers:
          - name: backup
            image: backup-tools:latest
            command: ["/scripts/backup.sh"]
            env:
            - name: DB_TYPE
              value: "postgresql"
            - name: BACKUP_S3_BUCKET
              value: "auth-service-backups"
            envFrom:
            - secretRef:
                name: backup-credentials
            volumeMounts:
            - name: backup-scripts
              mountPath: /scripts
            - name: encryption-key
              mountPath: /etc/backup
              readOnly: true
            resources:
              requests:
                cpu: "100m"
                memory: "256Mi"
              limits:
                cpu: "500m"
                memory: "1Gi"
          volumes:
          - name: backup-scripts
            configMap:
              name: backup-scripts
              defaultMode: 0755
          - name: encryption-key
            secret:
              secretName: backup-encryption-key
          restartPolicy: OnFailure
```

### Disaster Recovery Procedures

#### Recovery Testing Script
```bash
#!/bin/bash
# Disaster recovery testing script

set -euo pipefail

# Test database restoration
test_database_restore() {
    local backup_file="$1"
    local test_db_name="auth_service_test_restore"
    
    echo "Testing database restore from: $backup_file"
    
    # Download and decrypt backup
    aws s3 cp "s3://${BACKUP_S3_BUCKET}/${backup_file}" "/tmp/backup.enc"
    openssl enc -d -aes-256-cbc \
        -in "/tmp/backup.enc" \
        -out "/tmp/backup.sql.gz" \
        -pass file:"$BACKUP_ENCRYPTION_KEY"
    
    # Create test database
    PGPASSWORD="$DB_PASSWORD" createdb \
        -h "$DB_HOST" \
        -U "$DB_USER" \
        "$test_db_name"
    
    # Restore backup to test database
    gunzip -c "/tmp/backup.sql.gz" | \
    PGPASSWORD="$DB_PASSWORD" psql \
        -h "$DB_HOST" \
        -U "$DB_USER" \
        -d "$test_db_name"
    
    # Verify data integrity
    local user_count=$(PGPASSWORD="$DB_PASSWORD" psql \
        -h "$DB_HOST" \
        -U "$DB_USER" \
        -d "$test_db_name" \
        -t -c "SELECT COUNT(*) FROM users;")
    
    echo "Restored database contains $user_count users"
    
    # Cleanup test database
    PGPASSWORD="$DB_PASSWORD" dropdb \
        -h "$DB_HOST" \
        -U "$DB_USER" \
        "$test_db_name"
    
    rm "/tmp/backup.enc" "/tmp/backup.sql.gz"
    
    echo "Database restore test completed successfully"
}

# Test application recovery
test_application_recovery() {
    echo "Testing application recovery..."
    
    # Deploy to test namespace
    kubectl create namespace auth-service-test || true
    
    # Apply manifests to test namespace
    kubectl apply -f k8s/ -n auth-service-test
    
    # Wait for deployment to be ready
    kubectl wait --for=condition=available \
        deployment/rust-auth-service \
        -n auth-service-test \
        --timeout=300s
    
    # Test health endpoint
    kubectl port-forward \
        -n auth-service-test \
        service/rust-auth-service 8080:80 &
    
    local port_forward_pid=$!
    sleep 5
    
    local health_status=$(curl -s http://localhost:8080/health | jq -r '.status')
    
    if [[ "$health_status" == "healthy" ]]; then
        echo "Application recovery test passed"
    else
        echo "Application recovery test failed: $health_status"
        exit 1
    fi
    
    # Cleanup
    kill $port_forward_pid
    kubectl delete namespace auth-service-test
    
    echo "Application recovery test completed"
}

# Main recovery test
main() {
    local latest_backup=$(aws s3 ls "s3://${BACKUP_S3_BUCKET}/postgresql/" | \
                         sort | tail -n 1 | awk '{print $4}')
    
    test_database_restore "$latest_backup"
    test_application_recovery
    
    echo "All disaster recovery tests completed successfully"
}

main "$@"
```

## 🔧 CI/CD Integration

### Production Deployment Pipeline

#### GitHub Actions Workflow
```yaml
name: Production Deployment

on:
  push:
    tags:
      - 'v*'

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Run security audit
      run: |
        cargo install cargo-audit
        cargo audit
    
    - name: Run vulnerability scan
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  build-and-test:
    runs-on: ubuntu-latest
    needs: security-scan
    steps:
    - uses: actions/checkout@v4
    
    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
    
    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          target
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
    
    - name: Run tests
      run: |
        cargo test --release --all-features
        cargo test --release --test integration
    
    - name: Build release binary
      run: cargo build --release
    
    - name: Build Docker image
      run: |
        docker build -t ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }} .
        docker build -t ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest .
    
    - name: Scan Docker image
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: '${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }}'
        format: 'sarif'
        output: 'trivy-image-results.sarif'
    
    - name: Log in to registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Push images
      run: |
        docker push ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }}
        docker push ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest

  deploy-staging:
    runs-on: ubuntu-latest
    needs: build-and-test
    environment: staging
    steps:
    - uses: actions/checkout@v4
    
    - name: Configure kubectl
      run: |
        echo "${{ secrets.KUBE_CONFIG_STAGING }}" | base64 -d > ~/.kube/config
    
    - name: Deploy to staging
      run: |
        kubectl set image deployment/rust-auth-service \
          auth-service=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }} \
          -n auth-service-staging
        
        kubectl rollout status deployment/rust-auth-service \
          -n auth-service-staging \
          --timeout=300s
    
    - name: Run integration tests
      run: |
        kubectl port-forward -n auth-service-staging service/rust-auth-service 8080:80 &
        sleep 10
        npm run test:integration
        kill %1

  deploy-production:
    runs-on: ubuntu-latest
    needs: deploy-staging
    environment: production
    steps:
    - uses: actions/checkout@v4
    
    - name: Configure kubectl
      run: |
        echo "${{ secrets.KUBE_CONFIG_PRODUCTION }}" | base64 -d > ~/.kube/config
    
    - name: Deploy to production
      run: |
        kubectl set image deployment/rust-auth-service \
          auth-service=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }} \
          -n auth-service
        
        kubectl rollout status deployment/rust-auth-service \
          -n auth-service \
          --timeout=300s
    
    - name: Verify deployment
      run: |
        kubectl get pods -n auth-service
        kubectl get ingress -n auth-service
        
        # Health check
        curl -f https://auth.yourdomain.com/health
    
    - name: Post-deployment tests
      run: |
        npm run test:smoke-production
```

### Blue-Green Deployment Strategy

#### Blue-Green Deployment Script
```bash
#!/bin/bash
# Blue-green deployment implementation

set -euo pipefail

NAMESPACE="auth-service"
SERVICE_NAME="rust-auth-service"
NEW_IMAGE="$1"
TIMEOUT=300

# Determine current and new environments
get_current_environment() {
    kubectl get service "$SERVICE_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.spec.selector.environment}' 2>/dev/null || echo "blue"
}

# Deploy to inactive environment
deploy_new_version() {
    local current_env="$1"
    local new_env="$2"
    local image="$3"
    
    echo "Deploying $image to $new_env environment..."
    
    # Update deployment
    kubectl set image "deployment/${SERVICE_NAME}-${new_env}" \
        auth-service="$image" \
        -n "$NAMESPACE"
    
    # Wait for rollout
    kubectl rollout status "deployment/${SERVICE_NAME}-${new_env}" \
        -n "$NAMESPACE" \
        --timeout="${TIMEOUT}s"
    
    echo "Deployment to $new_env environment completed"
}

# Run health checks
verify_new_environment() {
    local env="$1"
    
    echo "Verifying $env environment..."
    
    # Port forward to new environment
    kubectl port-forward "service/${SERVICE_NAME}-${env}" 8080:80 -n "$NAMESPACE" &
    local port_forward_pid=$!
    
    sleep 5
    
    # Health check
    local health_status
    health_status=$(curl -s http://localhost:8080/health | jq -r '.status' || echo "unhealthy")
    
    # Cleanup port forward
    kill $port_forward_pid 2>/dev/null || true
    
    if [[ "$health_status" != "healthy" ]]; then
        echo "Health check failed for $env environment"
        return 1
    fi
    
    echo "$env environment is healthy"
    return 0
}

# Switch traffic to new environment
switch_traffic() {
    local new_env="$1"
    
    echo "Switching traffic to $new_env environment..."
    
    # Update service selector
    kubectl patch service "$SERVICE_NAME" -n "$NAMESPACE" \
        -p '{"spec":{"selector":{"environment":"'$new_env'"}}}'
    
    echo "Traffic switched to $new_env environment"
}

# Rollback to previous environment
rollback() {
    local rollback_env="$1"
    
    echo "Rolling back to $rollback_env environment..."
    
    kubectl patch service "$SERVICE_NAME" -n "$NAMESPACE" \
        -p '{"spec":{"selector":{"environment":"'$rollback_env'"}}}'
    
    echo "Rollback completed"
}

# Main deployment process
main() {
    local new_image="$1"
    
    if [[ -z "$new_image" ]]; then
        echo "Usage: $0 <new-image>"
        exit 1
    fi
    
    local current_env
    current_env=$(get_current_environment)
    
    local new_env
    if [[ "$current_env" == "blue" ]]; then
        new_env="green"
    else
        new_env="blue"
    fi
    
    echo "Current environment: $current_env"
    echo "Deploying to: $new_env"
    
    # Deploy new version
    deploy_new_version "$current_env" "$new_env" "$new_image"
    
    # Verify new environment
    if ! verify_new_environment "$new_env"; then
        echo "Verification failed, aborting deployment"
        exit 1
    fi
    
    # Switch traffic
    switch_traffic "$new_env"
    
    # Final verification
    sleep 10
    if ! verify_new_environment "$new_env"; then
        echo "Post-switch verification failed, rolling back"
        rollback "$current_env"
        exit 1
    fi
    
    echo "Blue-green deployment completed successfully"
    echo "Active environment: $new_env"
    echo "Previous environment: $current_env (ready for cleanup)"
}

main "$@"
```

## 📈 Capacity Planning

### Performance Baselines

#### Load Testing Configuration
```yaml
# Artillery.js load testing configuration
config:
  target: 'https://auth.yourdomain.com'
  phases:
    - duration: 60
      arrivalRate: 10
      rampTo: 50
      name: "Warm up"
    - duration: 120
      arrivalRate: 50
      name: "Sustained load"
    - duration: 60
      arrivalRate: 50
      rampTo: 100
      name: "Ramp up"
    - duration: 300
      arrivalRate: 100
      name: "High load"
  payload:
    path: './test-users.csv'
    fields:
      - 'email'
      - 'password'

scenarios:
  - name: "Authentication flow"
    weight: 80
    flow:
      - post:
          url: "/api/auth/login"
          json:
            email: "{{ email }}"
            password: "{{ password }}"
          capture:
            - json: "$.access_token"
              as: "token"
      - get:
          url: "/api/auth/me"
          headers:
            Authorization: "Bearer {{ token }}"
  
  - name: "Registration flow"
    weight: 20
    flow:
      - post:
          url: "/api/auth/register"
          json:
            email: "test+{{ $randomString() }}@example.com"
            password: "TestPassword123!"
            first_name: "Test"
            last_name: "User"
```

#### Performance Benchmarking
```bash
#!/bin/bash
# Performance benchmarking script

# Configuration
BASE_URL="https://auth.yourdomain.com"
CONCURRENT_USERS=(1 10 50 100 200 500)
TEST_DURATION=60

# Run benchmark tests
run_benchmark() {
    local concurrent="$1"
    local output_file="benchmark_${concurrent}_users.json"
    
    echo "Running benchmark with $concurrent concurrent users..."
    
    artillery run \
        --config benchmark-config.yaml \
        --overrides '{"config":{"phases":[{"duration":'$TEST_DURATION',"arrivalRate":'$concurrent'}]}}' \
        --output "$output_file"
    
    # Extract key metrics
    local avg_response_time=$(jq '.aggregate.latency.mean' "$output_file")
    local p99_response_time=$(jq '.aggregate.latency.p99' "$output_file")
    local error_rate=$(jq '.aggregate.counters."http.responses"."4xx" + .aggregate.counters."http.responses"."5xx"' "$output_file")
    local total_requests=$(jq '.aggregate.counters."http.requests"' "$output_file")
    
    echo "Results for $concurrent users:"
    echo "  Average response time: ${avg_response_time}ms"
    echo "  99th percentile: ${p99_response_time}ms"
    echo "  Error rate: $((error_rate * 100 / total_requests))%"
    echo "  Total requests: $total_requests"
    echo ""
}

# Generate performance report
generate_report() {
    echo "# Performance Benchmark Report" > performance_report.md
    echo "Generated: $(date)" >> performance_report.md
    echo "" >> performance_report.md
    
    echo "| Concurrent Users | Avg Response Time | 99th Percentile | Error Rate | RPS |" >> performance_report.md
    echo "|------------------|-------------------|-----------------|------------|-----|" >> performance_report.md
    
    for users in "${CONCURRENT_USERS[@]}"; do
        local file="benchmark_${users}_users.json"
        if [[ -f "$file" ]]; then
            local avg=$(jq '.aggregate.latency.mean' "$file")
            local p99=$(jq '.aggregate.latency.p99' "$file")
            local errors=$(jq '.aggregate.counters."http.responses"."4xx" + .aggregate.counters."http.responses"."5xx"' "$file")
            local total=$(jq '.aggregate.counters."http.requests"' "$file")
            local rps=$((total / TEST_DURATION))
            local error_rate=$((errors * 100 / total))
            
            echo "| $users | ${avg}ms | ${p99}ms | ${error_rate}% | $rps |" >> performance_report.md
        fi
    done
}

# Main execution
main() {
    echo "Starting performance benchmark..."
    
    for users in "${CONCURRENT_USERS[@]}"; do
        run_benchmark "$users"
        sleep 30  # Cool-down period
    done
    
    generate_report
    echo "Benchmark completed. Report saved to performance_report.md"
}

main "$@"
```

### Resource Scaling Guidelines

#### Scaling Decision Matrix
```yaml
# Scaling configuration based on metrics
apiVersion: v1
kind: ConfigMap
metadata:
  name: scaling-config
  namespace: auth-service
data:
  scaling-rules.yaml: |
    # CPU-based scaling
    cpu_scaling:
      scale_up_threshold: 70    # Scale up when CPU > 70%
      scale_down_threshold: 30  # Scale down when CPU < 30%
      stabilization_window: 300 # 5 minutes
      
    # Memory-based scaling
    memory_scaling:
      scale_up_threshold: 80    # Scale up when memory > 80%
      scale_down_threshold: 50  # Scale down when memory < 50%
      
    # Custom metrics scaling
    custom_metrics:
      - name: requests_per_second
        scale_up_threshold: 100
        scale_down_threshold: 50
      - name: active_connections
        scale_up_threshold: 1000
        scale_down_threshold: 500
      - name: queue_depth
        scale_up_threshold: 50
        scale_down_threshold: 10
    
    # Database scaling
    database_scaling:
      connection_pool_size:
        base: 20
        per_replica: 10
        max: 100
      
    # Cache scaling
    cache_scaling:
      redis_max_memory: "512mb"
      eviction_policy: "allkeys-lru"
```

---

## 🎯 Production Readiness Checklist

### Pre-Deployment Checklist
- [ ] **Security audit completed**
  - [ ] Vulnerability scanning passed
  - [ ] Secrets properly configured
  - [ ] Network policies implemented
  - [ ] SSL/TLS certificates valid
- [ ] **Performance testing completed**
  - [ ] Load testing passed requirements
  - [ ] Database performance optimized
  - [ ] Cache hit rates > 80%
  - [ ] Response times < 100ms (p99)
- [ ] **Monitoring configured**
  - [ ] Metrics collection enabled
  - [ ] Alerting rules configured
  - [ ] Dashboards created
  - [ ] Log aggregation working
- [ ] **Backup and recovery tested**
  - [ ] Automated backups configured
  - [ ] Recovery procedures tested
  - [ ] RTO/RPO requirements met
- [ ] **Documentation complete**
  - [ ] Runbooks created
  - [ ] Architecture documented
  - [ ] API documentation updated
  - [ ] Troubleshooting guides available

### Post-Deployment Verification
- [ ] **Health checks passing**
- [ ] **Traffic flowing correctly**
- [ ] **Monitoring showing healthy metrics**
- [ ] **Alerts configured and tested**
- [ ] **Backup schedule active**
- [ ] **Team trained on operations**

Ready for production! 🚀