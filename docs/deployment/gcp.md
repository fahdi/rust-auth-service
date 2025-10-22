# Google Cloud Platform (GCP) Deployment Guide

This guide walks you through deploying the Rust Auth Service on Google Cloud Platform using managed services for a production-ready, scalable deployment.

## 🎯 Overview

GCP deployment provides:
- **GKE Autopilot** for fully managed Kubernetes
- **Cloud SQL** with automated backups and high availability
- **Memorystore Redis** for high-performance caching
- **Cloud Load Balancing** with SSL termination
- **Cloud Monitoring** and logging with Stackdriver
- **Cloud IAM** for identity and access management

## 🏗️ Architecture

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   Cloud DNS         │    │  Cloud CDN         │    │   Cloud Armor       │
│   Domain Management │────│  Global Distribution│────│   DDoS Protection   │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
           │                           │                           │
           └───────────────────────────┼───────────────────────────┘
                                      │
                 ┌─────────────────────┴─────────────────────┐
                 │        Cloud Load Balancer               │
                 │        SSL Termination & Routing         │
                 └─────────────────────┬─────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │              GKE Autopilot Cluster                       │
        │  ┌─────────────────┐    ┌─────────────────┐             │
        │  │   Auth Service  │    │   Admin Panel   │             │
        │  │   (3 replicas)  │    │   (2 replicas)  │             │
        │  └─────────────────┘    └─────────────────┘             │
        └─────────────────────────────┬─────────────────────────────┘
                                      │
    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
    │   Cloud SQL     │    │  Memorystore    │    │  Cloud Storage  │
    │   PostgreSQL    │────│  Redis Instance │────│  Backups/Logs   │
    │   High Avail.   │    │   Regional      │    │  Static Assets  │
    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📋 Prerequisites

### Required Tools
- **gcloud CLI**: Google Cloud command-line tool
- **kubectl**: Kubernetes command-line tool
- **helm**: Kubernetes package manager

### Required Permissions
Your GCP account needs the following roles:
- `roles/container.clusterAdmin`
- `roles/cloudsql.admin`
- `roles/redis.admin`
- `roles/compute.networkAdmin`
- `roles/dns.admin`
- `roles/secretmanager.admin`

### Installation Commands
```bash
# Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Install kubectl via gcloud
gcloud components install kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install GKE gcloud auth plugin
gcloud components install gke-gcloud-auth-plugin
```

### Initial Setup
```bash
# Login to GCP
gcloud auth login

# Set project
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable container.googleapis.com
gcloud services enable sqladmin.googleapis.com
gcloud services enable redis.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable dns.googleapis.com
gcloud services enable cloudresourcemanager.googleapis.com
```

## 🚀 Step-by-Step Deployment

### Step 1: Infrastructure Setup

#### 1.1 Create GKE Autopilot Cluster
```bash
# Create VPC network
gcloud compute networks create rust-auth-service-vpc --subnet-mode regional

# Create subnet
gcloud compute networks subnets create rust-auth-service-subnet \
    --network rust-auth-service-vpc \
    --range 10.0.0.0/24 \
    --region us-central1

# Create GKE Autopilot cluster
gcloud container clusters create-auto rust-auth-service-cluster \
    --region us-central1 \
    --network rust-auth-service-vpc \
    --subnetwork rust-auth-service-subnet \
    --cluster-version latest \
    --enable-autoscaling \
    --enable-autorepair \
    --enable-autoupgrade \
    --enable-shielded-nodes \
    --shielded-secure-boot \
    --shielded-integrity-monitoring \
    --enable-ip-alias \
    --enable-network-policy \
    --workload-pool=YOUR_PROJECT_ID.svc.id.goog

# Get cluster credentials
gcloud container clusters get-credentials rust-auth-service-cluster --region us-central1

# Verify connection
kubectl get nodes
```

#### 1.2 Set Up Workload Identity
```bash
# Create Google Service Account
gcloud iam service-accounts create rust-auth-service-sa \
    --display-name "Rust Auth Service"

# Bind Kubernetes Service Account to Google Service Account
gcloud iam service-accounts add-iam-policy-binding \
    --role roles/iam.workloadIdentityUser \
    --member "serviceAccount:YOUR_PROJECT_ID.svc.id.goog[auth-service/rust-auth-service-ksa]" \
    rust-auth-service-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com

# Grant necessary permissions
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:rust-auth-service-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/cloudsql.client"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:rust-auth-service-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

### Step 2: Database Setup

#### 2.1 Create Cloud SQL PostgreSQL Instance
```bash
# Create Cloud SQL instance
gcloud sql instances create rust-auth-service-db \
    --database-version POSTGRES_15 \
    --tier db-f1-micro \
    --region us-central1 \
    --storage-type SSD \
    --storage-size 20GB \
    --storage-auto-increase \
    --backup \
    --backup-start-time 03:00 \
    --maintenance-window-day SUN \
    --maintenance-window-hour 04 \
    --maintenance-release-channel production \
    --deletion-protection \
    --enable-ip-alias \
    --network rust-auth-service-vpc

# Set password for postgres user
gcloud sql users set-password postgres \
    --instance rust-auth-service-db \
    --password 'SecureDBPassword123!'

# Create application database
gcloud sql databases create auth_service \
    --instance rust-auth-service-db

# Create application user
gcloud sql users create auth_user \
    --instance rust-auth-service-db \
    --password 'AppUserPassword123!'

# Get connection name
gcloud sql instances describe rust-auth-service-db --format='value(connectionName)'
```

#### 2.2 Create Memorystore Redis Instance
```bash
# Create Redis instance
gcloud redis instances create rust-auth-service-redis \
    --size 1 \
    --region us-central1 \
    --network rust-auth-service-vpc \
    --redis-version redis_7_0 \
    --enable-auth \
    --persistence-mode rdb \
    --rdb-snapshot-period 12h \
    --rdb-snapshot-start-time 2024-01-01T03:00:00Z

# Get Redis host
gcloud redis instances describe rust-auth-service-redis --region us-central1 --format='value(host)'
```

### Step 3: Secrets Management

#### 3.1 Create Secret Manager Secrets
```bash
# Database connection secret
echo -n 'postgresql://auth_user:AppUserPassword123!@127.0.0.1:5432/auth_service' | \
gcloud secrets create database-url --data-file=-

# JWT secret
echo -n 'your-super-secure-jwt-secret-key-256-bits-long' | \
gcloud secrets create jwt-secret --data-file=-

# Email provider secret
echo -n 'your-sendgrid-api-key' | \
gcloud secrets create email-api-key --data-file=-

# Redis auth token
REDIS_AUTH=$(gcloud redis instances describe rust-auth-service-redis --region us-central1 --format='value(authString)')
echo -n $REDIS_AUTH | gcloud secrets create redis-auth --data-file=-

# Grant service account access to secrets
gcloud secrets add-iam-policy-binding database-url \
    --member="serviceAccount:rust-auth-service-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding jwt-secret \
    --member="serviceAccount:rust-auth-service-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding email-api-key \
    --member="serviceAccount:rust-auth-service-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding redis-auth \
    --member="serviceAccount:rust-auth-service-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

#### 3.2 Install Secret Manager CSI Driver
```bash
# Install Secret Manager CSI driver
kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp/main/deploy/provider-gcp-plugin.yaml

# Install Secrets Store CSI Driver
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver \
    --namespace kube-system \
    --set syncSecret.enabled=true \
    --set enableSecretRotation=true
```

### Step 4: Application Deployment

#### 4.1 Create Kubernetes Namespace and Service Account
```bash
# Create namespace
kubectl create namespace auth-service

# Create Kubernetes service account
cat > k8s-service-account.yaml << EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rust-auth-service-ksa
  namespace: auth-service
  annotations:
    iam.gke.io/gcp-service-account: rust-auth-service-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com
EOF

kubectl apply -f k8s-service-account.yaml
```

#### 4.2 Create Cloud SQL Proxy
```bash
cat > cloudsql-proxy.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloudsql-proxy
  namespace: auth-service
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cloudsql-proxy
  template:
    metadata:
      labels:
        app: cloudsql-proxy
    spec:
      serviceAccountName: rust-auth-service-ksa
      containers:
      - name: cloudsql-proxy
        image: gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.7.0
        args:
        - "--structured-logs"
        - "--port=5432"
        - "YOUR_PROJECT_ID:us-central1:rust-auth-service-db"
        securityContext:
          runAsNonRoot: true
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
        ports:
        - containerPort: 5432
        livenessProbe:
          tcpSocket:
            port: 5432
          periodSeconds: 10
          timeoutSeconds: 5
        readinessProbe:
          tcpSocket:
            port: 5432
          periodSeconds: 5
          timeoutSeconds: 3
---
apiVersion: v1
kind: Service
metadata:
  name: cloudsql-proxy
  namespace: auth-service
spec:
  ports:
  - port: 5432
    targetPort: 5432
  selector:
    app: cloudsql-proxy
EOF

kubectl apply -f cloudsql-proxy.yaml
```

#### 4.3 Create Secret Provider Class
```bash
cat > secret-provider-class.yaml << EOF
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: rust-auth-service-secrets
  namespace: auth-service
spec:
  provider: gcp
  parameters:
    secrets: |
      - resourceName: "projects/YOUR_PROJECT_ID/secrets/database-url/versions/latest"
        path: "database-url"
      - resourceName: "projects/YOUR_PROJECT_ID/secrets/jwt-secret/versions/latest"
        path: "jwt-secret"
      - resourceName: "projects/YOUR_PROJECT_ID/secrets/email-api-key/versions/latest"
        path: "email-api-key"
      - resourceName: "projects/YOUR_PROJECT_ID/secrets/redis-auth/versions/latest"
        path: "redis-auth"
  secretObjects:
  - secretName: rust-auth-service-secrets
    type: Opaque
    data:
    - objectName: "database-url"
      key: "DATABASE_URL"
    - objectName: "jwt-secret"
      key: "JWT_SECRET"
    - objectName: "email-api-key"
      key: "EMAIL_API_KEY"
    - objectName: "redis-auth"
      key: "REDIS_AUTH"
EOF

kubectl apply -f secret-provider-class.yaml
```

#### 4.4 Deploy Application
```bash
# Get Redis host IP
REDIS_HOST=$(gcloud redis instances describe rust-auth-service-redis --region us-central1 --format='value(host)')

cat > deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rust-auth-service
  namespace: auth-service
  labels:
    app: rust-auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rust-auth-service
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    metadata:
      labels:
        app: rust-auth-service
    spec:
      serviceAccountName: rust-auth-service-ksa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      containers:
      - name: auth-service
        image: gcr.io/YOUR_PROJECT_ID/rust-auth-service:latest
        ports:
        - containerPort: 8090
          name: http
        env:
        - name: RUST_LOG
          value: "info"
        - name: DATABASE_TYPE
          value: "postgresql"
        - name: REDIS_URL
          value: "redis://:\$(REDIS_AUTH)@$REDIS_HOST:6379"
        - name: SERVER_HOST
          value: "0.0.0.0"
        - name: SERVER_PORT
          value: "8090"
        - name: EMAIL_PROVIDER
          value: "sendgrid"
        - name: CORS_ALLOWED_ORIGINS
          value: "https://yourdomain.com,https://app.yourdomain.com"
        envFrom:
        - secretRef:
            name: rust-auth-service-secrets
        volumeMounts:
        - name: secrets-store
          mountPath: "/mnt/secrets-store"
          readOnly: true
        - name: tmp-volume
          mountPath: /tmp
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8090
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health
            port: 8090
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        startupProbe:
          httpGet:
            path: /health
            port: 8090
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 10
      volumes:
      - name: secrets-store
        csi:
          driver: secrets-store.csi.k8s.io
          readOnly: true
          volumeAttributes:
            secretProviderClass: rust-auth-service-secrets
      - name: tmp-volume
        emptyDir: {}
      nodeSelector:
        kubernetes.io/os: linux
      tolerations:
      - effect: NoSchedule
        operator: Equal
        key: kubernetes.io/arch
        value: arm64
---
apiVersion: v1
kind: Service
metadata:
  name: rust-auth-service
  namespace: auth-service
  labels:
    app: rust-auth-service
  annotations:
    cloud.google.com/neg: '{"ingress": true}'
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 8090
    protocol: TCP
    name: http
  selector:
    app: rust-auth-service
EOF

kubectl apply -f deployment.yaml
```

#### 4.5 Set Up Horizontal Pod Autoscaler
```bash
cat > hpa.yaml << EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: rust-auth-service-hpa
  namespace: auth-service
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
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
      - type: Pods
        value: 2
        periodSeconds: 60
      selectPolicy: Min
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
EOF

kubectl apply -f hpa.yaml
```

### Step 5: Load Balancer and Ingress

#### 5.1 Create Managed SSL Certificate
```bash
# Create managed SSL certificate
cat > ssl-certificate.yaml << EOF
apiVersion: networking.gke.io/v1
kind: ManagedCertificate
metadata:
  name: rust-auth-service-ssl
  namespace: auth-service
spec:
  domains:
  - auth.yourdomain.com
  - api.yourdomain.com
EOF

kubectl apply -f ssl-certificate.yaml
```

#### 5.2 Create Ingress with Global Load Balancer
```bash
cat > ingress.yaml << EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rust-auth-service-ingress
  namespace: auth-service
  annotations:
    kubernetes.io/ingress.global-static-ip-name: rust-auth-service-ip
    networking.gke.io/managed-certificates: rust-auth-service-ssl
    kubernetes.io/ingress.class: gce
    kubernetes.io/ingress.allow-http: "false"
    ingress.gcp.kubernetes.io/load-balancer-type: "External"
    cloud.google.com/armor-config: '{"rust-auth-service-armor-policy": "projects/YOUR_PROJECT_ID/global/securityPolicies/rust-auth-service-armor-policy"}'
spec:
  rules:
  - host: auth.yourdomain.com
    http:
      paths:
      - path: /*
        pathType: ImplementationSpecific
        backend:
          service:
            name: rust-auth-service
            port:
              number: 80
  - host: api.yourdomain.com
    http:
      paths:
      - path: /*
        pathType: ImplementationSpecific
        backend:
          service:
            name: rust-auth-service
            port:
              number: 80
EOF

# Reserve static IP address
gcloud compute addresses create rust-auth-service-ip --global

# Apply ingress
kubectl apply -f ingress.yaml
```

#### 5.3 Set Up Cloud Armor Security Policy
```bash
# Create Cloud Armor security policy
gcloud compute security-policies create rust-auth-service-armor-policy \
    --description "Security policy for Rust Auth Service"

# Add rate limiting rule
gcloud compute security-policies rules create 1000 \
    --security-policy rust-auth-service-armor-policy \
    --expression "true" \
    --action "rate-based-ban" \
    --rate-limit-threshold-count 100 \
    --rate-limit-threshold-interval-sec 60 \
    --ban-duration-sec 300 \
    --conform-action allow \
    --exceed-action deny-403 \
    --enforce-on-key IP

# Add geographic restriction (optional)
gcloud compute security-policies rules create 2000 \
    --security-policy rust-auth-service-armor-policy \
    --expression "origin.region_code == 'CN' || origin.region_code == 'RU'" \
    --action deny-403
```

### Step 6: DNS Configuration

#### 6.1 Create Cloud DNS Zone
```bash
# Create DNS zone
gcloud dns managed-zones create yourdomain-com \
    --description "DNS zone for yourdomain.com" \
    --dns-name yourdomain.com

# Get static IP address
STATIC_IP=$(gcloud compute addresses describe rust-auth-service-ip --global --format='value(address)')

# Create A records
gcloud dns record-sets transaction start --zone yourdomain-com
gcloud dns record-sets transaction add $STATIC_IP --name auth.yourdomain.com. --ttl 300 --type A --zone yourdomain-com
gcloud dns record-sets transaction add $STATIC_IP --name api.yourdomain.com. --ttl 300 --type A --zone yourdomain-com
gcloud dns record-sets transaction execute --zone yourdomain-com

# Get name servers
gcloud dns managed-zones describe yourdomain-com --format='value(nameServers)'
```

### Step 7: Monitoring and Logging

#### 7.1 Set Up Cloud Monitoring
```bash
# Create notification channel
gcloud alpha monitoring channels create \
    --display-name="Email Alerts" \
    --type=email \
    --channel-labels=email_address=admin@yourdomain.com

# Create uptime check
gcloud monitoring uptime create \
    --display-name="Rust Auth Service Health Check" \
    --hostname=auth.yourdomain.com \
    --path=/health \
    --port=443 \
    --protocol=HTTPS

# Create alerting policy for high error rate
cat > alert-policy.yaml << EOF
displayName: "High Error Rate - Rust Auth Service"
conditions:
- displayName: "HTTP 5xx errors"
  conditionThreshold:
    filter: 'resource.type="gce_instance"'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 10
    duration: 300s
    aggregations:
    - alignmentPeriod: 60s
      perSeriesAligner: ALIGN_RATE
      crossSeriesReducer: REDUCE_SUM
notificationChannels:
- "projects/YOUR_PROJECT_ID/notificationChannels/CHANNEL_ID"
EOF

gcloud alpha monitoring policies create --policy-from-file=alert-policy.yaml
```

#### 7.2 Install Prometheus and Grafana
```bash
# Add Prometheus Helm repository
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Install Prometheus with GKE integration
helm install prometheus prometheus-community/kube-prometheus-stack \
    --namespace monitoring \
    --create-namespace \
    --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
    --set grafana.adminPassword='admin123' \
    --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.storageClassName=standard-rwo \
    --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi

# Create service monitor for auth service
cat > service-monitor.yaml << EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: rust-auth-service-monitor
  namespace: monitoring
  labels:
    app: rust-auth-service
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
EOF

kubectl apply -f service-monitor.yaml
```

## 🔧 Configuration and Management

### Environment Configuration
```bash
# Create ConfigMap for application configuration
cat > configmap.yaml << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: rust-auth-service-config
  namespace: auth-service
data:
  RUST_LOG: "info"
  SERVER_HOST: "0.0.0.0"
  SERVER_PORT: "8090"
  DATABASE_TYPE: "postgresql"
  CACHE_TYPE: "redis"
  EMAIL_PROVIDER: "sendgrid"
  CORS_ALLOWED_ORIGINS: "https://yourdomain.com,https://app.yourdomain.com"
  RATE_LIMIT_REQUESTS_PER_MINUTE: "60"
  JWT_EXPIRATION: "3600"
  BCRYPT_COST: "12"
  METRICS_ENABLED: "true"
  HEALTH_CHECK_TIMEOUT: "5"
EOF

kubectl apply -f configmap.yaml
```

### Resource Quotas and Limits
```bash
cat > resource-quota.yaml << EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: auth-service-quota
  namespace: auth-service
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
    pods: "20"
    services: "5"
    persistentvolumeclaims: "4"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: auth-service-limits
  namespace: auth-service
spec:
  limits:
  - default:
      cpu: "500m"
      memory: "256Mi"
    defaultRequest:
      cpu: "100m"
      memory: "64Mi"
    type: Container
EOF

kubectl apply -f resource-quota.yaml
```

## 📊 Performance Tuning

### Cloud SQL Optimization
```bash
# Update Cloud SQL instance for better performance
gcloud sql instances patch rust-auth-service-db \
    --database-flags shared_preload_libraries=pg_stat_statements \
    --database-flags max_connections=200 \
    --database-flags work_mem=4MB \
    --database-flags maintenance_work_mem=256MB \
    --database-flags effective_cache_size=1GB \
    --database-flags checkpoint_completion_target=0.9

# Enable query insights
gcloud sql instances patch rust-auth-service-db \
    --insights-config-query-insights-enabled \
    --insights-config-record-application-tags \
    --insights-config-record-client-address
```

### Memorystore Redis Optimization
```bash
# Update Redis instance configuration
gcloud redis instances update rust-auth-service-redis \
    --region us-central1 \
    --redis-config maxmemory-policy=allkeys-lru \
    --redis-config timeout=300 \
    --redis-config tcp-keepalive=60
```

### GKE Cluster Optimization
```bash
# Enable cluster autoscaling
gcloud container clusters update rust-auth-service-cluster \
    --region us-central1 \
    --enable-autoscaling \
    --min-nodes 1 \
    --max-nodes 10 \
    --location-policy BALANCED

# Enable node auto-provisioning
gcloud container clusters update rust-auth-service-cluster \
    --region us-central1 \
    --enable-autoprovisioning \
    --min-cpu 1 \
    --max-cpu 16 \
    --min-memory 1 \
    --max-memory 64
```

## 🛡️ Security Best Practices

### Network Security
```bash
# Create network policy
cat > network-policy.yaml << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: rust-auth-service-network-policy
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
    - podSelector:
        matchLabels:
          app: cloudsql-proxy
    ports:
    - protocol: TCP
      port: 8090
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: cloudsql-proxy
    ports:
    - protocol: TCP
      port: 5432
  - to: []
    ports:
    - protocol: TCP
      port: 6379  # Redis
    - protocol: TCP
      port: 443   # HTTPS
    - protocol: TCP
      port: 53    # DNS
    - protocol: UDP
      port: 53    # DNS
EOF

kubectl apply -f network-policy.yaml
```

### Pod Security Standards
```bash
cat > pod-security-policy.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: rust-auth-service
  namespace: auth-service
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
EOF
```

### Binary Authorization
```bash
# Enable Binary Authorization
gcloud container binauthz policy import policy.yaml

# Create attestor
gcloud container binauthz attestors create rust-auth-service-attestor \
    --attestation-authority-note projects/YOUR_PROJECT_ID/notes/rust-auth-service-note \
    --attestation-authority-note-project YOUR_PROJECT_ID
```

## 🐛 Troubleshooting

### Common Issues

#### 1. Pod Startup Issues
```bash
# Check pod status and events
kubectl get pods -n auth-service
kubectl describe pods -n auth-service

# Check logs
kubectl logs -f deployment/rust-auth-service -n auth-service

# Check secret mounting
kubectl exec -it deployment/rust-auth-service -n auth-service -- ls -la /mnt/secrets-store/
```

#### 2. Database Connection Issues
```bash
# Check Cloud SQL Proxy status
kubectl logs -f deployment/cloudsql-proxy -n auth-service

# Test database connectivity
kubectl run postgres-client --rm -it --restart=Never --image=postgres:15 -- psql postgresql://auth_user:AppUserPassword123!@cloudsql-proxy:5432/auth_service

# Check Cloud SQL instance status
gcloud sql instances describe rust-auth-service-db
```

#### 3. Load Balancer Issues
```bash
# Check ingress status
kubectl describe ingress rust-auth-service-ingress -n auth-service

# Check managed certificate status
kubectl describe managedcertificate rust-auth-service-ssl -n auth-service

# Check Cloud Load Balancer
gcloud compute url-maps list
gcloud compute backend-services list
```

#### 4. Monitoring Issues
```bash
# Check service monitor
kubectl get servicemonitor -n monitoring

# Check Prometheus targets
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090
# Visit http://localhost:9090/targets
```

### Performance Monitoring
```bash
# Check cluster metrics
kubectl top nodes
kubectl top pods -n auth-service

# Check Cloud Monitoring
gcloud logging read "resource.type=k8s_container AND resource.labels.container_name=auth-service" --limit 50

# Monitor Cloud SQL performance
gcloud sql operations list --instance rust-auth-service-db
```

## 💰 Cost Optimization

### Resource Right-Sizing
```bash
# Analyze resource usage
kubectl top pods -n auth-service

# Use Vertical Pod Autoscaler recommendations
cat > vpa.yaml << EOF
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: rust-auth-service-vpa
  namespace: auth-service
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: rust-auth-service
  updatePolicy:
    updateMode: "Off"  # Recommendation only
EOF

kubectl apply -f vpa.yaml
```

### Committed Use Discounts
```bash
# Check current usage
gcloud compute instances list
gcloud sql instances list

# Purchase committed use contracts for predictable workloads
gcloud compute commitments create rust-auth-service-commitment \
    --plan 1-year \
    --resources type=memory,amount=16 \
    --resources type=vcpu,amount=8 \
    --region us-central1
```

### Preemptible Instances (for non-critical workloads)
```bash
# Create preemptible node pool for development
gcloud container node-pools create preemptible-pool \
    --cluster rust-auth-service-cluster \
    --region us-central1 \
    --machine-type e2-medium \
    --preemptible \
    --num-nodes 1 \
    --enable-autoscaling \
    --min-nodes 0 \
    --max-nodes 3
```

## 🔄 Maintenance and Updates

### Application Updates
```bash
# Build and push new image
docker build -t gcr.io/YOUR_PROJECT_ID/rust-auth-service:v2.0.0 .
docker push gcr.io/YOUR_PROJECT_ID/rust-auth-service:v2.0.0

# Update deployment
kubectl set image deployment/rust-auth-service auth-service=gcr.io/YOUR_PROJECT_ID/rust-auth-service:v2.0.0 -n auth-service

# Monitor rollout
kubectl rollout status deployment/rust-auth-service -n auth-service

# Rollback if needed
kubectl rollout undo deployment/rust-auth-service -n auth-service
```

### Cluster Maintenance
```bash
# Update GKE cluster
gcloud container clusters update rust-auth-service-cluster \
    --region us-central1 \
    --cluster-version latest

# Update node pools
gcloud container node-pools update default-pool \
    --cluster rust-auth-service-cluster \
    --region us-central1 \
    --node-version latest
```

### Database Maintenance
```bash
# Create on-demand backup
gcloud sql backups create \
    --instance rust-auth-service-db \
    --description "Pre-maintenance backup"

# Update database version
gcloud sql instances patch rust-auth-service-db \
    --database-version POSTGRES_15 \
    --maintenance-window-day SUN \
    --maintenance-window-hour 04
```

## 📈 Monitoring and Alerting

### Custom Dashboards
```bash
# Import Grafana dashboard
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80
# Visit http://localhost:3000 (admin/admin123)
# Import dashboard ID: 14314 (Kubernetes monitoring)
```

### Cloud Monitoring Dashboards
```bash
# Create custom dashboard
gcloud monitoring dashboards create --config-from-file=dashboard.json
```

### Alerting Policies
```bash
# High CPU usage alert
gcloud alpha monitoring policies create \
    --policy-from-file=cpu-alert-policy.yaml

# Database connection alert
gcloud alpha monitoring policies create \
    --policy-from-file=db-alert-policy.yaml

# Application error rate alert
gcloud alpha monitoring policies create \
    --policy-from-file=error-rate-alert-policy.yaml
```

---

## 🎯 Next Steps

### Post-Deployment Checklist
- [ ] Application responding to health checks
- [ ] Database connectivity verified
- [ ] SSL certificate valid and working
- [ ] Cloud Armor policies active
- [ ] Monitoring and alerting configured
- [ ] Auto-scaling tested
- [ ] Backup and disaster recovery tested

### Production Readiness
1. **Load Testing**: Verify performance under expected load
2. **Security Review**: Complete security audit
3. **Disaster Recovery**: Test backup and restore procedures
4. **Monitoring**: Fine-tune alerting thresholds
5. **Documentation**: Update operational runbooks

Ready for enterprise-scale authentication on Google Cloud! 🚀☁️