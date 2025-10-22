# Kubernetes Production Deployment Guide

This guide covers deploying the Rust Auth Service on Kubernetes for production environments.

## 🎯 Overview

This deployment provides:
- **Production-ready** Kubernetes manifests
- **High availability** with replica sets and health checks  
- **Auto-scaling** based on CPU and memory usage
- **Load balancing** with ingress controllers
- **Security hardening** with RBAC and network policies
- **Monitoring** with Prometheus and Grafana integration

## 🔧 Prerequisites

### Required Tools
- **kubectl**: Kubernetes CLI (v1.25+)
- **helm**: Package manager for Kubernetes (v3.10+)
- **docker**: For building custom images (optional)

### Kubernetes Cluster
- **Kubernetes**: Version 1.25+ 
- **CPU**: 8+ cores available
- **Memory**: 16GB+ available
- **Storage**: 100GB+ with persistent volumes
- **Ingress Controller**: nginx-ingress, traefik, or cloud provider

### Installation Verification
```bash
# Check kubectl
kubectl version --client

# Check helm
helm version

# Check cluster access
kubectl cluster-info
kubectl get nodes
```

## 🚀 Quick Start (Production)

### 1. Clone Repository
```bash
git clone https://github.com/fahdi/rust-auth-service.git
cd rust-auth-service
```

### 2. Configure Environment
```bash
# Copy and edit production values
cp helm/auth-service/values.yaml helm/auth-service/values-prod.yaml
nano helm/auth-service/values-prod.yaml
```

### 3. Deploy with Helm
```bash
# Add required Helm repositories
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Install the auth service
helm install rust-auth-service helm/auth-service \
  --namespace auth-service \
  --create-namespace \
  --values helm/auth-service/values-prod.yaml
```

### 4. Verify Deployment
```bash
# Check deployment status
kubectl get pods -n auth-service
kubectl get services -n auth-service
kubectl get ingress -n auth-service

# Check application health
kubectl port-forward -n auth-service svc/rust-auth-service 8090:8090
curl http://localhost:8090/health
```

## 📋 Detailed Deployment

### Step 1: Namespace and RBAC Setup

#### Create Namespace
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: auth-service
  labels:
    name: auth-service
    environment: production
---
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
    persistentvolumeclaims: "10"
```

#### Apply Namespace
```bash
kubectl apply -f k8s/namespace.yaml
```

#### RBAC Configuration
```yaml
# k8s/rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rust-auth-service
  namespace: auth-service
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: auth-service
  name: rust-auth-service-role
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rust-auth-service-binding
  namespace: auth-service
subjects:
- kind: ServiceAccount
  name: rust-auth-service
  namespace: auth-service
roleRef:
  kind: Role
  name: rust-auth-service-role
  apiGroup: rbac.authorization.k8s.io
```

### Step 2: Secrets and ConfigMaps

#### Secrets Configuration
```bash
# Create JWT secret
kubectl create secret generic jwt-secrets \
  --from-literal=jwt-secret="$(openssl rand -base64 32)" \
  --from-literal=refresh-secret="$(openssl rand -base64 32)" \
  --namespace auth-service

# Create database secrets
kubectl create secret generic database-secrets \
  --from-literal=database-url="mongodb://admin:$(openssl rand -base64 16)@mongodb:27017/auth_service" \
  --from-literal=redis-url="redis://redis:6379" \
  --namespace auth-service

# Create email secrets (example for SMTP)
kubectl create secret generic email-secrets \
  --from-literal=smtp-username="your-smtp-username" \
  --from-literal=smtp-password="your-smtp-password" \
  --namespace auth-service
```

#### ConfigMap for Application Settings
```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-service-config
  namespace: auth-service
data:
  RUST_LOG: "info"
  SERVER_HOST: "0.0.0.0"
  SERVER_PORT: "8090"
  EMAIL_PROVIDER: "smtp"
  SMTP_HOST: "smtp.gmail.com"
  SMTP_PORT: "587"
  SMTP_TLS: "true"
  CACHE_TTL: "3600"
  JWT_EXPIRATION: "3600"
  RATE_LIMIT_REQUESTS: "100"
  RATE_LIMIT_WINDOW: "60"
```

```bash
kubectl apply -f k8s/configmap.yaml
```

### Step 3: Database Deployment

#### MongoDB StatefulSet
```yaml
# k8s/mongodb-statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mongodb
  namespace: auth-service
spec:
  serviceName: mongodb
  replicas: 3
  selector:
    matchLabels:
      app: mongodb
  template:
    metadata:
      labels:
        app: mongodb
    spec:
      containers:
      - name: mongodb
        image: mongo:7.0
        env:
        - name: MONGO_INITDB_ROOT_USERNAME
          value: admin
        - name: MONGO_INITDB_ROOT_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-secrets
              key: mongo-password
        ports:
        - containerPort: 27017
        volumeMounts:
        - name: mongodb-data
          mountPath: /data/db
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          exec:
            command:
            - mongosh
            - --eval
            - "db.adminCommand('ping')"
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - mongosh
            - --eval
            - "db.adminCommand('ping')"
          initialDelaySeconds: 5
          periodSeconds: 5
  volumeClaimTemplates:
  - metadata:
      name: mongodb-data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 20Gi
---
apiVersion: v1
kind: Service
metadata:
  name: mongodb
  namespace: auth-service
spec:
  clusterIP: None
  selector:
    app: mongodb
  ports:
  - port: 27017
    targetPort: 27017
```

#### Redis Deployment
```yaml
# k8s/redis-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: auth-service
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "200m"
        livenessProbe:
          exec:
            command:
            - redis-cli
            - ping
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - redis-cli
            - ping
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: auth-service
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
```

### Step 4: Auth Service Deployment

#### Deployment Configuration
```yaml
# k8s/auth-service-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rust-auth-service
  namespace: auth-service
  labels:
    app: rust-auth-service
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: rust-auth-service
  template:
    metadata:
      labels:
        app: rust-auth-service
    spec:
      serviceAccountName: rust-auth-service
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
      containers:
      - name: auth-service
        image: rust-auth-service:latest
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8090
          name: http
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: database-secrets
              key: redis-url
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: jwt-secrets
              key: jwt-secret
        - name: REFRESH_SECRET
          valueFrom:
            secretKeyRef:
              name: jwt-secrets
              key: refresh-secret
        envFrom:
        - configMapRef:
            name: auth-service-config
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: rust-auth-service
  namespace: auth-service
  labels:
    app: rust-auth-service
spec:
  selector:
    app: rust-auth-service
  ports:
  - port: 8090
    targetPort: http
    name: http
  type: ClusterIP
```

### Step 5: Auto-scaling Configuration

#### Horizontal Pod Autoscaler
```yaml
# k8s/hpa.yaml
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
  maxReplicas: 10
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

### Step 6: Ingress and Load Balancing

#### Ingress Configuration
```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rust-auth-service-ingress
  namespace: auth-service
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      add_header X-Frame-Options "SAMEORIGIN" always;
      add_header X-Content-Type-Options "nosniff" always;
      add_header X-XSS-Protection "1; mode=block" always;
      add_header Referrer-Policy "strict-origin-when-cross-origin" always;
spec:
  tls:
  - hosts:
    - auth.yourdomain.com
    secretName: auth-service-tls
  rules:
  - host: auth.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: rust-auth-service
            port:
              number: 8090
```

#### Network Policy
```yaml
# k8s/network-policy.yaml
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
  - to:
    - podSelector:
        matchLabels:
          app: mongodb
    ports:
    - protocol: TCP
      port: 27017
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
  - to: [] # Allow outbound for email/external APIs
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 587
    - protocol: TCP
      port: 25
```

## 🔧 Helm Chart Deployment

### Helm Values Configuration

#### Production Values
```yaml
# helm/auth-service/values-prod.yaml
replicaCount: 3

image:
  repository: rust-auth-service
  tag: "latest"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 8090

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  hosts:
    - host: auth.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: auth-service-tls
      hosts:
        - auth.yourdomain.com

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

resources:
  limits:
    cpu: 500m
    memory: 1Gi
  requests:
    cpu: 250m
    memory: 512Mi

# Database configuration
mongodb:
  enabled: true
  auth:
    enabled: true
    rootUser: admin
    rootPassword: "your-secure-password"
  persistence:
    enabled: true
    size: 20Gi
  resources:
    limits:
      cpu: 1000m
      memory: 2Gi
    requests:
      cpu: 500m
      memory: 1Gi

redis:
  enabled: true
  auth:
    enabled: false
  master:
    persistence:
      enabled: false
  resources:
    limits:
      cpu: 200m
      memory: 512Mi
    requests:
      cpu: 100m
      memory: 256Mi

# Security configuration
securityContext:
  runAsNonRoot: true
  runAsUser: 1001
  fsGroup: 1001

podSecurityContext:
  seccompProfile:
    type: RuntimeDefault

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
    - ALL

# Environment configuration
env:
  RUST_LOG: info
  JWT_EXPIRATION: "3600"
  RATE_LIMIT_REQUESTS: "100"
  RATE_LIMIT_WINDOW: "60"

# Secrets (create these separately)
existingSecrets:
  jwt: jwt-secrets
  database: database-secrets
  email: email-secrets
```

### Deployment Commands

#### Install with Helm
```bash
# Install dependencies first
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install the auth service
helm install rust-auth-service helm/auth-service \
  --namespace auth-service \
  --create-namespace \
  --values helm/auth-service/values-prod.yaml \
  --wait

# Check deployment status
helm status rust-auth-service -n auth-service
```

#### Upgrade Deployment
```bash
# Upgrade to new version
helm upgrade rust-auth-service helm/auth-service \
  --namespace auth-service \
  --values helm/auth-service/values-prod.yaml \
  --wait

# Rollback if needed
helm rollback rust-auth-service 1 -n auth-service
```

## 📊 Monitoring Setup

### Prometheus Integration

#### ServiceMonitor for Prometheus
```yaml
# k8s/servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: rust-auth-service
  namespace: auth-service
  labels:
    app: rust-auth-service
spec:
  selector:
    matchLabels:
      app: rust-auth-service
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
```

#### Grafana Dashboard ConfigMap
```bash
# Create dashboard configmap
kubectl create configmap grafana-dashboard-auth-service \
  --from-file=grafana/dashboards/auth-service-dashboard.json \
  --namespace monitoring
```

### Alerting Rules

#### PrometheusRule
```yaml
# k8s/prometheus-rules.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: rust-auth-service-rules
  namespace: auth-service
spec:
  groups:
  - name: auth-service.rules
    rules:
    - alert: AuthServiceDown
      expr: up{job="rust-auth-service"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Auth Service is down"
        description: "Auth Service has been down for more than 1 minute"
    
    - alert: AuthServiceHighErrorRate
      expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "High error rate in Auth Service"
        description: "Error rate is {{ $value }} errors per second"
    
    - alert: AuthServiceHighLatency
      expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.1
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High latency in Auth Service"
        description: "95th percentile latency is {{ $value }}s"
```

## 🔒 Security Configuration

### Pod Security Standards
```yaml
# k8s/pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: rust-auth-service-psp
  namespace: auth-service
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'emptyDir'
    - 'secret'
    - 'configMap'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

### Network Security
```bash
# Apply network policies
kubectl apply -f k8s/network-policy.yaml

# Verify network policies
kubectl get networkpolicies -n auth-service
```

## 🛠️ Management Operations

### Deployment Management

#### Check Deployment Status
```bash
# Get all resources
kubectl get all -n auth-service

# Check pod logs
kubectl logs -f deployment/rust-auth-service -n auth-service

# Describe deployment
kubectl describe deployment rust-auth-service -n auth-service
```

#### Rolling Updates
```bash
# Update image
kubectl set image deployment/rust-auth-service auth-service=rust-auth-service:v2.0.0 -n auth-service

# Check rollout status
kubectl rollout status deployment/rust-auth-service -n auth-service

# Rollback if needed
kubectl rollout undo deployment/rust-auth-service -n auth-service
```

#### Scaling
```bash
# Manual scaling
kubectl scale deployment rust-auth-service --replicas=5 -n auth-service

# Check HPA status
kubectl get hpa -n auth-service
kubectl describe hpa rust-auth-service-hpa -n auth-service
```

### Database Operations

#### Database Backup
```bash
# Create backup job
kubectl create job mongodb-backup-$(date +%Y%m%d-%H%M%S) \
  --from=cronjob/mongodb-backup -n auth-service

# Check backup status
kubectl get jobs -n auth-service
```

#### Database Migration
```bash
# Run migration job
kubectl run migration-job \
  --image=rust-auth-service:latest \
  --restart=Never \
  --command -- cargo run --bin migrate up \
  -n auth-service

# Check migration logs
kubectl logs migration-job -n auth-service
```

## 🐛 Troubleshooting

### Common Issues

#### 1. Pod Startup Issues
```bash
# Check pod status
kubectl get pods -n auth-service

# Describe problematic pod
kubectl describe pod <pod-name> -n auth-service

# Check logs
kubectl logs <pod-name> -n auth-service --previous
```

#### 2. Service Discovery Issues
```bash
# Test service connectivity
kubectl run test-pod --image=busybox --rm -it --restart=Never -- /bin/sh

# Inside the pod:
nslookup rust-auth-service.auth-service.svc.cluster.local
wget -O- http://rust-auth-service.auth-service.svc.cluster.local:8090/health
```

#### 3. Ingress Issues
```bash
# Check ingress status
kubectl get ingress -n auth-service
kubectl describe ingress rust-auth-service-ingress -n auth-service

# Check ingress controller logs
kubectl logs -f deployment/nginx-controller -n ingress-nginx
```

#### 4. Database Connectivity
```bash
# Test MongoDB connection
kubectl run mongodb-test --image=mongo:7.0 --rm -it --restart=Never -- \
  mongosh mongodb://admin:password@mongodb.auth-service.svc.cluster.local:27017/auth_service

# Test Redis connection
kubectl run redis-test --image=redis:7-alpine --rm -it --restart=Never -- \
  redis-cli -h redis.auth-service.svc.cluster.local ping
```

### Performance Troubleshooting

#### Resource Usage
```bash
# Check resource usage
kubectl top pods -n auth-service
kubectl top nodes

# Check HPA metrics
kubectl get hpa -n auth-service -o wide
```

#### Metrics and Monitoring
```bash
# Port forward to Prometheus
kubectl port-forward svc/prometheus-server 9090:80 -n monitoring

# Access metrics
curl http://localhost:8090/metrics

# Check service health
curl http://localhost:8090/health
```

## 🚀 Next Steps

### Production Checklist
- [ ] Secrets properly configured
- [ ] TLS certificates installed
- [ ] Monitoring and alerting set up
- [ ] Network policies applied
- [ ] Auto-scaling configured
- [ ] Backup procedures tested
- [ ] Load testing completed

### Advanced Configuration
1. **Multi-cluster setup** for high availability
2. **Service mesh** integration (Istio, Linkerd)
3. **GitOps** deployment with ArgoCD or Flux
4. **Advanced monitoring** with Jaeger tracing
5. **Chaos engineering** with Chaos Monkey

### Security Hardening
1. **Image scanning** with Twistlock or Snyk
2. **Runtime security** with Falco
3. **Policy enforcement** with OPA Gatekeeper
4. **Network segmentation** with Calico
5. **Secrets management** with Vault

Your Rust Auth Service is now ready for production on Kubernetes! 🎉