# AWS Cloud Deployment Guide

This guide walks you through deploying the Rust Auth Service on AWS using managed services for a production-ready, scalable deployment.

## 🎯 Overview

AWS deployment provides:
- **EKS Managed Kubernetes** for container orchestration
- **RDS Database** with automated backups and high availability
- **ElastiCache Redis** for high-performance caching
- **Application Load Balancer** with SSL termination
- **Auto Scaling** for traffic-based scaling
- **CloudWatch** monitoring and alerting

## 🏗️ Architecture

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  Route 53 (DNS)     │    │  CloudFront (CDN)   │    │   WAF (Security)    │
│  Domain Management  │────│  Global Distribution│────│   DDoS Protection   │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
           │                           │                           │
           └───────────────────────────┼───────────────────────────┘
                                      │
                 ┌─────────────────────┴─────────────────────┐
                 │        Application Load Balancer         │
                 │        SSL Termination & Routing         │
                 └─────────────────────┬─────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                   EKS Cluster (Kubernetes)               │
        │  ┌─────────────────┐    ┌─────────────────┐             │
        │  │   Auth Service  │    │   Admin Panel   │             │
        │  │   (3 replicas)  │    │   (2 replicas)  │             │
        │  └─────────────────┘    └─────────────────┘             │
        └─────────────────────────────┬─────────────────────────────┘
                                      │
    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
    │   RDS Database  │    │  ElastiCache    │    │   S3 Storage    │
    │   Multi-AZ      │────│  Redis Cluster  │────│   Backups/Logs  │
    │   Auto Backup   │    │   High Avail.   │    │   Static Assets │
    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📋 Prerequisites

### Required AWS Services
- **AWS CLI**: Version 2.0+ configured with appropriate permissions
- **kubectl**: Kubernetes command-line tool
- **eksctl**: EKS cluster management tool
- **helm**: Kubernetes package manager

### Required Permissions
Your AWS credentials need the following managed policies:
- `AmazonEKSClusterPolicy`
- `AmazonEKSWorkerNodePolicy`
- `AmazonEKS_CNI_Policy`
- `AmazonEC2ContainerRegistryReadOnly`
- `AmazonRDSFullAccess`
- `AmazonElastiCacheFullAccess`
- `AmazonRoute53FullAccess`

### Installation Commands
```bash
# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Install eksctl
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

## 🚀 Step-by-Step Deployment

### Step 1: Infrastructure Setup

#### 1.1 Create EKS Cluster
```bash
# Create cluster configuration
cat > cluster-config.yaml << EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: rust-auth-service-cluster
  region: us-west-2
  version: "1.28"

iam:
  withOIDC: true

managedNodeGroups:
  - name: auth-service-nodes
    instanceType: t3.medium
    minSize: 2
    maxSize: 10
    desiredCapacity: 3
    volumeSize: 50
    ssh:
      allow: false
    iam:
      withAddonPolicies:
        autoScaler: true
        cloudWatch: true
        ebs: true
        efs: true
        albIngress: true

addons:
  - name: vpc-cni
  - name: coredns
  - name: kube-proxy
  - name: aws-ebs-csi-driver
EOF

# Create the cluster (takes 15-20 minutes)
eksctl create cluster -f cluster-config.yaml
```

#### 1.2 Configure kubectl
```bash
# Update kubeconfig
aws eks update-kubeconfig --region us-west-2 --name rust-auth-service-cluster

# Verify connection
kubectl get nodes
```

#### 1.3 Install AWS Load Balancer Controller
```bash
# Download IAM policy
curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.7.2/docs/install/iam_policy.json

# Create IAM policy
aws iam create-policy \
    --policy-name AWSLoadBalancerControllerIAMPolicy \
    --policy-document file://iam_policy.json

# Create IAM service account
eksctl create iamserviceaccount \
  --cluster=rust-auth-service-cluster \
  --namespace=kube-system \
  --name=aws-load-balancer-controller \
  --role-name AmazonEKSLoadBalancerControllerRole \
  --attach-policy-arn=arn:aws:iam::ACCOUNT-ID:policy/AWSLoadBalancerControllerIAMPolicy \
  --approve

# Install controller
helm repo add eks https://aws.github.io/eks-charts
helm repo update
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=rust-auth-service-cluster \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller
```

### Step 2: Database Setup

#### 2.1 Create RDS PostgreSQL Instance
```bash
# Create DB subnet group
aws rds create-db-subnet-group \
    --db-subnet-group-name rust-auth-service-subnet-group \
    --db-subnet-group-description "Subnet group for Rust Auth Service" \
    --subnet-ids subnet-12345678 subnet-87654321

# Create security group for RDS
aws ec2 create-security-group \
    --group-name rust-auth-service-db-sg \
    --description "Security group for Rust Auth Service database"

# Allow PostgreSQL access from EKS nodes
aws ec2 authorize-security-group-ingress \
    --group-id sg-0123456789abcdef0 \
    --protocol tcp \
    --port 5432 \
    --source-group sg-eks-cluster-sg-rust-auth-service-cluster

# Create RDS instance
aws rds create-db-instance \
    --db-name auth_service \
    --db-instance-identifier rust-auth-service-db \
    --db-instance-class db.t3.micro \
    --engine postgres \
    --engine-version 15.4 \
    --master-username admin \
    --master-user-password 'SecureDBPassword123!' \
    --allocated-storage 20 \
    --storage-type gp2 \
    --vpc-security-group-ids sg-0123456789abcdef0 \
    --db-subnet-group-name rust-auth-service-subnet-group \
    --backup-retention-period 7 \
    --multi-az \
    --storage-encrypted
```

#### 2.2 Create ElastiCache Redis Cluster
```bash
# Create cache subnet group
aws elasticache create-cache-subnet-group \
    --cache-subnet-group-name rust-auth-service-cache-subnet \
    --cache-subnet-group-description "Cache subnet group for Rust Auth Service" \
    --subnet-ids subnet-12345678 subnet-87654321

# Create security group for Redis
aws ec2 create-security-group \
    --group-name rust-auth-service-redis-sg \
    --description "Security group for Rust Auth Service Redis"

# Allow Redis access from EKS nodes
aws ec2 authorize-security-group-ingress \
    --group-id sg-redis123456789 \
    --protocol tcp \
    --port 6379 \
    --source-group sg-eks-cluster-sg-rust-auth-service-cluster

# Create Redis cluster
aws elasticache create-replication-group \
    --replication-group-id rust-auth-service-redis \
    --description "Redis cluster for Rust Auth Service" \
    --num-cache-clusters 2 \
    --cache-node-type cache.t3.micro \
    --engine redis \
    --engine-version 7.0 \
    --cache-parameter-group default.redis7 \
    --cache-subnet-group-name rust-auth-service-cache-subnet \
    --security-group-ids sg-redis123456789 \
    --at-rest-encryption-enabled \
    --transit-encryption-enabled
```

### Step 3: Secrets Management

#### 3.1 Create AWS Secrets Manager Secrets
```bash
# Database connection secret
aws secretsmanager create-secret \
    --name "rust-auth-service/database" \
    --description "Database connection for Rust Auth Service" \
    --secret-string '{
        "username": "admin",
        "password": "SecureDBPassword123!",
        "host": "rust-auth-service-db.cluster-abc123.us-west-2.rds.amazonaws.com",
        "port": 5432,
        "database": "auth_service"
    }'

# JWT secret
aws secretsmanager create-secret \
    --name "rust-auth-service/jwt" \
    --description "JWT secret for Rust Auth Service" \
    --secret-string '{
        "secret": "your-super-secure-jwt-secret-key-256-bits-long"
    }'

# Email provider secret
aws secretsmanager create-secret \
    --name "rust-auth-service/email" \
    --description "Email provider credentials" \
    --secret-string '{
        "provider": "sendgrid",
        "api_key": "your-sendgrid-api-key"
    }'
```

#### 3.2 Install AWS Secrets Manager CSI Driver
```bash
# Install secrets store CSI driver
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver \
    --namespace kube-system \
    --set syncSecret.enabled=true

# Install AWS provider
kubectl apply -f https://raw.githubusercontent.com/aws/secrets-store-csi-driver-provider-aws/main/deployment/aws-provider-installer.yaml
```

### Step 4: Application Deployment

#### 4.1 Create Kubernetes Namespace and RBAC
```bash
# Create namespace
kubectl create namespace auth-service

# Create service account for secrets access
cat > service-account.yaml << EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: auth-service-sa
  namespace: auth-service
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT-ID:role/auth-service-secrets-role
---
apiVersion: v1
kind: Secret
metadata:
  name: auth-service-sa-token
  namespace: auth-service
  annotations:
    kubernetes.io/service-account.name: auth-service-sa
type: kubernetes.io/service-account-token
EOF

kubectl apply -f service-account.yaml
```

#### 4.2 Create Secrets Provider Class
```bash
cat > secrets-provider.yaml << EOF
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: rust-auth-service-secrets
  namespace: auth-service
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "rust-auth-service/database"
        objectType: "secretsmanager"
        jmesPath:
          - path: "username"
            objectAlias: "db_username"
          - path: "password"
            objectAlias: "db_password"
          - path: "host"
            objectAlias: "db_host"
          - path: "port"
            objectAlias: "db_port"
          - path: "database"
            objectAlias: "db_name"
      - objectName: "rust-auth-service/jwt"
        objectType: "secretsmanager"
        jmesPath:
          - path: "secret"
            objectAlias: "jwt_secret"
      - objectName: "rust-auth-service/email"
        objectType: "secretsmanager"
        jmesPath:
          - path: "provider"
            objectAlias: "email_provider"
          - path: "api_key"
            objectAlias: "email_api_key"
  secretObjects:
  - secretName: rust-auth-service-secrets
    type: Opaque
    data:
    - objectName: "db_username"
      key: "DATABASE_USER"
    - objectName: "db_password"
      key: "DATABASE_PASSWORD"
    - objectName: "db_host"
      key: "DATABASE_HOST"
    - objectName: "db_port"
      key: "DATABASE_PORT"
    - objectName: "db_name"
      key: "DATABASE_NAME"
    - objectName: "jwt_secret"
      key: "JWT_SECRET"
    - objectName: "email_provider"
      key: "EMAIL_PROVIDER"
    - objectName: "email_api_key"
      key: "EMAIL_API_KEY"
EOF

kubectl apply -f secrets-provider.yaml
```

#### 4.3 Deploy Application
```bash
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
  template:
    metadata:
      labels:
        app: rust-auth-service
    spec:
      serviceAccountName: auth-service-sa
      containers:
      - name: auth-service
        image: your-account.dkr.ecr.us-west-2.amazonaws.com/rust-auth-service:latest
        ports:
        - containerPort: 8090
        env:
        - name: RUST_LOG
          value: "info"
        - name: DATABASE_TYPE
          value: "postgresql"
        - name: DATABASE_URL
          value: "postgresql://\$(DATABASE_USER):\$(DATABASE_PASSWORD)@\$(DATABASE_HOST):\$(DATABASE_PORT)/\$(DATABASE_NAME)"
        - name: REDIS_URL
          value: "redis://rust-auth-service-redis.abc123.cache.amazonaws.com:6379"
        - name: SERVER_HOST
          value: "0.0.0.0"
        - name: SERVER_PORT
          value: "8090"
        envFrom:
        - secretRef:
            name: rust-auth-service-secrets
        volumeMounts:
        - name: secrets-store
          mountPath: "/mnt/secrets-store"
          readOnly: true
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
        readinessProbe:
          httpGet:
            path: /health
            port: 8090
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
      volumes:
      - name: secrets-store
        csi:
          driver: secrets-store.csi.k8s.io
          readOnly: true
          volumeAttributes:
            secretProviderClass: rust-auth-service-secrets
---
apiVersion: v1
kind: Service
metadata:
  name: rust-auth-service
  namespace: auth-service
  labels:
    app: rust-auth-service
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 8090
    protocol: TCP
  selector:
    app: rust-auth-service
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rust-auth-service-ingress
  namespace: auth-service
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:us-west-2:ACCOUNT-ID:certificate/12345678-1234-1234-1234-123456789012
    alb.ingress.kubernetes.io/ssl-redirect: '443'
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}, {"HTTPS": 443}]'
spec:
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
              number: 80
EOF

kubectl apply -f deployment.yaml
```

#### 4.4 Set Up Horizontal Pod Autoscaler
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
  maxReplicas: 20
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
EOF

kubectl apply -f hpa.yaml
```

### Step 5: Monitoring and Logging

#### 5.1 Install Prometheus and Grafana
```bash
# Add Prometheus Helm repository
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Install Prometheus
helm install prometheus prometheus-community/kube-prometheus-stack \
    --namespace monitoring \
    --create-namespace \
    --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
    --set grafana.adminPassword='admin123'

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
EOF

kubectl apply -f service-monitor.yaml
```

#### 5.2 Configure CloudWatch Logging
```bash
# Install AWS for Fluent Bit
helm repo add aws https://aws.github.io/eks-charts
helm install aws-for-fluent-bit aws/aws-for-fluent-bit \
    --namespace amazon-cloudwatch \
    --create-namespace \
    --set cloudWatchLogs.region=us-west-2 \
    --set cloudWatchLogs.logGroupName=/aws/eks/rust-auth-service-cluster/application \
    --set firehose.enabled=false \
    --set kinesis.enabled=false
```

### Step 6: SSL Certificate Setup

#### 6.1 Request SSL Certificate via ACM
```bash
# Request certificate
aws acm request-certificate \
    --domain-name auth.yourdomain.com \
    --subject-alternative-names "*.yourdomain.com" \
    --validation-method DNS \
    --region us-west-2

# Note the certificate ARN for ingress configuration
aws acm list-certificates --region us-west-2
```

#### 6.2 Configure Route 53 DNS
```bash
# Create hosted zone (if not exists)
aws route53 create-hosted-zone \
    --name yourdomain.com \
    --caller-reference $(date +%s)

# Create A record pointing to ALB
# (Get ALB DNS name from ingress)
kubectl get ingress rust-auth-service-ingress -n auth-service
```

## 🔧 Configuration and Management

### Environment Configuration
```bash
# Create ConfigMap for non-sensitive configuration
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
EOF

kubectl apply -f configmap.yaml
```

### Scaling Configuration
```bash
# Manual scaling
kubectl scale deployment rust-auth-service --replicas=5 -n auth-service

# Check autoscaler status
kubectl get hpa -n auth-service

# View detailed autoscaler events
kubectl describe hpa rust-auth-service-hpa -n auth-service
```

### Health Checks and Monitoring
```bash
# Check service health
kubectl get pods -n auth-service
kubectl logs -f deployment/rust-auth-service -n auth-service

# Check ingress status
kubectl get ingress -n auth-service
kubectl describe ingress rust-auth-service-ingress -n auth-service

# Test external access
curl -k https://auth.yourdomain.com/health
```

## 📊 Performance Tuning

### Database Optimization
```bash
# Configure RDS parameter group for performance
aws rds create-db-parameter-group \
    --db-parameter-group-name rust-auth-service-postgres15 \
    --db-parameter-group-family postgres15 \
    --description "Optimized parameters for Rust Auth Service"

# Set performance parameters
aws rds modify-db-parameter-group \
    --db-parameter-group-name rust-auth-service-postgres15 \
    --parameters \
        ParameterName=shared_preload_libraries,ParameterValue=pg_stat_statements \
        ParameterName=max_connections,ParameterValue=200 \
        ParameterName=work_mem,ParameterValue=4MB \
        ParameterName=maintenance_work_mem,ParameterValue=256MB \
        ParameterName=effective_cache_size,ParameterValue=1GB

# Apply parameter group to instance
aws rds modify-db-instance \
    --db-instance-identifier rust-auth-service-db \
    --db-parameter-group-name rust-auth-service-postgres15 \
    --apply-immediately
```

### Redis Configuration
```bash
# Configure Redis parameters for performance
aws elasticache create-cache-parameter-group \
    --cache-parameter-group-name rust-auth-service-redis7 \
    --cache-parameter-group-family redis7 \
    --description "Optimized Redis parameters for Rust Auth Service"

# Set Redis parameters
aws elasticache modify-cache-parameter-group \
    --cache-parameter-group-name rust-auth-service-redis7 \
    --parameter-name-values \
        ParameterName=maxmemory-policy,ParameterValue=allkeys-lru \
        ParameterName=timeout,ParameterValue=300 \
        ParameterName=tcp-keepalive,ParameterValue=60
```

## 🛡️ Security Best Practices

### Network Security
```bash
# Create network policy for auth service
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
          name: auth-service
    - podSelector:
        matchLabels:
          app: nginx-ingress
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
    volumeMounts:
    - name: tmp-volume
      mountPath: /tmp
  volumes:
  - name: tmp-volume
    emptyDir: {}
EOF
```

## 🐛 Troubleshooting

### Common Issues

#### 1. Pod Startup Issues
```bash
# Check pod events
kubectl describe pods -n auth-service

# Check logs
kubectl logs -f deployment/rust-auth-service -n auth-service

# Check secrets mounting
kubectl exec -it deployment/rust-auth-service -n auth-service -- ls -la /mnt/secrets-store/
```

#### 2. Database Connection Issues
```bash
# Test database connectivity
kubectl run postgres-client --rm -it --restart=Never --image=postgres:15 -- psql -h rust-auth-service-db.cluster-abc123.us-west-2.rds.amazonaws.com -U admin -d auth_service

# Check security groups
aws ec2 describe-security-groups --group-ids sg-0123456789abcdef0
```

#### 3. Load Balancer Issues
```bash
# Check ALB status
kubectl describe ingress rust-auth-service-ingress -n auth-service

# Check ALB logs
aws logs describe-log-groups --log-group-name-prefix /aws/applicationloadbalancer/
```

#### 4. Autoscaling Issues
```bash
# Check HPA status
kubectl get hpa -n auth-service -o wide

# Check metrics server
kubectl top pods -n auth-service
kubectl top nodes
```

### Performance Monitoring
```bash
# Check CloudWatch metrics
aws cloudwatch get-metric-statistics \
    --namespace AWS/ApplicationELB \
    --metric-name RequestCount \
    --dimensions Name=LoadBalancer,Value=app/rust-auth-service-ingress \
    --start-time 2024-01-01T00:00:00Z \
    --end-time 2024-01-01T23:59:59Z \
    --period 3600 \
    --statistics Sum

# Monitor RDS performance
aws rds describe-db-instances --db-instance-identifier rust-auth-service-db
```

## 💰 Cost Optimization

### Resource Right-Sizing
```bash
# Analyze resource usage
kubectl top pods -n auth-service

# Adjust resource requests/limits based on usage
kubectl patch deployment rust-auth-service -n auth-service -p '{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","resources":{"requests":{"cpu":"50m","memory":"32Mi"},"limits":{"cpu":"200m","memory":"128Mi"}}}]}}}}'
```

### Auto Scaling Optimization
```bash
# Configure cluster autoscaler
cat > cluster-autoscaler.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cluster-autoscaler
  namespace: kube-system
spec:
  template:
    spec:
      containers:
      - image: k8s.gcr.io/autoscaling/cluster-autoscaler:v1.28.2
        name: cluster-autoscaler
        command:
        - ./cluster-autoscaler
        - --v=4
        - --stderrthreshold=info
        - --cloud-provider=aws
        - --skip-nodes-with-local-storage=false
        - --expander=least-waste
        - --node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler/rust-auth-service-cluster
        - --balance-similar-node-groups
        - --skip-nodes-with-system-pods=false
EOF

kubectl apply -f cluster-autoscaler.yaml
```

## 🔄 Maintenance and Updates

### Application Updates
```bash
# Update application image
kubectl set image deployment/rust-auth-service auth-service=your-account.dkr.ecr.us-west-2.amazonaws.com/rust-auth-service:v2.0.0 -n auth-service

# Monitor rollout
kubectl rollout status deployment/rust-auth-service -n auth-service

# Rollback if needed
kubectl rollout undo deployment/rust-auth-service -n auth-service
```

### Cluster Maintenance
```bash
# Update EKS cluster
eksctl update cluster --name rust-auth-service-cluster --region us-west-2

# Update node groups
eksctl update nodegroup --cluster rust-auth-service-cluster --name auth-service-nodes --region us-west-2
```

### Database Maintenance
```bash
# Create database snapshot
aws rds create-db-snapshot \
    --db-instance-identifier rust-auth-service-db \
    --db-snapshot-identifier rust-auth-service-snapshot-$(date +%Y%m%d)

# Schedule automated backups
aws rds modify-db-instance \
    --db-instance-identifier rust-auth-service-db \
    --backup-retention-period 30 \
    --preferred-backup-window "03:00-04:00"
```

## 📈 Monitoring and Alerting

### CloudWatch Alarms
```bash
# High CPU alarm
aws cloudwatch put-metric-alarm \
    --alarm-name "RustAuthService-HighCPU" \
    --alarm-description "Alarm when CPU exceeds 80%" \
    --metric-name CPUUtilization \
    --namespace AWS/EKS \
    --statistic Average \
    --period 300 \
    --threshold 80.0 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 2

# Database connection alarm
aws cloudwatch put-metric-alarm \
    --alarm-name "RustAuthService-DatabaseConnections" \
    --alarm-description "Alarm when database connections exceed 80%" \
    --metric-name DatabaseConnections \
    --namespace AWS/RDS \
    --statistic Average \
    --period 300 \
    --threshold 160 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 2
```

---

## 🎯 Next Steps

### Post-Deployment Checklist
- [ ] Application responding to health checks
- [ ] Database connectivity verified
- [ ] SSL certificate valid and working
- [ ] Monitoring and alerting configured
- [ ] Auto-scaling tested
- [ ] Backup and disaster recovery tested

### Production Readiness
1. **Load Testing**: Verify performance under expected load
2. **Security Audit**: Review all security configurations
3. **Disaster Recovery**: Test backup and restore procedures
4. **Monitoring**: Set up comprehensive alerting
5. **Documentation**: Update runbooks and procedures

Ready for production-scale authentication on AWS! 🚀☁️