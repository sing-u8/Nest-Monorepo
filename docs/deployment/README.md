# NestJS Auth Service Deployment Guide

This guide provides comprehensive instructions for deploying the NestJS Authentication Service across different environments using Docker, Kubernetes, and CI/CD pipelines.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Environment Configuration](#environment-configuration)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [CI/CD Pipeline](#cicd-pipeline)
- [Monitoring and Health Checks](#monitoring-and-health-checks)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Software

- **Docker**: Version 24.0+ with Docker Compose V2
- **Node.js**: Version 20.x LTS
- **pnpm**: Version 8.x
- **kubectl**: Version 1.28+ (for Kubernetes deployment)
- **Git**: Version 2.40+

### Infrastructure Requirements

#### Minimum System Requirements

- **CPU**: 2 cores
- **Memory**: 4GB RAM
- **Storage**: 20GB available disk space
- **Network**: Stable internet connection

#### Production Requirements

- **CPU**: 4 cores per instance (3 instances recommended)
- **Memory**: 8GB RAM per instance
- **Storage**: 100GB SSD with backup
- **Database**: PostgreSQL 16+ with replication
- **Cache**: Redis 7+ with persistence
- **Load Balancer**: Nginx or cloud provider LB

## Environment Configuration

### 1. Environment Variables Setup

Copy the environment template and configure for your deployment:

```bash
cp .env.example .env
```

#### Required Environment Variables

```bash
# Application
NODE_ENV=production
PORT=3000
APP_NAME="Auth Service"

# Database (Required)
DATABASE_HOST=postgres-host
DATABASE_PORT=5432
DATABASE_USERNAME=auth_user
DATABASE_PASSWORD=your_secure_password
DATABASE_NAME=auth_db

# JWT Secrets (Required - Generate with crypto.randomBytes(32).toString('hex'))
JWT_SECRET=your-256-bit-jwt-secret-key
JWT_REFRESH_SECRET=your-256-bit-refresh-secret-key

# OAuth (Optional but recommended)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
APPLE_CLIENT_ID=your.app.bundle.id
APPLE_TEAM_ID=YOUR_TEAM_ID
APPLE_KEY_ID=YOUR_KEY_ID
APPLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
```

### 2. SSL Certificate Setup

For production deployments, configure SSL certificates:

```bash
# Create SSL directory
mkdir -p ssl/

# Copy your certificates
cp your-cert.pem ssl/cert.pem
cp your-private-key.pem ssl/key.pem
cp your-ca-bundle.pem ssl/ca.pem

# Set proper permissions
chmod 600 ssl/*.pem
```

## Docker Deployment

### Development Environment

Start the development environment with hot reloading:

```bash
# Start development services
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# View logs
docker-compose logs -f auth-service

# Access development tools
docker-compose --profile tools up -d pgadmin redis-commander
```

Development services will be available at:
- **Auth Service**: http://localhost:3001
- **API Documentation**: http://localhost:3001/docs
- **PgAdmin**: http://localhost:8080 (admin@localhost.com / admin123)
- **Redis Commander**: http://localhost:8081

### Production Environment

Deploy to production with security hardening:

```bash
# Build and start production services
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Verify deployment
docker-compose ps
docker-compose logs auth-service

# Health check
curl https://your-domain.com/health
```

### Docker Commands Reference

```bash
# Build custom image
docker build -t auth-service:custom .

# Run single container
docker run -d \
  --name auth-service \
  -p 3000:3000 \
  --env-file .env \
  auth-service:latest

# Container management
docker logs -f auth-service
docker exec -it auth-service sh
docker stop auth-service
docker rm auth-service

# Cleanup
docker-compose down -v
docker system prune -a
```

## Kubernetes Deployment

### 1. Cluster Preparation

Ensure your Kubernetes cluster meets requirements:

```bash
# Verify cluster access
kubectl cluster-info
kubectl get nodes

# Create namespace
kubectl apply -f k8s/namespace.yaml

# Verify namespace
kubectl get namespace auth-service
```

### 2. Secrets Configuration

Update Kubernetes secrets with your actual values:

```bash
# Generate base64 encoded secrets
echo -n "your-database-password" | base64
echo -n "your-jwt-secret" | base64

# Apply secrets (after updating k8s/secret.yaml)
kubectl apply -f k8s/secret.yaml

# Verify secrets
kubectl get secrets -n auth-service
```

### 3. ConfigMap and Deployment

```bash
# Apply configuration
kubectl apply -f k8s/configmap.yaml

# Deploy application
kubectl apply -f k8s/deployment.yaml

# Create services
kubectl apply -f k8s/service.yaml

# Verify deployment
kubectl get pods -n auth-service
kubectl rollout status deployment/auth-service -n auth-service
```

### 4. Ingress Setup (Optional)

Create an ingress for external access:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-service-ingress
  namespace: auth-service
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - auth.yourapp.com
    secretName: auth-service-tls
  rules:
  - host: auth.yourapp.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-service
            port:
              number: 80
```

### Kubernetes Commands Reference

```bash
# Deployment management
kubectl get deployments -n auth-service
kubectl describe deployment auth-service -n auth-service
kubectl scale deployment auth-service --replicas=5 -n auth-service

# Pod management
kubectl get pods -n auth-service
kubectl logs -f pod/auth-service-xxx -n auth-service
kubectl exec -it pod/auth-service-xxx -n auth-service -- sh

# Service management
kubectl get services -n auth-service
kubectl port-forward service/auth-service 3000:80 -n auth-service

# Configuration management
kubectl get configmap -n auth-service
kubectl describe configmap auth-service-config -n auth-service

# Rollout management
kubectl rollout restart deployment/auth-service -n auth-service
kubectl rollout undo deployment/auth-service -n auth-service
kubectl rollout history deployment/auth-service -n auth-service

# Cleanup
kubectl delete -f k8s/
kubectl delete namespace auth-service
```

## CI/CD Pipeline

### GitHub Actions Setup

The repository includes two main workflows:

1. **CI Pipeline** (`.github/workflows/ci.yml`)
   - Code quality checks
   - Security audits
   - Unit and integration tests
   - Docker image building

2. **Deployment Pipeline** (`.github/workflows/deploy.yml`)
   - Multi-stage deployments
   - Blue-green deployment strategy
   - Automated rollbacks
   - Production verification

### Required GitHub Secrets

Configure the following secrets in your GitHub repository:

```bash
# Kubernetes Configuration
KUBE_CONFIG_STAGING=<base64-encoded-kubeconfig>
KUBE_CONFIG_PRODUCTION=<base64-encoded-kubeconfig>

# Container Registry
GHCR_TOKEN=<github-personal-access-token>

# Notification Services (Optional)
SLACK_WEBHOOK=<slack-webhook-url>
TEAMS_WEBHOOK=<teams-webhook-url>
```

### Manual Deployment

Trigger manual deployments using GitHub Actions:

1. Go to **Actions** tab in your repository
2. Select **Deploy to Production** workflow
3. Click **Run workflow**
4. Choose environment (staging/production)
5. Monitor deployment progress

### Deployment Verification

After deployment, verify the service:

```bash
# Health check
curl https://your-domain.com/health

# API availability
curl https://your-domain.com/api/v1/auth/oauth/config

# Authentication test
curl -X POST https://your-domain.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123!","name":"Test User"}'
```

## Monitoring and Health Checks

### Health Check Endpoints

The service provides multiple health check endpoints:

- **`/health`** - Basic health check for load balancers
- **`/health/detailed`** - Comprehensive system health
- **`/health/ready`** - Kubernetes readiness probe
- **`/health/live`** - Kubernetes liveness probe
- **`/health/external`** - External service dependencies
- **`/health/security`** - Security configuration status

### Monitoring Integration

#### Prometheus Metrics

```yaml
# Add to your Prometheus configuration
scrape_configs:
  - job_name: 'auth-service'
    static_configs:
      - targets: ['auth-service:3000']
    metrics_path: '/api/v1/metrics'
    scrape_interval: 30s
```

#### Grafana Dashboard

Import the provided dashboard configuration for visualization:
- Authentication metrics
- Performance monitoring
- Security events
- System resource usage

### Log Aggregation

Configure log shipping to your preferred system:

```bash
# Using Fluentd
kubectl apply -f monitoring/fluentd-config.yaml

# Using Filebeat
kubectl apply -f monitoring/filebeat-config.yaml
```

## Troubleshooting

### Common Issues

#### 1. Container Won't Start

```bash
# Check container logs
docker logs auth-service

# Common causes:
# - Missing environment variables
# - Database connection issues
# - Port conflicts
# - Insufficient permissions
```

#### 2. Database Connection Failed

```bash
# Verify database connectivity
docker exec -it auth-service sh
ping postgres-host
telnet postgres-host 5432

# Check configuration
echo $DATABASE_HOST
echo $DATABASE_PORT
```

#### 3. JWT Authentication Issues

```bash
# Verify JWT configuration
curl http://localhost:3000/health/security

# Check secret encoding
echo $JWT_SECRET | base64 -d
```

#### 4. Kubernetes Pod Crashes

```bash
# Check pod status
kubectl describe pod auth-service-xxx -n auth-service

# View recent logs
kubectl logs --previous auth-service-xxx -n auth-service

# Check resource limits
kubectl top pod auth-service-xxx -n auth-service
```

### Performance Optimization

#### Database Optimization

```sql
-- Check connection pool usage
SELECT count(*) FROM pg_stat_activity WHERE datname = 'auth_db';

-- Optimize queries
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'user@example.com';

-- Create additional indexes if needed
CREATE INDEX CONCURRENTLY idx_users_email_status ON users (email, status);
```

#### Application Optimization

```bash
# Monitor memory usage
docker stats auth-service

# Check for memory leaks
kubectl top pod -n auth-service

# Analyze performance
curl http://localhost:3000/api/v1/metrics/performance
```

### Backup and Recovery

#### Database Backup

```bash
# Create backup
docker exec postgres pg_dump -U auth_user auth_db > backup_$(date +%Y%m%d).sql

# Restore backup
docker exec -i postgres psql -U auth_user auth_db < backup_20240101.sql
```

#### Configuration Backup

```bash
# Backup Kubernetes secrets
kubectl get secret auth-service-secrets -n auth-service -o yaml > secrets-backup.yaml

# Backup environment configuration
cp .env .env.backup.$(date +%Y%m%d)
```

### Support and Updates

#### Getting Help

- **Documentation**: Check this deployment guide and API documentation
- **Health Checks**: Use `/health/detailed` for system diagnostics
- **Logs**: Always check application logs first
- **GitHub Issues**: Report issues with deployment logs and configuration

#### Updating the Service

```bash
# Update to latest version
docker pull ghcr.io/yourorg/auth-service:latest

# Rolling update in Kubernetes
kubectl set image deployment/auth-service auth-service=ghcr.io/yourorg/auth-service:v1.1.0 -n auth-service

# Verify update
kubectl rollout status deployment/auth-service -n auth-service
```

#### Security Updates

- Monitor security advisories for dependencies
- Update base images regularly
- Rotate secrets periodically
- Review access logs for suspicious activity

---

For additional help or questions, please refer to the [API Documentation](../api/README.md) or create an issue in the repository.