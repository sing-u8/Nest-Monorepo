# Auth Service Deployment Guide

Complete deployment guide for the NestJS Authentication Service with Docker, Kubernetes, and CI/CD integration.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Environment Configuration](#environment-configuration)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [CI/CD Pipeline](#cicd-pipeline)
- [Monitoring and Health Checks](#monitoring-and-health-checks)
- [Security Configuration](#security-configuration)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Software
- Docker 20.10+
- Docker Compose 2.0+
- Node.js 18+ (for local development)
- kubectl (for Kubernetes deployment)
- helm 3+ (optional, for advanced Kubernetes deployment)

### Required Services
- PostgreSQL 15+ database
- Redis 7+ cache server
- SSL certificates for HTTPS
- OAuth credentials (Google, Apple)

## Environment Configuration

### 1. Environment Files

Create environment-specific configuration files:

```bash
# Copy example environment file
cp apps/auth-service/.env.example apps/auth-service/.env.production

# Edit production configuration
nano apps/auth-service/.env.production
```

### 2. Required Environment Variables

#### Database Configuration
```bash
DB_HOST=your-database-host
DB_PORT=5432
DB_USERNAME=auth_user_prod
DB_PASSWORD=your-secure-production-password
DB_NAME=auth_service_prod
DB_SSL=true
```

#### JWT Secrets (Generate secure 512-bit secrets)
```bash
JWT_SECRET=your-super-secure-jwt-secret-512-bits-minimum
JWT_REFRESH_SECRET=your-super-secure-refresh-secret-512-bits-minimum
```

#### OAuth Configuration
```bash
# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Apple OAuth
APPLE_CLIENT_ID=com.yourcompany.yourapp
APPLE_TEAM_ID=your-apple-team-id
APPLE_KEY_ID=your-apple-key-id
APPLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nyour-apple-private-key\n-----END PRIVATE KEY-----"
```

## Docker Deployment

### 1. Local Development

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose -f docker-compose.dev.yml logs -f auth-service-dev

# Stop services
docker-compose -f docker-compose.dev.yml down
```

### 2. Production Deployment

```bash
# Build and start production services
docker-compose up -d

# Check service health
curl http://localhost:3000/health

# View production logs
docker-compose logs -f auth-service

# Stop production services
docker-compose down
```

### 3. Database Migration

```bash
# Run database migrations
docker-compose exec auth-service npm run migration:run

# Check migration status
docker-compose exec auth-service npm run migration:show
```

## Kubernetes Deployment

### 1. Prepare Kubernetes Resources

```bash
# Create namespace
kubectl apply -f k8s/namespace.yml

# Create secrets (update with your values first)
kubectl apply -f k8s/secret.yml

# Create config map
kubectl apply -f k8s/configmap.yml
```

### 2. Deploy Application

```bash
# Deploy auth service
kubectl apply -f k8s/deployment.yml

# Create service and ingress
kubectl apply -f k8s/service.yml

# Check deployment status
kubectl get pods -n auth-service
kubectl get services -n auth-service
kubectl get ingress -n auth-service
```

### 3. Verify Deployment

```bash
# Check pod logs
kubectl logs -f deployment/auth-service -n auth-service

# Port forward for testing
kubectl port-forward service/auth-service 3000:80 -n auth-service

# Test health endpoint
curl http://localhost:3000/health
```

### 4. Database Setup in Kubernetes

If using an external database, ensure:
1. Database is accessible from the cluster
2. Firewall rules allow connections
3. SSL certificates are properly configured

For in-cluster database:
```bash
# Deploy PostgreSQL (example)
helm install postgres bitnami/postgresql \\
  --set auth.postgresPassword=your-password \\
  --set auth.database=auth_service \\
  --namespace auth-service
```

## CI/CD Pipeline

### GitHub Actions Setup

1. **Repository Secrets**: Configure in GitHub Settings > Secrets and variables > Actions

```bash
# Required secrets
SNYK_TOKEN=your-snyk-token
SLACK_WEBHOOK_URL=your-slack-webhook-url
KUBE_CONFIG=your-kubernetes-config-base64-encoded
```

2. **Environment Protection**: Configure environments in GitHub Settings > Environments
   - `staging`: Require reviewers for deployment
   - `production`: Require reviewers and branch protection

3. **Container Registry**: GitHub Container Registry is used automatically

### Pipeline Stages

1. **Test Stage**: Runs unit, integration, and e2e tests
2. **Security Stage**: Runs npm audit and Snyk security scanning
3. **Build Stage**: Builds and pushes Docker image to registry
4. **Deploy Staging**: Automatic deployment to staging on `develop` branch
5. **Deploy Production**: Manual deployment to production on `main` branch

### Manual Deployment

```bash
# Build and tag image manually
docker build -t auth-service:latest -f apps/auth-service/Dockerfile .

# Push to registry
docker tag auth-service:latest ghcr.io/your-org/auth-service:latest
docker push ghcr.io/your-org/auth-service:latest

# Update Kubernetes deployment
kubectl set image deployment/auth-service auth-service=ghcr.io/your-org/auth-service:latest -n auth-service
```

## Monitoring and Health Checks

### Available Health Endpoints

```bash
# Basic health check
GET /health

# Liveness probe (Kubernetes)
GET /health/live

# Readiness probe (Kubernetes)
GET /health/ready

# Detailed system status
GET /health/status

# Application metrics
GET /health/metrics

# Prometheus metrics
GET /health/metrics/prometheus
```

### Monitoring Setup

1. **Application Metrics**: Available at `/health/metrics`
2. **Prometheus Integration**: Metrics exposed at `/health/metrics/prometheus`
3. **Structured Logging**: JSON logs for log aggregation systems
4. **Alert Rules**: Configurable alerting for security and performance events

### Log Aggregation

Logs are structured JSON format suitable for:
- Elasticsearch/ELK Stack
- AWS CloudWatch
- Datadog
- Splunk
- Fluentd

## Security Configuration

### 1. mTLS Configuration

```bash
# Generate CA certificate
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -sha256 -key ca-key.pem -out ca-cert.pem -days 365

# Generate client certificate
openssl genrsa -out client-key.pem 4096
openssl req -new -key client-key.pem -out client.csr
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -out client-cert.pem -days 365
```

### 2. Security Headers

Configured automatically via Helmet middleware:
- Content Security Policy
- HSTS (HTTP Strict Transport Security)
- X-Frame-Options
- X-Content-Type-Options

### 3. Rate Limiting

- Global: 100 requests/minute
- Authentication endpoints: 10 requests/minute
- Login endpoint: 5 requests/5 minutes

## Troubleshooting

### Common Issues

#### 1. Database Connection Issues

```bash
# Check database connectivity
kubectl exec -it deployment/auth-service -n auth-service -- npm run typeorm -- query "SELECT 1"

# Check environment variables
kubectl exec -it deployment/auth-service -n auth-service -- env | grep DB_
```

#### 2. OAuth Configuration Issues

```bash
# Verify OAuth secrets are properly encoded
echo "your-google-client-secret" | base64

# Check OAuth redirect URIs match your domain
curl -I https://your-domain.com/api/auth/google/callback
```

#### 3. Performance Issues

```bash
# Check application metrics
curl https://your-domain.com/health/metrics

# Monitor slow operations
curl https://your-domain.com/health/performance/slow

# Check resource usage
kubectl top pods -n auth-service
```

#### 4. SSL/TLS Issues

```bash
# Verify certificate expiration
openssl x509 -in /path/to/cert.pem -text -noout | grep "Not After"

# Test SSL connection
openssl s_client -connect your-domain.com:443 -servername your-domain.com
```

### Health Check Failures

#### Database Health Check Failing
```bash
# Check database connection
kubectl exec -it deployment/auth-service -n auth-service -- npm run typeorm -- connection:show

# Verify database migrations
kubectl exec -it deployment/auth-service -n auth-service -- npm run migration:show
```

#### External Service Health Check Failing
```bash
# Test OAuth provider connectivity
curl -I https://accounts.google.com/.well-known/openid-configuration
curl -I https://appleid.apple.com/.well-known/openid_configuration
```

### Scaling Considerations

#### Horizontal Scaling
```bash
# Scale replicas
kubectl scale deployment auth-service --replicas=5 -n auth-service

# Configure HPA (Horizontal Pod Autoscaler)
kubectl autoscale deployment auth-service --cpu-percent=70 --min=3 --max=10 -n auth-service
```

#### Database Connection Pooling
- Monitor connection pool usage via `/health/metrics`
- Adjust `DB_POOL_SIZE` based on replica count
- Consider using connection pooler like PgBouncer

### Backup and Recovery

#### Database Backup
```bash
# Create database backup
kubectl exec -it postgres-pod -- pg_dump -U auth_user auth_service > backup.sql

# Restore database
kubectl exec -i postgres-pod -- psql -U auth_user auth_service < backup.sql
```

#### Configuration Backup
```bash
# Export Kubernetes resources
kubectl get all,secrets,configmaps -n auth-service -o yaml > auth-service-backup.yaml
```

### Support and Maintenance

- **Log Monitoring**: Monitor application logs for errors and security events
- **Performance Monitoring**: Track response times and resource usage
- **Security Updates**: Regularly update dependencies and container images
- **Certificate Renewal**: Monitor SSL certificate expiration dates
- **Database Maintenance**: Regular vacuum and analyze operations

For additional support, check:
- Application logs: `kubectl logs -f deployment/auth-service -n auth-service`
- Health endpoints: `https://your-domain.com/health/status`
- Metrics dashboard: `https://your-domain.com/health/metrics`