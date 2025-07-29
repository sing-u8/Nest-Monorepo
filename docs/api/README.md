# Auth Service API Documentation

## Overview

The Auth Service provides a comprehensive authentication and user management API built with NestJS and following clean architecture principles. It supports multiple authentication methods including JWT-based login, OAuth social login (Google/Apple), and mTLS certificate authentication.

## Features

- 🔐 **JWT Authentication**: Secure token-based authentication with refresh token rotation
- 🌐 **OAuth Social Login**: Google and Apple Sign In integration
- 🔒 **mTLS Support**: Certificate-based authentication for enterprise security
- 👤 **User Management**: Registration, profile management, and session handling
- 📊 **Monitoring**: Comprehensive metrics collection and alerting
- 🛡️ **Security**: Rate limiting, input validation, audit logging, and security headers
- 📈 **Performance**: Request tracking, database monitoring, and external service metrics

## Quick Start

### Base URL

- **Local Development**: `http://localhost:3000`
- **Staging**: `https://api-staging.yourapp.com`
- **Production**: `https://api.yourapp.com`

### API Documentation

Interactive API documentation is available at:
- **Swagger UI**: `/docs` (development and staging only)
- **OpenAPI Schema**: `/docs-json`

### Authentication

The API uses Bearer token authentication for protected endpoints:

```http
Authorization: Bearer <your-jwt-token>
```

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/v1/auth/register` | User registration | No |
| POST | `/api/v1/auth/login` | User login | No |
| POST | `/api/v1/auth/refresh` | Refresh access token | No |
| POST | `/api/v1/auth/logout` | User logout | Yes |

### OAuth Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/auth/google` | Initiate Google OAuth | No |
| GET | `/api/v1/auth/google/callback` | Google OAuth callback | No |
| GET | `/api/v1/auth/apple` | Initiate Apple Sign In | No |
| POST | `/api/v1/auth/apple/callback` | Apple Sign In callback | No |
| GET | `/api/v1/auth/oauth/config` | OAuth configuration | No |

### Profile Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/profile` | Get user profile | Yes |
| PUT | `/api/v1/profile` | Update user profile | Yes |
| POST | `/api/v1/profile/picture` | Upload profile picture | Yes |
| PUT | `/api/v1/profile/picture/delete` | Delete profile picture | Yes |

### Health Check Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/health` | Basic health check | No |
| GET | `/health/detailed` | Detailed health information | No |
| GET | `/health/ready` | Readiness probe | No |
| GET | `/health/live` | Liveness probe | No |
| GET | `/health/external` | External services health | No |
| GET | `/health/security` | Security configuration health | No |
| GET | `/health/comprehensive` | Complete system health | No |
| GET | `/health/status` | Simple status for monitoring | No |
| GET | `/health/info` | Application information | No |

### Metrics Endpoints (Protected)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/metrics` | All metrics summaries | Yes |
| GET | `/api/v1/metrics/summary` | Specific metric summary | Yes |
| GET | `/api/v1/metrics/export` | Export metrics | Yes |
| GET | `/api/v1/metrics/auth` | Authentication metrics | Yes |
| GET | `/api/v1/metrics/performance` | Performance metrics | Yes |
| GET | `/api/v1/metrics/security` | Security metrics | Yes |
| GET | `/api/v1/metrics/system` | System metrics | Yes |
| GET | `/api/v1/metrics/health` | Metrics service health | Yes |

### Alerting Endpoints (Protected)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/alerting/rules` | Get all alert rules | Yes |
| POST | `/api/v1/alerting/rules` | Add alert rule | Yes |
| DELETE | `/api/v1/alerting/rules/:id` | Remove alert rule | Yes |
| GET | `/api/v1/alerting/alerts` | Get active alerts | Yes |
| GET | `/api/v1/alerting/alerts/all` | Get all alerts | Yes |
| PUT | `/api/v1/alerting/alerts/:id/resolve` | Resolve alert | Yes |
| POST | `/api/v1/alerting/alerts/trigger` | Trigger manual alert | Yes |
| POST | `/api/v1/alerting/rules/check` | Check all rules | Yes |
| GET | `/api/v1/alerting/health` | Alerting service health | Yes |

## Authentication Flows

### 1. Email/Password Registration

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant DB
    
    Client->>API: POST /auth/register
    API->>API: Validate input
    API->>DB: Check email exists
    API->>API: Hash password
    API->>DB: Create user
    API->>API: Generate JWT tokens
    API->>DB: Create session
    API->>Client: Return tokens + user data
```

### 2. Email/Password Login

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant DB
    
    Client->>API: POST /auth/login
    API->>DB: Find user by email
    API->>API: Verify password
    API->>API: Generate JWT tokens
    API->>DB: Create/update session
    API->>Client: Return tokens + user data
```

### 3. Google OAuth Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Google
    participant DB
    
    Client->>API: GET /auth/google
    API->>Client: Redirect to Google
    Client->>Google: Authorize
    Google->>API: GET /auth/google/callback?code=...
    API->>Google: Exchange code for tokens
    Google->>API: Return user profile
    API->>DB: Find or create user
    API->>API: Generate JWT tokens
    API->>DB: Create session
    API->>Client: Redirect with tokens
```

### 4. Token Refresh

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant DB
    
    Client->>API: POST /auth/refresh
    API->>API: Validate refresh token
    API->>DB: Check token in database
    API->>DB: Verify user status
    API->>API: Generate new tokens
    API->>DB: Revoke old refresh token
    API->>DB: Save new refresh token
    API->>Client: Return new tokens
```

## Request/Response Examples

### User Registration

**Request:**
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "name": "John Doe"
}
```

**Response:**
```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIs...",
    "expiresIn": 900,
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "name": "John Doe",
      "provider": "local",
      "profilePicture": null,
      "createdAt": "2023-12-01T10:00:00.000Z"
    }
  }
}
```

### User Login

**Request:**
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "message": "Login successful",
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIs...",
    "expiresIn": 900,
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "name": "John Doe",
      "provider": "local",
      "profilePicture": null,
      "lastLoginAt": "2023-12-01T10:00:00.000Z"
    }
  }
}
```

### Get User Profile

**Request:**
```http
GET /api/v1/profile
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "data": {
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "name": "John Doe",
      "profilePicture": "https://example.com/profiles/john-doe.jpg",
      "provider": "local",
      "bio": "Software developer passionate about clean code",
      "location": "San Francisco, CA",
      "website": "https://johndoe.dev",
      "createdAt": "2023-12-01T10:00:00.000Z",
      "updatedAt": "2023-12-01T15:30:00.000Z"
    },
    "accountSummary": {
      "daysSinceRegistration": 7,
      "totalSessions": 15,
      "activeSessions": 2,
      "lastActivity": "2023-12-01T15:30:00.000Z"
    },
    "activeSessions": [
      {
        "id": "session_1",
        "deviceInfo": {
          "browser": "Chrome",
          "os": "macOS",
          "device": "Desktop"
        },
        "location": {
          "country": "US",
          "city": "San Francisco"
        },
        "createdAt": "2023-12-01T14:00:00.000Z",
        "lastAccessAt": "2023-12-01T15:30:00.000Z",
        "isCurrentSession": true
      }
    ]
  }
}
```

## Error Responses

All API endpoints return consistent error responses:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": [
      {
        "field": "email",
        "errors": ["must be a valid email"],
        "value": "invalid-email"
      }
    ],
    "timestamp": "2023-12-01T10:00:00.000Z",
    "path": "/api/v1/auth/register",
    "errorId": "err_1701423600_abc123"
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Input validation failed |
| `AUTHENTICATION_ERROR` | 401 | Invalid credentials |
| `AUTHORIZATION_ERROR` | 403 | Insufficient permissions |
| `RESOURCE_NOT_FOUND` | 404 | Resource not found |
| `DUPLICATE_RESOURCE` | 409 | Resource already exists |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_SERVER_ERROR` | 500 | Internal server error |

## Rate Limiting

The API implements rate limiting to protect against abuse:

| Endpoint Type | Limit | Window |
|---------------|-------|--------|
| Login | 5 requests | 15 minutes |
| Registration | 3 requests | 1 hour |
| Token Refresh | 50 requests | 15 minutes |
| OAuth | 10 requests | 10 minutes |
| Profile Updates | 20 requests | 1 hour |
| File Uploads | 5 requests | 10 minutes |

Rate limit headers are included in responses:
- `RateLimit-Limit`: Maximum requests allowed
- `RateLimit-Remaining`: Remaining requests in window
- `RateLimit-Reset`: Time when limit resets (Unix timestamp)

## Security

### Authentication Methods

1. **JWT Bearer Tokens**: Primary method for API authentication
2. **OAuth 2.0**: Google and Apple social login
3. **mTLS**: Certificate-based authentication (enterprise)

### Security Headers

The API includes comprehensive security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy: default-src 'self'`

### Input Validation

All inputs are validated and sanitized to prevent:
- SQL injection
- XSS attacks
- Command injection
- Path traversal
- LDAP injection

## Monitoring

### Health Checks

The service provides multiple health check endpoints for different use cases:

- **Basic Health** (`/health`): For load balancers
- **Detailed Health** (`/health/detailed`): For monitoring systems
- **Readiness Probe** (`/health/ready`): For Kubernetes deployments
- **Liveness Probe** (`/health/live`): For container orchestration

### Metrics

Comprehensive metrics are collected for:

- **Authentication Events**: Login/logout, registration, OAuth flows
- **Performance**: Response times, database queries, external calls
- **Security**: Failed attempts, rate limits, suspicious activity
- **System**: Memory usage, CPU usage, active connections

### Alerting

Built-in alerting for security and performance issues:

- High login failure rates
- Rate limit violations
- Brute force attempts
- Slow response times
- High memory usage
- OAuth failures

## Environment Configuration

### Required Environment Variables

```bash
# Application
NODE_ENV=development
PORT=3000
APP_NAME="Auth Service"
API_PREFIX="api/v1"

# Database
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=auth_db
DATABASE_USERNAME=auth_user
DATABASE_PASSWORD=secure_password

# JWT
JWT_SECRET=your-256-bit-secret
JWT_REFRESH_SECRET=your-256-bit-refresh-secret
JWT_ACCESS_TOKEN_EXPIRATION=15m
JWT_REFRESH_TOKEN_EXPIRATION=7d

# OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

APPLE_CLIENT_ID=your-apple-client-id
APPLE_TEAM_ID=your-apple-team-id
APPLE_KEY_ID=your-apple-key-id
APPLE_PRIVATE_KEY=your-apple-private-key
APPLE_CALLBACK_URL=http://localhost:3000/auth/apple/callback

# Security
SECURITY_ENABLE_RATE_LIMITING=true
SECURITY_ENABLE_HELMET=true
FORCE_HTTPS=false

# Monitoring
MONITORING_ENABLE_METRICS=true
MONITORING_ENABLE_ALERTING=true
MONITORING_WEBHOOK_URL=https://your-webhook-url
```

### Optional Environment Variables

```bash
# Redis (for session storage)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_SSL=false

# mTLS
SECURITY_ENABLE_MTLS=false
SECURITY_MTLS_CA_PATH=/path/to/ca.pem
SECURITY_MTLS_CERT_PATH=/path/to/cert.pem
SECURITY_MTLS_KEY_PATH=/path/to/key.pem

# Logging
LOG_LEVEL=info
LOG_FILE_PATH=/var/log/auth-service.log

# Email (for alerts)
MONITORING_EMAIL_TO=admin@yourapp.com
```

## Development

### Local Setup

1. **Clone the repository**
2. **Install dependencies**: `npm install`
3. **Set up environment**: Copy `.env.example` to `.env`
4. **Start database**: `docker-compose up -d postgres`
5. **Run migrations**: `npm run migration:run`
6. **Start development server**: `npm run dev`

### API Testing

Use the interactive Swagger UI at `http://localhost:3000/docs` for testing endpoints.

### Running Tests

```bash
# Unit tests
npm run test

# Integration tests
npm run test:integration

# E2E tests
npm run test:e2e

# Test coverage
npm run test:coverage
```

## Support

- **Documentation**: [https://docs.yourapp.com](https://docs.yourapp.com)
- **API Support**: support@yourapp.com
- **GitHub Issues**: [https://github.com/yourorg/auth-service/issues](https://github.com/yourorg/auth-service/issues)
- **Status Page**: [https://status.yourapp.com](https://status.yourapp.com)