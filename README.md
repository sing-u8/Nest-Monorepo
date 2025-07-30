# NestJS Authentication Service

A comprehensive authentication service built with NestJS, following clean architecture principles and modern security best practices.

## Features

### 🔐 Authentication & Authorization
- **Multi-provider Authentication**: Local email/password, Google OAuth, Apple Sign In
- **JWT Token Management**: Access tokens with refresh token rotation
- **Session Management**: Secure session handling with activity tracking
- **mTLS Support**: Client certificate authentication for service-to-service communication
- **Role-based Access Control**: Flexible role and permission system

### 🛡️ Security Features
- **Rate Limiting**: Configurable rate limits for different endpoints
- **Input Validation**: Comprehensive input sanitization and validation
- **Audit Logging**: Detailed security event logging and audit trails
- **Password Security**: Bcrypt hashing with configurable salt rounds
- **CORS Protection**: Configurable cross-origin resource sharing
- **Security Headers**: Helmet integration for security headers

### 📊 Monitoring & Observability
- **Health Checks**: Comprehensive application and dependency health monitoring
- **Metrics Collection**: Authentication events, performance, and system metrics
- **Prometheus Integration**: Metrics export in Prometheus format
- **Structured Logging**: JSON logs with correlation IDs and security events
- **Alert System**: Configurable alerting for security and performance issues

### 🏗️ Architecture & Development
- **Clean Architecture**: Domain-driven design with clear separation of concerns
- **TypeScript**: Full TypeScript implementation with strict typing
- **Database**: PostgreSQL with TypeORM and automated migrations
- **Testing**: 900+ test cases with unit, integration, and e2e tests
- **API Documentation**: Interactive Swagger/OpenAPI documentation
- **Docker Support**: Multi-stage Docker builds and container orchestration

## Quick Start

### Prerequisites
- Node.js 18+
- PostgreSQL 15+
- Redis 7+ (optional, for caching)
- Docker & Docker Compose (for containerized deployment)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd nestjs-monorepo

# Install dependencies
npm install

# Copy environment configuration
cp apps/auth-service/.env.example apps/auth-service/.env.development

# Set up database
npm run migration:run

# Start development server
nx serve auth-service
```

### Environment Configuration

Configure the following environment variables in your `.env` file:

```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=auth_user
DB_PASSWORD=your_password
DB_NAME=auth_service

# JWT Secrets (generate secure secrets)
JWT_SECRET=your-jwt-secret
JWT_REFRESH_SECRET=your-refresh-secret

# OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
APPLE_CLIENT_ID=your-apple-client-id
APPLE_TEAM_ID=your-apple-team-id
APPLE_KEY_ID=your-apple-key-id
APPLE_PRIVATE_KEY="your-apple-private-key"
```

### Docker Development

```bash
# Start development environment with Docker
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose -f docker-compose.dev.yml logs -f

# Stop services
docker-compose -f docker-compose.dev.yml down
```

## Development Commands

```bash
# Auth Service commands
npm run build:auth         # Build auth service
npm run test:auth          # Run all tests
npm run test:auth:unit     # Run unit tests
npm run test:auth:e2e      # Run e2e tests
npm run lint:auth          # Run linting

# Database commands
npm run migration:generate # Generate migration
npm run migration:run      # Run migrations
npm run migration:revert   # Revert migration
```

## API Documentation

Once the service is running, access the interactive API documentation:

- **Development**: http://localhost:3000/api/docs
- **Swagger UI**: Complete API documentation with authentication support
- **Health Checks**: http://localhost:3000/health

### Main Endpoints

#### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - User logout

#### Social Authentication
- `GET /api/auth/google` - Google OAuth initiation
- `GET /api/auth/google/callback` - Google OAuth callback
- `GET /api/auth/apple` - Apple Sign In initiation
- `POST /api/auth/apple/callback` - Apple Sign In callback

#### Profile Management
- `GET /api/profile` - Get user profile
- `PUT /api/profile` - Update user profile
- `GET /api/profile/sessions` - Get active sessions

#### Health & Monitoring
- `GET /health` - Application health status
- `GET /health/live` - Liveness probe
- `GET /health/ready` - Readiness probe
- `GET /health/metrics` - Application metrics

## Testing

The project includes comprehensive testing with 900+ test cases:

```bash
# Run all tests
npm run test:auth

# Run specific test types
npm run test:auth:unit        # Unit tests
npm run test:auth:integration # Integration tests
npm run test:auth:e2e        # End-to-end tests

# Generate coverage report
npm run test:auth:coverage

# Watch mode for development
npm run test:auth:watch
```

### Test Coverage
- **Unit Tests**: 365 tests covering domain entities and use cases
- **Integration Tests**: 200+ tests for database repositories and HTTP controllers
- **E2E Tests**: 335+ tests for complete authentication flows
- **Coverage**: 90%+ code coverage across all layers

## Deployment

### Docker Production

```bash
# Build and start production services
docker-compose up -d

# Check service health
curl http://localhost:3000/health

# Scale services
docker-compose up -d --scale auth-service=3
```

### Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Check deployment
kubectl get pods -n auth-service
kubectl get services -n auth-service

# Port forward for testing
kubectl port-forward service/auth-service 3000:80 -n auth-service
```

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed deployment instructions.

## Architecture

### Clean Architecture Layers

```
apps/auth-service/src/
├── domain/                 # Business logic and entities
│   ├── entities/          # Domain entities (User, Token, AuthSession)
│   ├── use-cases/         # Business use cases
│   ├── ports/             # Repository and service interfaces
│   └── models/            # Request/response models
├── infrastructure/        # External concerns
│   ├── controllers/       # HTTP controllers
│   ├── repositories/      # Database implementations
│   ├── services/          # External service implementations
│   ├── guards/            # Authentication guards
│   └── strategies/        # Passport strategies
├── modules/               # NestJS modules
└── config/                # Configuration management
```

## Security

### Authentication Methods
- **Local Authentication**: Email/password with bcrypt hashing
- **Google OAuth 2.0**: OpenID Connect integration
- **Apple Sign In**: JWT token verification with Apple's public keys
- **mTLS**: Client certificate authentication for services

### Security Features
- **Rate Limiting**: 100 req/min global, 10 req/min for auth endpoints
- **Input Validation**: XSS, SQL injection, and command injection protection
- **CORS**: Configurable cross-origin resource sharing
- **Security Headers**: CSP, HSTS, X-Frame-Options, and more
- **Audit Logging**: Comprehensive security event logging

### Token Security
- **JWT Access Tokens**: 15-minute expiration
- **Refresh Tokens**: 7-day expiration with rotation
- **Token Revocation**: Immediate token invalidation on logout
- **Session Management**: Device and location tracking

## Monitoring

### Health Checks
- **Database**: Connection and query performance
- **External Services**: OAuth provider availability
- **System Resources**: Memory, CPU, and disk usage
- **Application**: Response times and error rates

### Metrics
- **Authentication Events**: Registration, login, logout, failures
- **OAuth Events**: Provider-specific success/failure rates
- **Security Events**: Rate limit violations, suspicious activity
- **Performance**: Response times, database query performance

### Alerting
- **Security Alerts**: Multiple auth failures, rate limit violations
- **Performance Alerts**: High response times, slow database queries
- **Availability Alerts**: Service downtime, external service failures
- **Capacity Alerts**: High memory usage, connection pool exhaustion

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make your changes and add tests
4. Run tests: `npm run test:auth`
5. Run linting: `npm run lint:auth`
6. Commit your changes: `git commit -am 'Add new feature'`
7. Push to the branch: `git push origin feature/new-feature`
8. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [API Documentation](http://localhost:3000/api/docs)
- **Health Status**: [Health Endpoint](http://localhost:3000/health)
- **Metrics**: [Application Metrics](http://localhost:3000/health/metrics)
- **Issues**: GitHub Issues for bug reports and feature requests
