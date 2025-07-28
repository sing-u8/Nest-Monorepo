# Implementation Plan

- [x] 1. Set up Nx monorepo structure and core project configuration ✅ **COMPLETED**
  - [x] Create Nx workspace with NestJS preset ✅
  - [x] Generate auth-service application and required libraries (auth/domain, auth/infrastructure, auth/shared) ✅
  - [x] Configure TypeScript paths and library dependencies ✅
  - [x] Set up basic project structure following clean architecture layers ✅
  - _Requirements: 8.1, 8.2_
  
  **📁 Created Structure:**
  ```
  apps/
  ├── auth-service/                    # Main NestJS application (Composition Root)
  │   ├── src/
  │   │   ├── main.ts                 # Application bootstrap
  │   │   ├── app.module.ts           # DI container setup
  │   │   └── config/                 # Configuration management
  │   └── project.json                # Nx project configuration

  libs/
  ├── auth/
  │   ├── domain/                     # Entities + Use Cases (Core Business Logic)
  │   │   ├── src/
  │   │   │   ├── entities/           # Business entities
  │   │   │   ├── use-cases/          # Application business rules
  │   │   │   └── ports/              # Interface definitions
  │   │   └── project.json
  │   │
  │   ├── infrastructure/             # Interface Adapters + Frameworks & Drivers
  │   │   ├── src/
  │   │   │   ├── controllers/        # HTTP controllers
  │   │   │   ├── repositories/       # Data access implementations
  │   │   │   ├── guards/             # Authentication guards
  │   │   │   ├── strategies/         # Passport strategies
  │   │   │   ├── database/           # TypeORM entities & migrations
  │   │   │   └── external/           # External service clients
  │   │   └── project.json
  │   │
  │   └── shared/                     # Shared DTOs, types, utilities
  │       ├── src/
  │       │   ├── dtos/
  │       │   ├── types/
  │       │   └── utils/
  │       └── project.json
  ```
  
  **🔗 TypeScript Path Aliases:**
  - `@auth/domain` → `libs/auth/domain/src/index.ts`
  - `@auth/infrastructure` → `libs/auth/infrastructure/src/index.ts`
  - `@auth/shared` → `libs/auth/shared/src/index.ts`
  
  **📦 Dependency Configuration:**
  - auth-service depends on: infrastructure, domain, shared
  - infrastructure depends on: domain
  - domain: no external dependencies (pure business logic)
  - shared: common types and DTOs
  
  **🏷️ Project Tags:**
  - auth-service: `["scope:auth", "type:app"]`
  - domain: `["scope:auth", "type:domain"]`
  - infrastructure: `["scope:auth", "type:infrastructure"]`
  - shared: `["scope:auth", "type:shared"]`

- [x] 2. Implement core domain entities with business rules ✅ **COMPLETED**
  - [x] 2.1 Create User entity with validation and business methods ✅
    - [x] Implement User class with email, password, name, profile picture properties ✅
    - [x] Add business methods: validatePassword, updatePassword, updateProfile, activate/deactivate ✅
    - [x] Write unit tests for User entity business rules ✅
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_
  
  - [x] 2.2 Create Token entity with expiration and validation logic ✅
    - [x] Implement Token class with type, value, expiration, and revocation logic ✅
    - [x] Add methods: isExpired, revoke, isValid ✅
    - [x] Write unit tests for Token entity business rules ✅
    - _Requirements: 2.4, 2.5, 6.1, 6.3_
  
  - [x] 2.3 Create AuthSession entity for session management ✅
    - [x] Implement AuthSession class with session token and client info ✅
    - [x] Add session validation and expiration methods ✅
    - [x] Write unit tests for AuthSession entity ✅
    - _Requirements: 6.4, 6.5_
  
  **🎯 Created Entities:**
  
  1. **User Entity** (`libs/auth/domain/src/entities/user.entity.ts`)
     - Email validation with regex pattern
     - Password strength validation (min 8 chars, uppercase, lowercase, numbers, special chars)
     - Account status management (active, inactive, suspended, deleted)
     - Support for multiple auth providers (local, Google, Apple, mTLS)
     - Profile update functionality
     - Factory methods for creation and social login
  
  2. **Token Entity** (`libs/auth/domain/src/entities/token.entity.ts`)
     - Token types: access, refresh, reset_password, email_verification
     - Expiration management with time calculations
     - Revocation functionality
     - Token validity checking (not expired + not revoked)
     - Factory methods for different token types
     - Safe serialization methods
  
  3. **AuthSession Entity** (`libs/auth/domain/src/entities/auth-session.entity.ts`)
     - Session tracking with client information
     - Activity tracking and idle detection
     - Session extension (sliding sessions)
     - Device and IP-based validation
     - Status management (active, inactive, expired, idle)
  
  **🧪 Test Coverage:**
  - Comprehensive unit tests for all entities
  - Edge case coverage (expired tokens, invalid passwords, etc.)
  - Mock timers for time-based testing
  - 100% business logic coverage

- [x] 3. Define use case interfaces and ports ✅ **COMPLETED**
  - [x] 3.1 Create repository port interfaces ✅
    - [x] Define UserRepository interface with CRUD operations ✅
    - [x] Define TokenRepository interface with token management operations ✅
    - [x] Define AuthSessionRepository interface with session operations ✅
    - _Requirements: 8.3, 8.4_
  
  - [x] 3.2 Create external service port interfaces ✅
    - [x] Define GoogleOAuthService interface for Google authentication ✅
    - [x] Define AppleOAuthService interface for Apple authentication ✅
    - [x] Define PasswordHashingService interface for password operations ✅
    - [x] Define TokenService interface for JWT operations ✅
    - _Requirements: 4.1, 4.2, 5.1, 5.2, 7.1_
  
  - [x] 3.3 Define use case input/output models ✅
    - [x] Create request/response DTOs for all authentication use cases ✅
    - [x] Define output port interfaces for presenters ✅
    - [x] Implement proper validation for input models ✅
    - _Requirements: 8.4, 8.5_
  
  **🎯 Created Interfaces and Ports:**
  
  1. **Repository Ports** (`libs/auth/domain/src/ports/repositories/`)
     - UserRepository: CRUD operations with find by email/provider support
     - TokenRepository: Token storage with expiration cleanup and batch operations
     - AuthSessionRepository: Session management with activity tracking
  
  2. **Service Ports** (`libs/auth/domain/src/ports/services/`)
     - PasswordHashingService: Secure password hashing with configurable algorithms
     - TokenService: JWT token generation, validation, and management
     - GoogleOAuthService: Complete Google OAuth 2.0 flow implementation
     - AppleOAuthService: Apple Sign In with identity token validation
  
  3. **DTOs** (`libs/auth/shared/src/dtos/`)
     - Comprehensive auth.dto.ts: Registration, login, social auth, token refresh, logout
     - Complete user.dto.ts: Profile management, sessions, account operations
  
  4. **Presenter Ports** (`libs/auth/domain/src/ports/presenters/`)
     - AuthPresenter: Authentication flow presentations with error handling
     - ProfilePresenter: User profile operations with comprehensive error scenarios
  
  **🔗 Key Features:**
  - Dependency inversion principle adherence
  - Comprehensive error handling scenarios
  - Support for all authentication flows (local, Google, Apple, mTLS)
  - Session management with device tracking
  - Profile picture upload with validation
  - Rate limiting and security error presentations

- [x] 4. Implement core use cases with business logic ✅ **IN PROGRESS**
  - [x] 4.1 Implement RegisterUserUseCase ✅ **COMPLETED**
    - [x] Create RegisterUserUseCase with email validation and duplicate checking ✅
    - [x] Implement password hashing and user creation logic ✅
    - [x] Write unit tests with mocked dependencies ✅
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 7.1_
  
  - [x] 4.2 Implement LoginUserUseCase for JWT authentication ✅ **COMPLETED**
    - [x] Create LoginUserUseCase with credential validation ✅
    - [x] Implement token generation and session creation ✅
    - [x] Add account status checking and security measures ✅
    - [x] Implement comprehensive error handling ✅
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_
  
  **🎯 Completed Use Cases:**
  
  1. **RegisterUserUseCase** (`libs/auth/domain/src/use-cases/register-user.use-case.ts`)
     - Comprehensive input validation (email format, password strength, name requirements)
     - Duplicate email checking with proper error presentation
     - Secure password hashing using PasswordHashingService port
     - User entity creation with proper ID generation
     - JWT token generation (access + refresh tokens with proper expiration)
     - Initial session creation with client information tracking
     - Comprehensive error handling with user-friendly error presentation
     - Follows clean architecture with dependency inversion principle
  
  2. **LoginUserUseCase** (`libs/auth/domain/src/use-cases/login-user.use-case.ts`)
     - Input validation for email and password
     - User lookup by email with proper error handling
     - Account status validation (active, inactive, suspended, deleted)
     - Secure password verification using PasswordHashingService
     - JWT token generation with configurable expiration
     - Session management with "remember me" functionality
     - Last login timestamp tracking
     - Comprehensive error handling with security-focused error messages

  **🔗 Key Features Implemented:**
  - Proper dependency inversion through port interfaces
  - Comprehensive input validation with detailed error messages
  - Secure password handling (hashing and verification)
  - JWT token lifecycle management (generation, expiration)
  - Session management with client information tracking
  - Account status and security validations
  - User-friendly error presentation through presenter pattern
  - ID generation utilities for entities
  
  - [ ] 4.3 Implement RefreshTokenUseCase
    - Create RefreshTokenUseCase with token validation and rotation
    - Implement secure token refresh logic
    - Write unit tests for token refresh scenarios
    - _Requirements: 2.4, 2.6, 6.6_
  
  - [ ] 4.4 Implement SocialLoginUseCase for OAuth flows
    - Create SocialLoginUseCase supporting Google and Apple OAuth
    - Implement user creation/lookup for social users
    - Add proper error handling for OAuth failures
    - Write unit tests with mocked OAuth services
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_
  
  - [ ] 4.5 Implement UpdateProfileUseCase
    - Create UpdateProfileUseCase with profile validation
    - Implement profile picture upload handling
    - Write unit tests for profile update scenarios
    - _Requirements: 1.5, 1.6_

- [ ] 5. Implement infrastructure layer adapters
  - [ ] 5.1 Create database repository implementations
    - Implement UserRepository using TypeORM
    - Implement TokenRepository with proper indexing
    - Implement AuthSessionRepository with cleanup logic
    - Write integration tests with test database
    - _Requirements: 8.3, 8.4_
  
  - [ ] 5.2 Create password hashing service implementation
    - Implement PasswordHashingService using bcrypt
    - Configure proper salt rounds and security settings
    - Write unit tests for password hashing operations
    - _Requirements: 7.1_
  
  - [ ] 5.3 Create JWT token service implementation
    - Implement TokenService with RS256 signing
    - Configure access and refresh token generation
    - Add token validation and blacklisting support
    - Write unit tests for token operations
    - _Requirements: 6.1, 6.2, 6.3, 6.5_

- [ ] 6. Implement OAuth service adapters
  - [ ] 6.1 Create Google OAuth service implementation
    - Implement GoogleOAuthService using Google OAuth2 client
    - Handle authorization code exchange and user info retrieval
    - Add proper error handling for OAuth failures
    - Write integration tests with mocked Google API
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_
  
  - [ ] 6.2 Create Apple OAuth service implementation
    - Implement AppleOAuthService using Apple Sign In
    - Handle identity token validation and user info extraction
    - Implement privacy-focused user data handling
    - Write integration tests with mocked Apple API
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

- [ ] 7. Create HTTP controllers and presenters
  - [ ] 7.1 Implement AuthController with REST endpoints
    - Create POST /auth/register endpoint
    - Create POST /auth/login endpoint
    - Create POST /auth/refresh endpoint
    - Create POST /auth/logout endpoint
    - Add proper request validation and error handling
    - _Requirements: 1.1, 2.1, 2.4, 2.5_
  
  - [ ] 7.2 Implement SocialAuthController
    - Create GET /auth/google endpoint for OAuth initiation
    - Create GET /auth/google/callback endpoint
    - Create GET /auth/apple endpoint for Apple Sign In
    - Create GET /auth/apple/callback endpoint
    - _Requirements: 4.1, 4.2, 5.1, 5.2_
  
  - [ ] 7.3 Implement ProfileController
    - Create GET /profile endpoint for user profile
    - Create PUT /profile endpoint for profile updates
    - Create POST /profile/picture endpoint for profile picture upload
    - _Requirements: 1.5, 1.6_
  
  - [ ] 7.4 Create response presenters
    - Implement AuthPresenter for authentication responses
    - Implement ProfilePresenter for profile data formatting
    - Implement ErrorPresenter for consistent error responses
    - Write unit tests for presenter logic
    - _Requirements: 8.4, 8.5_

- [ ] 8. Implement authentication guards and strategies
  - [ ] 8.1 Create JWT authentication guard
    - Implement JwtAuthGuard using Passport JWT strategy
    - Add token validation and user context injection
    - Write unit tests for guard behavior
    - _Requirements: 2.4, 6.5_
  
  - [ ] 8.2 Create mTLS authentication guard
    - Implement MTLSAuthGuard for certificate validation
    - Add client certificate verification logic
    - Configure CA certificate chain validation
    - Write integration tests with test certificates
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  
  - [ ] 8.3 Create Passport strategies
    - Implement GoogleStrategy for Google OAuth
    - Implement AppleStrategy for Apple Sign In
    - Configure strategy options and validation
    - Write unit tests for strategy implementations
    - _Requirements: 4.1, 4.2, 5.1, 5.2_

- [ ] 9. Set up database schema and migrations
  - [ ] 9.1 Create TypeORM entities and migrations
    - Create database entities for User, Token, AuthSession
    - Generate and configure database migrations
    - Set up proper indexes and constraints
    - Write database integration tests
    - _Requirements: 8.1, 8.2_
  
  - [ ] 9.2 Configure database connection and pooling
    - Set up TypeORM configuration with connection pooling
    - Configure database connection for different environments
    - Add database health check endpoint
    - _Requirements: 8.1_

- [ ] 10. Implement security features
  - [ ] 10.1 Add rate limiting middleware
    - Implement rate limiting for authentication endpoints
    - Configure progressive delays for failed attempts
    - Add IP-based and user-based rate limiting
    - Write tests for rate limiting behavior
    - _Requirements: 7.4_
  
  - [ ] 10.2 Implement audit logging
    - Create audit logging for authentication events
    - Log security events and failed attempts
    - Configure structured logging with proper levels
    - Write tests for logging functionality
    - _Requirements: 7.5_
  
  - [ ] 10.3 Add input validation and sanitization
    - Implement comprehensive input validation using class-validator
    - Add request sanitization middleware
    - Configure CORS and security headers
    - Write tests for validation and security measures
    - _Requirements: 7.3_

- [ ] 11. Configure application composition and dependency injection
  - [ ] 11.1 Set up NestJS modules and dependency injection
    - Create AuthModule with proper provider configuration
    - Configure dependency injection for all use cases and services
    - Set up module imports and exports
    - _Requirements: 8.3, 8.4_
  
  - [ ] 11.2 Configure application settings and environment variables
    - Set up configuration management with validation
    - Configure JWT secrets, OAuth credentials, and database settings
    - Add environment-specific configuration files
    - Write configuration validation tests
    - _Requirements: 8.1_
  
  - [ ] 11.3 Create application bootstrap and main entry point
    - Configure main.ts with proper application setup
    - Add global middleware, filters, and pipes
    - Configure Swagger documentation
    - Set up application shutdown hooks
    - _Requirements: 8.1, 8.2_

- [ ] 12. Write comprehensive tests
  - [ ] 12.1 Complete unit test coverage
    - Ensure all entities have comprehensive unit tests
    - Test all use cases with mocked dependencies
    - Test all adapters and services in isolation
    - Achieve minimum 90% code coverage
    - _Requirements: 8.5_
  
  - [ ] 12.2 Write integration tests
    - Test database repositories with test database
    - Test HTTP controllers with test server
    - Test OAuth flows with mocked external services
    - Test authentication guards and middleware
    - _Requirements: 8.5_
  
  - [ ] 12.3 Create end-to-end tests
    - Test complete authentication flows
    - Test social login integration
    - Test mTLS authentication flow
    - Test error scenarios and edge cases
    - _Requirements: 8.5_

- [ ] 13. Add monitoring and health checks
  - [ ] 13.1 Implement health check endpoints
    - Create /health endpoint for application status
    - Add database connectivity checks
    - Add external service dependency checks
    - Configure health check monitoring
    - _Requirements: 8.1_
  
  - [ ] 13.2 Add application metrics and monitoring
    - Implement metrics collection for authentication events
    - Add performance monitoring for critical paths
    - Configure logging aggregation and monitoring
    - Set up alerting for security events
    - _Requirements: 7.5_

- [ ] 14. Create documentation and deployment configuration
  - [ ] 14.1 Generate API documentation
    - Configure Swagger/OpenAPI documentation
    - Document all authentication endpoints
    - Add example requests and responses
    - Create authentication flow diagrams
    - _Requirements: 8.1_
  
  - [ ] 14.2 Create deployment configuration
    - Create Docker configuration for containerization
    - Set up environment-specific deployment configs
    - Configure CI/CD pipeline integration
    - Create deployment documentation
    - _Requirements: 8.1_