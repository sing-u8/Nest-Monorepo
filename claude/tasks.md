# Implementation Plan

- [x] 1. Set up Nx + NestJS application with clean architecture structure ✅ **COMPLETED**
  - ✅ Create Nx workspace and generate NestJS application using Nx CLI
  - ✅ Install core NestJS packages (@nestjs/core, @nestjs/common, @nestjs/platform-express)
  - ✅ Install additional required packages (@nestjs/passport, @nestjs/jwt, @nestjs/typeorm, @nestjs/config, @nestjs/throttler, @nestjs/swagger, bcrypt, class-validator, class-transformer, typeorm, pg, joi)
  - ✅ Set up clean architecture folder structure within auth-service app (domain/, infrastructure/, shared/, modules/)
  - ✅ Configure TypeScript paths and Nx project configuration for clean imports
  - ✅ Create basic NestJS modules structure following clean architecture principles (AuthModule, DatabaseModule, UserModule)
  - ✅ Configure main.ts with Swagger, ValidationPipe, CORS settings
  - ✅ Set up environment configuration files and validation
  - _Requirements: 8.1, 8.2, 9.1_

- [x] 2. Implement core domain entities with business rules ✅ **COMPLETED**
  - [x] 2.1 Create User entity with validation and business methods (Pure TypeScript) ✅ **COMPLETED**
    - ✅ Implement User class in src/domain/entities/ with email, password, name, profile picture properties
    - ✅ Add business methods: validatePassword, updatePassword, updateProfile, activate/deactivate
    - ✅ Ensure no NestJS dependencies in domain entities (pure TypeScript classes)
    - ✅ Support multiple AuthProvider types (LOCAL, GOOGLE, APPLE)
    - ✅ Implement comprehensive input validation (email format, name length, password requirements)
    - ✅ Write unit tests for User entity business rules using Jest (20+ test cases)
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 8.4_
  
  - [x] 2.2 Create Token entity with expiration and validation logic ✅ **COMPLETED**
    - ✅ Implement Token class with type (ACCESS/REFRESH), value, expiration, and revocation logic
    - ✅ Add methods: isExpired, revoke, isValid, getRemainingTime
    - ✅ Implement comprehensive token validation and state management
    - ✅ Write unit tests for Token entity business rules (20+ test cases)
    - _Requirements: 2.4, 2.5, 6.1, 6.3_
  
  - [x] 2.3 Create AuthSession entity for session management ✅ **COMPLETED**
    - ✅ Implement AuthSession class with session token and client info (UserAgent, IP, Device ID)
    - ✅ Add session validation, expiration, and activity tracking methods
    - ✅ Implement idle time calculation and inactivity-based expiration
    - ✅ Add methods: updateActivity, getIdleTime, shouldExpireForInactivity
    - ✅ Write unit tests for AuthSession entity (17+ test cases)
    - _Requirements: 6.4, 6.5_
  
  **📊 Test Results:** 57 test cases passed, complete test coverage for all domain entities

- [x] 3. Define use case interfaces and ports ✅ **COMPLETED**
  - [x] 3.1 Create repository port interfaces in domain layer ✅ **COMPLETED**
    - ✅ Define UserRepository interface in src/domain/ports/ with CRUD operations (save, findById, findByEmail, existsByEmail, update, delete, activate/deactivate, findByProvider)
    - ✅ Define TokenRepository interface in src/domain/ports/ with token management operations (save, findByValue, findByUserId, revoke, delete expired, count active)
    - ✅ Define AuthSessionRepository interface in src/domain/ports/ with session operations (save, findById, findBySessionToken, revoke, update activity, cleanup)
    - _Requirements: 8.3, 8.4_
  
  - [x] 3.2 Create external service port interfaces in domain layer ✅ **COMPLETED**
    - ✅ Define GoogleOAuthService interface in src/domain/ports/ for Google authentication (exchange code, get user info, verify ID token, refresh tokens)
    - ✅ Define AppleOAuthService interface in src/domain/ports/ for Apple authentication (verify ID token, extract user info, validate nonce)
    - ✅ Define PasswordHashingService interface in src/domain/ports/ for password operations (hash, compare, validate format, generate salt)
    - ✅ Define TokenService interface in src/domain/ports/ for JWT operations (generate, verify, decode, revoke, token pairs)
    - _Requirements: 4.1, 4.2, 5.1, 5.2, 7.1_
  
  - [x] 3.3 Define use case input/output models in domain layer ✅ **COMPLETED**
    - ✅ Create request/response DTOs in src/domain/models/ for all authentication use cases (Register, Login, SocialLogin, RefreshToken, UpdateProfile, Logout)
    - ✅ Define output port interfaces for presenters in src/domain/ports/ (AuthPresenter, ProfilePresenter with success/error presentation methods)
    - ✅ Implement comprehensive input/output model types with proper TypeScript typing
    - ✅ Create index files for clean exports and organized imports
    - _Requirements: 8.4, 8.5_

- [x] 4. Implement core use cases with business logic ✅ **COMPLETED (Steps 4.1-4.2)**
  - [x] 4.1 Implement RegisterUserUseCase as NestJS Injectable Service ✅ **COMPLETED**
    - ✅ Create RegisterUserUseCase in src/domain/use-cases/ with @Injectable decorator and @Inject tokens
    - ✅ Implement email validation, duplicate checking, and user creation logic (UserAlreadyExistsError, InvalidPasswordError)
    - ✅ Use NestJS dependency injection to inject repository and service dependencies with proper token-based injection
    - ✅ Write comprehensive unit tests using @nestjs/testing for DI container testing (12+ test cases)
    - ✅ Add input validation for email format, name length, and password requirements
    - ✅ Generate unique user IDs and handle profile picture optional parameter
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 7.1, 8.3, 8.4_
  
  - [x] 4.2 Implement LoginUserUseCase as NestJS Injectable Service ✅ **COMPLETED**
    - ✅ Create LoginUserUseCase in src/domain/use-cases/ with @Injectable decorator and @Inject tokens for all dependencies
    - ✅ Implement credential validation, token generation, and session creation (InvalidCredentialsError, UserNotActiveError)
    - ✅ Use NestJS DI to inject UserRepository, TokenRepository, AuthSessionRepository, PasswordService, and TokenService
    - ✅ Add account status checking and password validation with bcrypt comparison
    - ✅ Generate JWT token pairs (access/refresh) and create AuthSession with client info tracking
    - ✅ Implement token expiration logic (15min access, 7day refresh) and existing token revocation
    - ✅ Write comprehensive unit tests using @nestjs/testing with mocked dependencies (11+ test cases)
    - ✅ Handle edge cases: user not found, inactive users, invalid credentials, service failures
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 8.3, 8.4_
  
  **📊 Test Results:** 365 test cases passed (57 entity tests + 93 use case tests + 55 infrastructure service tests + 160 OAuth service tests), comprehensive coverage for domain, infrastructure, and external service layers
  
  - [x] 4.3 Implement RefreshTokenUseCase ✅ **COMPLETED**
    - ✅ Create RefreshTokenUseCase in src/domain/use-cases/ with @Injectable decorator and @Inject tokens
    - ✅ Implement secure token validation, rotation, and user verification (InvalidRefreshTokenError, TokenExpiredError, UserNotActiveError)
    - ✅ Add token signature verification and payload validation with TokenService integration
    - ✅ Implement token rotation security: revoke old refresh token and generate new token pair
    - ✅ Add session validation and activity updates with client info tracking
    - ✅ Write comprehensive unit tests using @nestjs/testing with mocked dependencies (15+ test cases)
    - ✅ Handle edge cases: expired tokens, invalid tokens, inactive users, invalid sessions
    - _Requirements: 2.4, 2.6, 6.6_
  
  - [x] 4.4 Implement SocialLoginUseCase for OAuth flows ✅ **COMPLETED**
    - ✅ Create SocialLoginUseCase in src/domain/use-cases/ supporting Google and Apple OAuth with @Injectable decorator
    - ✅ Implement Google OAuth flow: authorization code exchange, user info retrieval, token validation
    - ✅ Implement Apple OAuth flow: ID token verification, user info extraction with privacy handling
    - ✅ Add user account linking: create new users or link to existing accounts by email
    - ✅ Implement comprehensive error handling: UnsupportedProviderError, OAuthAuthorizationError, OAuthUserInfoError
    - ✅ Add provider-specific validation and user creation from social profile data
    - ✅ Write comprehensive unit tests using @nestjs/testing with mocked OAuth services (25+ test cases)
    - ✅ Handle edge cases: invalid providers, failed OAuth flows, deactivated users, invalid tokens
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_
  
  - [x] 4.5 Implement UpdateProfileUseCase ✅ **COMPLETED**
    - ✅ Create UpdateProfileUseCase in src/domain/use-cases/ with @Injectable decorator and comprehensive validation
    - ✅ Implement profile validation: name format, profile picture URL validation with HTTPS requirement
    - ✅ Add comprehensive input validation: user ID format, name length/characters, image file extensions
    - ✅ Implement change detection and NoChangesError for identical values
    - ✅ Add user account status validation and UserNotActiveError for inactive users
    - ✅ Handle profile picture updates with URL validation and security checks (HTTPS, valid extensions, length limits)
    - ✅ Write comprehensive unit tests using @nestjs/testing with validation scenarios (30+ test cases)
    - ✅ Handle edge cases: user not found, invalid data, no changes, validation failures
    - _Requirements: 1.5, 1.6_

- [x] 5. Implement infrastructure layer adapters ✅ **COMPLETED**
  - [x] 5.1 Create database repository implementations in infrastructure layer ✅ **COMPLETED**
    - ✅ Implement UserRepositoryImpl in src/infrastructure/repositories/ using TypeORM with @Injectable decorator
    - ✅ Create UserOrmEntity with proper indexes (email unique, provider+providerId unique) and column mappings
    - ✅ Implement TokenRepositoryImpl in src/infrastructure/repositories/ with comprehensive token management
    - ✅ Create TokenOrmEntity with proper indexes (userId, type, value unique, expiresAt, isRevoked) and foreign key relations
    - ✅ Implement AuthSessionRepositoryImpl in src/infrastructure/repositories/ with session lifecycle management
    - ✅ Create AuthSessionOrmEntity with JSONB client_info storage and proper indexing
    - ✅ Add comprehensive repository methods: CRUD operations, cleanup logic, active session management
    - ✅ Implement domain-to-ORM and ORM-to-domain entity mapping with proper type conversions
    - _Requirements: 8.3, 8.4_
  
  - [x] 5.2 Create password hashing service as NestJS Injectable ✅ **COMPLETED**
    - ✅ Implement PasswordHashingServiceImpl in src/infrastructure/services/ with @Injectable decorator and ConfigService integration
    - ✅ Use bcrypt library with configurable salt rounds (default 12) and comprehensive security validation
    - ✅ Add password format validation: 8+ chars, uppercase, lowercase, number, special character requirements
    - ✅ Implement advanced features: rehashIfNeeded, password strength scoring, compromised password detection
    - ✅ Add salt generation, hash validation, and password requirements documentation methods
    - ✅ Write comprehensive unit tests using @nestjs/testing with 25+ test cases covering all scenarios
    - ✅ Handle bcrypt errors gracefully with proper error messages and security considerations
    - _Requirements: 7.1, 8.3, 8.4_
  
  - [x] 5.3 Create JWT token service using @nestjs/jwt ✅ **COMPLETED**
    - ✅ Implement JwtTokenServiceImpl in src/infrastructure/services/ using JwtService from @nestjs/jwt
    - ✅ Configure separate secrets for access and refresh tokens with ConfigService integration
    - ✅ Add token pair generation: access tokens (15m), refresh tokens (7d) with proper expiration handling
    - ✅ Implement comprehensive token validation: signature verification, type validation, expiration checks
    - ✅ Add token utility methods: decode, format validation, expiration checking, payload extraction
    - ✅ Implement token refresh flow with security rotation and validation
    - ✅ Write comprehensive unit tests using @nestjs/testing with 30+ test cases and JwtService mocking
    - ✅ Handle JWT errors gracefully with proper null returns for invalid tokens
    - _Requirements: 6.1, 6.2, 6.3, 6.5, 9.2_

- [x] 6. Implement OAuth service adapters ✅ **COMPLETED**
  - [x] 6.1 Create Google OAuth service implementation in infrastructure layer ✅ **COMPLETED**
    - ✅ Implement GoogleOAuthServiceImpl in src/infrastructure/external/ using HttpService with @nestjs/axios
    - ✅ Handle authorization code exchange with proper request body formatting and timeout handling
    - ✅ Implement user info retrieval with Bearer token authentication and comprehensive error handling
    - ✅ Add token refresh functionality with refresh token validation and new token generation
    - ✅ Implement ID token verification using Google's tokeninfo endpoint with audience and issuer validation
    - ✅ Add token revocation functionality with graceful error handling (non-critical failures)
    - ✅ Create authorization URL generation with configurable scopes, state, and OAuth parameters
    - ✅ Add configuration validation and client ID access methods
    - ✅ Implement comprehensive error handling: GoogleOAuthError, GoogleTokenExchangeError, GoogleUserInfoError
    - ✅ Write comprehensive integration tests with mocked HttpService (85+ test cases covering all scenarios)
    - ✅ Handle edge cases: network timeouts, invalid tokens, API errors, malformed responses
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_
  
  - [x] 6.2 Create Apple OAuth service implementation in infrastructure layer ✅ **COMPLETED**
    - ✅ Implement AppleOAuthServiceImpl in src/infrastructure/external/ using Apple Sign In with JWT verification
    - ✅ Handle ID token verification with Apple's public keys from auth/keys endpoint
    - ✅ Implement public key caching mechanism with 1-hour expiration for performance optimization
    - ✅ Add user info extraction from ID token payload with privacy-focused data handling
    - ✅ Support additional user data from Sign In with Apple form (name objects, optional fields)
    - ✅ Implement nonce validation for security enhancement and CSRF protection
    - ✅ Add client secret generation using ES256 JWT signing with Apple's private key
    - ✅ Create authorization URL generation with Apple-specific parameters (response_mode=form_post)
    - ✅ Implement token revocation with client secret authentication (non-critical failures)
    - ✅ Add JWK to PEM conversion functionality for public key verification (simplified implementation)
    - ✅ Implement comprehensive error handling: AppleOAuthError, AppleTokenVerificationError, AppleUserInfoExtractionError
    - ✅ Write comprehensive integration tests with mocked HttpService (75+ test cases covering all scenarios)
    - ✅ Handle edge cases: invalid tokens, missing configuration, key fetch failures, payload decoding errors
    - ✅ Add utility methods: token expiration checking, user ID extraction, configuration validation
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_
  
  **📊 Test Results:** 160+ test cases passed for OAuth services (85 Google + 75 Apple), comprehensive coverage for all OAuth flows and error scenarios

- [ ] 7. Create HTTP controllers and presenters
  - [ ] 7.1 Implement AuthController using NestJS decorators
    - Create AuthController in src/infrastructure/controllers/ with @Controller decorator
    - Implement POST /auth/register, /auth/login, /auth/refresh, /auth/logout endpoints
    - Use @Post, @Body, @UsePipes decorators for endpoint definition
    - Add class-validator DTOs for request validation
    - Use NestJS ValidationPipe for automatic validation
    - Inject use case services through constructor dependency injection
    - _Requirements: 1.1, 2.1, 2.4, 2.5, 8.3, 8.4_
  
  - [ ] 7.2 Implement SocialAuthController in infrastructure layer
    - Create SocialAuthController in src/infrastructure/controllers/ with GET /auth/google endpoint for OAuth initiation
    - Create GET /auth/google/callback endpoint
    - Create GET /auth/apple endpoint for Apple Sign In
    - Create GET /auth/apple/callback endpoint
    - _Requirements: 4.1, 4.2, 5.1, 5.2_
  
  - [ ] 7.3 Implement ProfileController in infrastructure layer
    - Create ProfileController in src/infrastructure/controllers/ with GET /profile endpoint for user profile
    - Create PUT /profile endpoint for profile updates
    - Create POST /profile/picture endpoint for profile picture upload
    - _Requirements: 1.5, 1.6_
  
  - [ ] 7.4 Create response presenters in infrastructure layer
    - Implement AuthPresenter in src/infrastructure/presenters/ for authentication responses
    - Implement ProfilePresenter in src/infrastructure/presenters/ for profile data formatting
    - Implement ErrorPresenter in src/infrastructure/presenters/ for consistent error responses
    - Write unit tests for presenter logic
    - _Requirements: 8.4, 8.5_

- [ ] 8. Implement authentication guards and strategies
  - [ ] 8.1 Create JWT authentication guard using @nestjs/passport
    - Install @nestjs/passport and passport-jwt packages
    - Implement JwtAuthGuard in src/infrastructure/guards/ extending AuthGuard('jwt')
    - Create JwtStrategy extending PassportStrategy for token validation
    - Add user context injection and custom validation logic
    - Register strategy in NestJS module and use @UseGuards decorator
    - Write unit tests using @nestjs/testing for guard and strategy testing
    - _Requirements: 2.4, 6.5, 9.1_
  
  - [ ] 8.2 Create mTLS authentication guard in infrastructure layer
    - Implement MTLSAuthGuard in src/infrastructure/guards/ for certificate validation
    - Add client certificate verification logic
    - Configure CA certificate chain validation
    - Write integration tests with test certificates
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  
  - [ ] 8.3 Create OAuth strategies using @nestjs/passport
    - Implement GoogleStrategy in src/infrastructure/strategies/ extending PassportStrategy
    - Implement AppleStrategy in src/infrastructure/strategies/ extending PassportStrategy
    - Use @Injectable decorator and configure strategy options through NestJS config
    - Register strategies in NestJS module providers
    - Write unit tests using @nestjs/testing for strategy validation
    - _Requirements: 4.1, 4.2, 5.1, 5.2, 9.1_

- [ ] 9. Set up database schema and migrations
  - [ ] 9.1 Create TypeORM entities using @nestjs/typeorm
    - Install @nestjs/typeorm and configure TypeOrmModule in app module
    - Create database entities in src/infrastructure/database/entities/ using TypeORM decorators
    - Generate and configure database migrations using TypeORM CLI
    - Set up proper indexes, constraints, and relationships
    - Use @InjectRepository decorator for repository injection in services
    - Write database integration tests using @nestjs/testing with test database
    - _Requirements: 8.1, 8.2, 9.3_
  
  - [ ] 9.2 Configure database connection and pooling
    - Set up TypeORM configuration with connection pooling
    - Configure database connection for different environments
    - Add database health check endpoint
    - _Requirements: 8.1_

- [ ] 10. Implement security features
  - [ ] 10.1 Add rate limiting using @nestjs/throttler
    - Install and configure @nestjs/throttler module
    - Set up ThrottlerModule with global and endpoint-specific rate limits
    - Use @Throttle decorator for custom rate limiting on authentication endpoints
    - Configure progressive delays for failed attempts using custom throttler guards
    - Add IP-based and user-based rate limiting strategies
    - Write tests for rate limiting behavior using @nestjs/testing
    - _Requirements: 7.4, 9.5_
  
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
  - [ ] 11.1 Set up NestJS modules with clean architecture separation
    - Create AuthModule in src/modules/ with @Module decorator
    - Configure providers array with use cases, repositories, and services
    - Set up proper imports (ConfigModule, TypeOrmModule, JwtModule, PassportModule)
    - Use custom providers with 'provide' tokens for interface-based injection
    - Create separate modules for different features (UserModule, DatabaseModule)
    - Ensure proper layer separation in module organization
    - _Requirements: 8.3, 8.4, 8.6_
  
  - [ ] 11.2 Configure application settings using @nestjs/config
    - Install and configure @nestjs/config module with global registration
    - Create configuration schemas in src/config/ with Joi validation
    - Set up environment-specific configuration files (.env, .env.development, .env.production)
    - Use ConfigService injection for accessing configuration in services
    - Configure JWT secrets, OAuth credentials, and database settings through config
    - Write configuration validation tests using @nestjs/testing
    - _Requirements: 8.1, 9.4_
  
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
  - [ ] 14.1 Generate API documentation using @nestjs/swagger
    - Install and configure @nestjs/swagger module
    - Add SwaggerModule setup in main.ts with API metadata
    - Use @ApiTags, @ApiOperation, @ApiResponse decorators on controllers
    - Document DTOs with @ApiProperty decorators for request/response schemas
    - Add authentication security schemes and @ApiBearerAuth decorators
    - Generate interactive Swagger UI for API testing and documentation
    - _Requirements: 8.1, 9.6_
  
  - [ ] 14.2 Create deployment configuration
    - Create Docker configuration for containerization
    - Set up environment-specific deployment configs
    - Configure CI/CD pipeline integration
    - Create deployment documentation
    - _Requirements: 8.1_