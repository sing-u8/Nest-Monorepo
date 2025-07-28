# Auth Service Design Document

## Overview

Auth service는 클린 아키텍처의 4계층 구조를 따라 설계되며, NestJS와 Nx 모노레포 환경에서 구현됩니다. 서비스는 의존성 역전 원칙을 통해 비즈니스 로직을 외부 기술로부터 완전히 분리하여 테스트 가능하고 유지보수가 용이한 구조를 제공합니다.

## Architecture

### Clean Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Frameworks & Drivers                     │
│  NestJS, Passport.js, JWT, TypeORM, Express, Google/Apple  │
│                         OAuth SDKs                          │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                   Interface Adapters                        │
│     Controllers, Presenters, Repositories, Guards,         │
│              Strategies, DTOs, Mappers                      │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                      Use Cases                              │
│   LoginUser, RegisterUser, RefreshToken, UpdateProfile,    │
│        ValidateToken, RevokeToken, SocialLogin             │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                       Entities                              │
│           User, Token, AuthSession, Profile                 │
└─────────────────────────────────────────────────────────────┘
```

### Nx Monorepo Structure

클린 아키텍처를 Nx 모노레포에 적용하는 방법은 여러 가지가 있습니다. 다음은 권장되는 구조입니다:

#### Option 1: Layer-based Library Separation (권장)

```
apps/
├── auth-service/                    # Main NestJS application (Composition Root)
│   ├── src/
│   │   ├── main.ts                 # Application bootstrap
│   │   ├── app.module.ts           # DI container setup
│   │   └── config/                 # Configuration management
│   └── test/e2e/                   # End-to-end tests

libs/
├── auth/
│   ├── domain/                     # Entities + Use Cases (Core Business Logic)
│   │   ├── src/
│   │   │   ├── entities/           # Business entities
│   │   │   ├── use-cases/          # Application business rules
│   │   │   └── ports/              # Interface definitions (repositories, external services)
│   │   └── test/
│   │
│   ├── infrastructure/             # Interface Adapters + Frameworks & Drivers
│   │   ├── src/
│   │   │   ├── controllers/        # HTTP controllers
│   │   │   ├── presenters/         # Response formatters
│   │   │   ├── repositories/       # Data access implementations
│   │   │   ├── guards/             # Authentication guards
│   │   │   ├── strategies/         # Passport strategies
│   │   │   ├── database/           # TypeORM entities & migrations
│   │   │   └── external/           # External service clients
│   │   └── test/
│   │
│   └── shared/                     # Shared DTOs, types, utilities
│       ├── src/
│       │   ├── dtos/
│       │   ├── types/
│       │   └── utils/
│       └── test/

└── shared/                         # Cross-domain shared code
    ├── common/
    ├── testing/
    └── types/
```

#### Option 2: Feature-based with Clean Architecture (대안)

```
libs/
├── auth/
│   ├── feature-login/              # Login feature
│   │   ├── src/
│   │   │   ├── domain/             # Login-specific entities & use cases
│   │   │   ├── infrastructure/     # Login-specific adapters
│   │   │   └── presentation/       # Login controllers & DTOs
│   │   └── test/
│   │
│   ├── feature-registration/       # Registration feature
│   ├── feature-social-auth/        # Social authentication feature
│   │
│   └── core/                       # Shared auth domain logic
│       ├── src/
│       │   ├── entities/           # Core User, Token entities
│       │   ├── ports/              # Core repository interfaces
│       │   └── services/           # Domain services
│       └── test/
```

#### 클린 아키텍처 4계층과 Nx 구조의 매핑:

**🔴 1. Entities (가장 안쪽 계층)**

- **위치**: `libs/auth/domain/src/entities/`
- **내용**: User, Token, AuthSession 등 핵심 비즈니스 엔티티
- **특징**: 외부 의존성 없음, 순수한 비즈니스 규칙만 포함

**🟢 2. Use Cases (애플리케이션 비즈니스 로직)**

- **위치**: `libs/auth/domain/src/use-cases/`
- **내용**: LoginUser, RegisterUser, RefreshToken 등 애플리케이션 시나리오
- **특징**: Entities에만 의존, 포트 인터페이스를 통해 외부와 통신

**🔵 3. Interface Adapters (데이터 변환 계층)**

- **위치**: `libs/auth/infrastructure/src/` (controllers, presenters, repositories, guards, strategies)
- **내용**: HTTP 컨트롤러, 데이터베이스 리포지토리 구현체, 인증 가드 등
- **특징**: Use Cases의 포트를 구현, 외부 형식과 내부 형식 간 변환

**🟣 4. Frameworks & Drivers (가장 바깥쪽 계층)**

- **위치**:
  - `libs/auth/infrastructure/src/database/` (TypeORM 설정)
  - `libs/auth/infrastructure/src/external/` (OAuth SDK, 외부 API)
  - `apps/auth-service/src/` (NestJS 프레임워크 설정)
- **내용**: 데이터베이스 드라이버, 웹 프레임워크, 외부 라이브러리
- **특징**: 구체적인 기술 구현, 가장 변동성이 큰 부분

#### 의존성 방향 (Dependency Rule):

```
apps/auth-service (Composition Root)
    ↓ (depends on)
libs/auth/infrastructure (Interface Adapters + Frameworks)
    ↓ (depends on)
libs/auth/domain (Entities + Use Cases)
    ↓ (no external dependencies)
Pure Business Logic
```

#### 권장 사항:

- **Option 1**을 권장합니다. 클린 아키텍처의 4계층을 명확히 분리하면서도 Nx의 라이브러리 구조를 효과적으로 활용합니다.
- `domain` 라이브러리는 외부 의존성이 전혀 없는 순수한 비즈니스 로직만 포함합니다.
- `infrastructure` 라이브러리는 `domain`에 의존하지만, `domain`은 `infrastructure`를 알지 못합니다.
- 앱(`auth-service`)은 모든 것을 조립하는 Composition Root 역할만 합니다.

- 패키지 매니저는 pnpm을 사용하며, Nx의 `nx.json`과 `workspace.json` 파일을 통해 의존성 그래프를 관리합니다.
- nx build tool을 사용하여 각 라이브러리의 빌드 및 테스트를 관리합니다.
- 가능하면 @nestjs 패키지를 사용하여 NestJS의 모듈 시스템을 활용합니다. (예: `@nestjs/common`, `@nestjs/core` 등)

#### 실제 파일 예시:

```
libs/auth/domain/src/entities/user.entity.ts          # 🔴 Entities
libs/auth/domain/src/use-cases/login-user.use-case.ts # 🟢 Use Cases
libs/auth/domain/src/ports/user.repository.ts         # 🟢 Use Cases (포트 정의)

libs/auth/infrastructure/src/controllers/auth.controller.ts    # 🔵 Interface Adapters
libs/auth/infrastructure/src/repositories/user.repository.ts   # 🔵 Interface Adapters
libs/auth/infrastructure/src/database/user.entity.ts          # 🟣 Frameworks & Drivers
libs/auth/infrastructure/src/external/google-oauth.client.ts  # 🟣 Frameworks & Drivers

apps/auth-service/src/app.module.ts                   # 🟣 Frameworks & Drivers (조립)
```

## Components and Interfaces

### Entities Layer (libs/auth-core/entities)

#### User Entity

```typescript
export class User {
  constructor(
    public readonly id: string,
    public readonly email: string,
    private password: string,
    public readonly name: string,
    public readonly profilePicture?: string,
    public readonly provider: AuthProvider = AuthProvider.LOCAL,
    public readonly providerId?: string,
    private isActive: boolean = true,
    private readonly createdAt: Date = new Date(),
    private updatedAt: Date = new Date()
  ) {}

  public validatePassword(plainPassword: string): boolean;
  public updatePassword(newPassword: string): void;
  public updateProfile(name: string, profilePicture?: string): void;
  public deactivate(): void;
  public activate(): void;
  public isAccountActive(): boolean;
}
```

#### Token Entity

```typescript
export class Token {
  constructor(
    public readonly id: string,
    public readonly userId: string,
    public readonly type: TokenType,
    public readonly value: string,
    public readonly expiresAt: Date,
    private isRevoked: boolean = false,
    private readonly createdAt: Date = new Date()
  ) {}

  public isExpired(): boolean;
  public revoke(): void;
  public isValid(): boolean;
}
```

### Use Cases Layer (libs/auth-core/use-cases)

#### Core Use Cases

- `RegisterUserUseCase`: 새 사용자 등록
- `LoginUserUseCase`: 이메일/패스워드 로그인
- `LoginWithMTLSUseCase`: mTLS 인증서 기반 로그인
- `SocialLoginUseCase`: 소셜 로그인 (Google, Apple)
- `RefreshTokenUseCase`: 토큰 갱신
- `ValidateTokenUseCase`: 토큰 검증
- `UpdateProfileUseCase`: 프로필 업데이트
- `RevokeTokenUseCase`: 토큰 무효화

#### Use Case Interface Example

```typescript
export interface LoginUserUseCase {
  execute(
    request: LoginUserRequest,
    presenter: LoginUserOutputPort
  ): Promise<void>;
}

export interface LoginUserRequest {
  email: string;
  password: string;
  clientInfo?: ClientInfo;
}

export interface LoginUserOutputPort {
  presentSuccess(response: LoginUserResponse): void;
  presentInvalidCredentials(): void;
  presentAccountLocked(): void;
  presentError(error: string): void;
}
```

### Interface Adapters Layer (libs/auth-adapters)

#### Controllers

- `AuthController`: REST API endpoints
- `HealthController`: Health check endpoints

#### Repositories (Ports Implementation)

- `UserRepository`: User data persistence
- `TokenRepository`: Token management
- `AuthSessionRepository`: Session management

#### Guards & Strategies

- `JwtAuthGuard`: JWT token validation
- `MTLSAuthGuard`: mTLS certificate validation
- `GoogleOAuthStrategy`: Google OAuth strategy
- `AppleOAuthStrategy`: Apple OAuth strategy

#### Presenters

- `AuthPresenter`: Authentication response formatting
- `ProfilePresenter`: Profile data formatting

### Frameworks & Drivers Layer (apps/auth-service/frameworks)

#### Web Framework Integration

- NestJS modules and decorators
- Express middleware configuration
- Passport.js strategy registration

#### Database Integration

- TypeORM entity mappings
- Database connection configuration
- Migration scripts

#### External Services

- Google OAuth client
- Apple Sign In client
- Certificate authority integration

## Data Models

### Database Schema

#### Users Table

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255),
  name VARCHAR(255) NOT NULL,
  profile_picture TEXT,
  provider VARCHAR(50) DEFAULT 'local',
  provider_id VARCHAR(255),
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Tokens Table

```sql
CREATE TABLE tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL,
  value TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  is_revoked BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Auth Sessions Table

```sql
CREATE TABLE auth_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  session_token VARCHAR(255) UNIQUE NOT NULL,
  client_info JSONB,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### DTOs and Request/Response Models

#### Authentication DTOs

```typescript
export interface RegisterUserDto {
  email: string;
  password: string;
  name: string;
  profilePicture?: string;
}

export interface LoginUserDto {
  email: string;
  password: string;
}

export interface AuthResponseDto {
  accessToken: string;
  refreshToken: string;
  user: UserProfileDto;
  expiresIn: number;
}

export interface UserProfileDto {
  id: string;
  email: string;
  name: string;
  profilePicture?: string;
  provider: string;
}
```

## Error Handling

### Error Types

- `ValidationError`: Input validation failures
- `AuthenticationError`: Authentication failures
- `AuthorizationError`: Authorization failures
- `TokenExpiredError`: Token expiration
- `UserNotFoundError`: User lookup failures
- `DuplicateUserError`: Registration conflicts

### Error Response Format

```typescript
export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: any;
    timestamp: string;
    path: string;
  };
}
```

### Global Exception Filter

```typescript
@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    // Error handling logic with proper logging and response formatting
  }
}
```

## Testing Strategy

### Unit Testing

- **Entities**: Business rule validation
- **Use Cases**: Business logic without external dependencies
- **Repositories**: Data access logic with mocked dependencies

### Integration Testing

- **Controllers**: HTTP request/response handling
- **Database**: Repository implementations with test database
- **External Services**: OAuth flows with mocked providers

### End-to-End Testing

- **Authentication Flows**: Complete user journeys
- **API Endpoints**: Full request/response cycles
- **Security**: Token validation and security measures

### Test Structure

```
test/
├── unit/
│   ├── entities/
│   ├── use-cases/
│   └── repositories/
├── integration/
│   ├── controllers/
│   ├── database/
│   └── external/
└── e2e/
    ├── auth-flows/
    ├── api/
    └── security/
```

### Testing Tools

- **Jest**: Unit and integration testing framework
- **Supertest**: HTTP assertion library
- **Test Containers**: Database testing with Docker
- **MSW**: API mocking for external services

## Security Considerations

### Password Security

- bcrypt hashing with salt rounds ≥ 12
- Password strength validation
- Password history prevention

### Token Security

- JWT with RS256 signing algorithm
- Short-lived access tokens (15 minutes)
- Secure refresh token rotation
- Token blacklisting for logout

### mTLS Implementation

- Client certificate validation
- Certificate revocation checking
- Proper CA chain verification
- Certificate-based user mapping

### Rate Limiting

- Login attempt rate limiting
- API endpoint rate limiting
- Progressive delays for failed attempts

### Audit Logging

- Authentication events logging
- Security event monitoring
- Failed attempt tracking
- User activity logging

## Configuration Management

### Environment Variables

```typescript
export interface AuthConfig {
  jwt: {
    accessTokenSecret: string;
    refreshTokenSecret: string;
    accessTokenExpiresIn: string;
    refreshTokenExpiresIn: string;
  };
  oauth: {
    google: {
      clientId: string;
      clientSecret: string;
    };
    apple: {
      clientId: string;
      teamId: string;
      keyId: string;
      privateKey: string;
    };
  };
  mtls: {
    caCertPath: string;
    clientCertRequired: boolean;
  };
  database: {
    host: string;
    port: number;
    username: string;
    password: string;
    database: string;
  };
}
```

### Configuration Validation

- Environment variable validation at startup
- Type-safe configuration objects
- Default value handling
- Configuration documentation
