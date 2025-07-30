# Auth Service Design Document

## Overview

Auth service는 클린 아키텍처의 4계층 구조를 따라 설계되며, **Nx 빌드 툴과 NestJS 프레임워크**를 중심으로 구현됩니다. NestJS의 강력한 의존성 주입, 모듈 시스템, 데코레이터 기반 개발을 최대한 활용하여 클린 아키텍처 원칙을 준수하면서도 NestJS의 생산성을 극대화합니다.

### 기술 스택 우선순위

1. **NestJS 우선**: NestJS에서 제공하는 기본 기능과 생태계를 최우선으로 활용
2. **공식 패키지 선호**: @nestjs/* 네임스페이스의 공식 패키지 우선 사용
3. **대안 적용**: NestJS로 해결이 어려운 경우에만 서드파티 라이브러리 사용

## Architecture

### Clean Architecture Layers with NestJS Integration

```
┌─────────────────────────────────────────────────────────────┐
│                    Frameworks & Drivers                     │
│  Nx Build Tool, NestJS Framework, @nestjs/passport,        │
│  @nestjs/jwt, @nestjs/typeorm, @nestjs/config,             │
│  @nestjs/throttler, Express, Google/Apple OAuth SDKs       │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                   Interface Adapters                        │
│  NestJS Controllers (@Controller), Guards (@UseGuards),     │
│  Interceptors (@UseInterceptors), Pipes (@UsePipes),       │
│  DTOs (class-validator), Repositories (@Injectable)        │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                      Use Cases                              │
│  NestJS Services (@Injectable): LoginUser, RegisterUser,   │
│  RefreshToken, UpdateProfile, ValidateToken, SocialLogin   │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                       Entities                              │
│  Pure TypeScript Classes: User, Token, AuthSession         │
│  (No NestJS dependencies - Clean Architecture Core)        │
└─────────────────────────────────────────────────────────────┘
```

### Nx Monorepo Structure with NestJS

Nx 빌드 툴을 활용하여 NestJS 애플리케이션을 효율적으로 관리하고, 클린 아키텍처를 적용하는 구조입니다:

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

#### Option 2: Single NestJS App with Clean Architecture Layers (채택)

```
apps/
├── auth-service/                    # NestJS Application (Nx Generated)
│   ├── src/
│   │   ├── main.ts                 # NestJS Bootstrap with Nx integration
│   │   ├── app.module.ts           # Root Module with NestJS DI
│   │   │
│   │   ├── domain/                 # 🔴 Entities + 🟢 Use Cases (Pure TypeScript)
│   │   │   ├── entities/           # Business entities (No NestJS deps)
│   │   │   │   ├── user.entity.ts
│   │   │   │   ├── token.entity.ts
│   │   │   │   └── auth-session.entity.ts
│   │   │   ├── use-cases/          # Use Case Services (@Injectable)
│   │   │   │   ├── login-user.use-case.ts
│   │   │   │   ├── register-user.use-case.ts
│   │   │   │   └── refresh-token.use-case.ts
│   │   │   └── ports/              # Interface definitions (Abstract classes)
│   │   │       ├── user.repository.ts
│   │   │       ├── token.repository.ts
│   │   │       └── oauth.service.ts
│   │   │
│   │   ├── infrastructure/         # 🔵 Interface Adapters + 🟣 NestJS Framework
│   │   │   ├── controllers/        # NestJS Controllers (@Controller)
│   │   │   │   ├── auth.controller.ts
│   │   │   │   ├── social-auth.controller.ts
│   │   │   │   └── profile.controller.ts
│   │   │   ├── guards/             # NestJS Guards (@Injectable, CanActivate)
│   │   │   │   ├── jwt-auth.guard.ts
│   │   │   │   └── mtls-auth.guard.ts
│   │   │   ├── strategies/         # Passport Strategies (@Injectable)
│   │   │   │   ├── jwt.strategy.ts
│   │   │   │   ├── google-oauth.strategy.ts
│   │   │   │   └── apple-oauth.strategy.ts
│   │   │   ├── repositories/       # Repository Implementations (@Injectable)
│   │   │   │   ├── user.repository.impl.ts
│   │   │   │   └── token.repository.impl.ts
│   │   │   ├── services/           # Infrastructure Services (@Injectable)
│   │   │   │   ├── password-hashing.service.ts
│   │   │   │   └── jwt-token.service.ts
│   │   │   ├── database/           # TypeORM Integration
│   │   │   │   ├── entities/       # TypeORM Entities
│   │   │   │   │   ├── user.orm-entity.ts
│   │   │   │   │   └── token.orm-entity.ts
│   │   │   │   └── migrations/     # TypeORM Migrations
│   │   │   ├── external/           # External Service Clients (@Injectable)
│   │   │   │   ├── google-oauth.client.ts
│   │   │   │   └── apple-oauth.client.ts
│   │   │   ├── interceptors/       # NestJS Interceptors (@Injectable)
│   │   │   │   ├── logging.interceptor.ts
│   │   │   │   └── transform.interceptor.ts
│   │   │   └── filters/            # Exception Filters (@Catch)
│   │   │       └── global-exception.filter.ts
│   │   │
│   │   ├── shared/                 # Shared Components
│   │   │   ├── dtos/               # DTOs with class-validator
│   │   │   │   ├── auth.dto.ts
│   │   │   │   └── user.dto.ts
│   │   │   ├── types/              # TypeScript Types & Enums
│   │   │   ├── decorators/         # Custom NestJS Decorators
│   │   │   └── utils/              # Utility Functions
│   │   │
│   │   ├── config/                 # NestJS Configuration
│   │   │   ├── auth.config.ts      # @nestjs/config integration
│   │   │   ├── database.config.ts
│   │   │   └── oauth.config.ts
│   │   │
│   │   └── modules/                # Feature Modules
│   │       ├── auth.module.ts      # Authentication Module
│   │       ├── user.module.ts      # User Management Module
│   │       └── database.module.ts  # Database Module
│   │
│   ├── project.json                # Nx Project Configuration
│   ├── tsconfig.app.json          # TypeScript Config for App
│   └── test/                       # NestJS Testing
│       ├── unit/                   # Jest Unit Tests
│       ├── integration/            # Integration Tests
│       └── e2e/                    # E2E Tests with @nestjs/testing
│
├── nx.json                         # Nx Workspace Configuration
├── package.json                    # Dependencies with NestJS packages
└── tsconfig.base.json             # Base TypeScript Configuration
```

#### Option 3: Feature-based with Clean Architecture (대안)

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

**기본 채택 방안: Option 2 (Single NestJS App with Clean Architecture)**

이 프로젝트에서는 **Option 2**를 기본으로 채택하여 **Nx + NestJS**의 강력한 조합을 활용합니다.

**NestJS 중심 개발 전략:**

- **NestJS 의존성 주입**: `@Injectable`, `@Inject` 데코레이터를 활용한 깔끔한 DI
- **모듈 시스템**: `@Module` 데코레이터로 기능별 모듈 분리 및 의존성 관리
- **데코레이터 기반**: `@Controller`, `@UseGuards`, `@UsePipes` 등으로 선언적 개발
- **공식 패키지 우선**: `@nestjs/*` 네임스페이스 패키지를 최대한 활용

**Option 2 + NestJS 채택 이유:**

- **NestJS 생산성**: 강력한 CLI, 자동 생성, Hot Reload 등 개발 효율성 극대화
- **타입 안전성**: TypeScript First 접근으로 컴파일 타임 오류 방지
- **테스트 친화적**: `@nestjs/testing` 모듈로 DI 컨테이너 기반 테스트 지원
- **확장성**: NestJS 생태계의 풍부한 패키지들 활용 가능
- **클린 아키텍처 준수**: NestJS의 모듈 시스템이 클린 아키텍처와 자연스럽게 조화

**NestJS 패키지 활용 계획:**

- `@nestjs/passport`: 인증 전략 구현
- `@nestjs/jwt`: JWT 토큰 관리
- `@nestjs/typeorm`: 데이터베이스 ORM
- `@nestjs/config`: 환경 설정 관리
- `@nestjs/throttler`: Rate Limiting
- `@nestjs/swagger`: API 문서화

#### 실제 파일 예시:

**Option 1 (Library-based):**

```
libs/auth/domain/src/entities/user.entity.ts          # � Esntities
libs/auth/domain/src/use-cases/login-user.use-case.ts # 🟢 Use Cases
libs/auth/domain/src/ports/user.repository.ts         # 🟢 Use Cases (포트 정의)

libs/auth/infrastructure/src/controllers/auth.controller.ts    # 🔵 Interface Adapters
libs/auth/infrastructure/src/repositories/user.repository.ts   # � Interoface Adapters
libs/auth/infrastructure/src/database/user.entity.ts          # 🟣 Frameworks & Drivers
libs/auth/infrastructure/src/external/google-oauth.client.ts  # 🟣 Frameworks & Drivers

apps/auth-service/src/app.module.ts                   # 🟣 Frameworks & Drivers (조립)
```

**Option 2 (Single App):**

```
apps/auth-service/src/domain/entities/user.entity.ts                    # 🔴 Entities
apps/auth-service/src/domain/use-cases/login-user.use-case.ts          # 🟢 Use Cases
apps/auth-service/src/domain/ports/user.repository.ts                  # 🟢 Use Cases (포트 정의)

apps/auth-service/src/infrastructure/controllers/auth.controller.ts     # 🔵 Interface Adapters
apps/auth-service/src/infrastructure/repositories/user.repository.impl.ts # 🔵 Interface Adapters
apps/auth-service/src/infrastructure/database/entities/user.orm-entity.ts # 🟣 Frameworks & Drivers
apps/auth-service/src/infrastructure/external/google-oauth.client.ts    # 🟣 Frameworks & Drivers

apps/auth-service/src/app.module.ts                            # 🟣 Frameworks & Drivers (조립)
```

## NestJS Components and Clean Architecture Integration

### Entities Layer (Pure TypeScript - No NestJS Dependencies)

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

### Use Cases Layer (NestJS Services with @Injectable)

#### Core Use Cases as NestJS Services

- `RegisterUserUseCase`: 새 사용자 등록 (`@Injectable` 서비스)
- `LoginUserUseCase`: 이메일/패스워드 로그인 (`@Injectable` 서비스)
- `LoginWithMTLSUseCase`: mTLS 인증서 기반 로그인 (`@Injectable` 서비스)
- `SocialLoginUseCase`: 소셜 로그인 (`@Injectable` 서비스)
- `RefreshTokenUseCase`: 토큰 갱신 (`@Injectable` 서비스)
- `ValidateTokenUseCase`: 토큰 검증 (`@Injectable` 서비스)
- `UpdateProfileUseCase`: 프로필 업데이트 (`@Injectable` 서비스)
- `RevokeTokenUseCase`: 토큰 무효화 (`@Injectable` 서비스)

#### NestJS Use Case Implementation Example

```typescript
@Injectable()
export class LoginUserUseCase {
  constructor(
    @Inject('UserRepository') private userRepository: UserRepository,
    @Inject('PasswordHashingService') private passwordService: PasswordHashingService,
    @Inject('TokenService') private tokenService: TokenService,
  ) {}

  async execute(request: LoginUserRequest): Promise<LoginUserResponse> {
    // Use case logic implementation
    const user = await this.userRepository.findByEmail(request.email);
    
    if (!user || !user.validatePassword(request.password)) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const tokens = await this.tokenService.generateTokens(user.id);
    
    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: user.toDto(),
    };
  }
}

// Request/Response DTOs with class-validator
export class LoginUserRequest {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsOptional()
  clientInfo?: ClientInfo;
}

export class LoginUserResponse {
  accessToken: string;
  refreshToken: string;
  user: UserProfileDto;
  expiresIn: number;
}
```

### Interface Adapters Layer (NestJS Infrastructure Components)

#### NestJS Controllers

```typescript
@Controller('auth')
@UseInterceptors(LoggingInterceptor)
export class AuthController {
  constructor(
    private loginUseCase: LoginUserUseCase,
    private registerUseCase: RegisterUserUseCase,
  ) {}

  @Post('login')
  @UsePipes(ValidationPipe)
  async login(@Body() loginDto: LoginUserRequest): Promise<LoginUserResponse> {
    return this.loginUseCase.execute(loginDto);
  }

  @Post('register')
  @UsePipes(ValidationPipe)
  async register(@Body() registerDto: RegisterUserRequest): Promise<AuthResponseDto> {
    return this.registerUseCase.execute(registerDto);
  }
}
```

#### NestJS Guards & Strategies

```typescript
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext): boolean | Promise<boolean> {
    // Custom JWT validation logic
    return super.canActivate(context);
  }
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(@Inject('JWT_CONFIG') private jwtConfig: JwtConfig) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtConfig.accessTokenSecret,
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }
}
```

#### Repository Implementations (NestJS + TypeORM)

```typescript
@Injectable()
export class UserRepositoryImpl implements UserRepository {
  constructor(
    @InjectRepository(UserOrmEntity)
    private userOrmRepository: Repository<UserOrmEntity>,
  ) {}

  async findByEmail(email: string): Promise<User | null> {
    const userOrm = await this.userOrmRepository.findOne({ where: { email } });
    return userOrm ? this.toDomainEntity(userOrm) : null;
  }

  async save(user: User): Promise<User> {
    const userOrm = this.toOrmEntity(user);
    const saved = await this.userOrmRepository.save(userOrm);
    return this.toDomainEntity(saved);
  }
}
```

### Frameworks & Drivers Layer (NestJS Ecosystem Integration)

#### NestJS Module System

```typescript
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: authConfigSchema,
    }),
    TypeOrmModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('DATABASE_HOST'),
        port: configService.get('DATABASE_PORT'),
        // ... other config
      }),
      inject: [ConfigService],
    }),
    PassportModule,
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_ACCESS_SECRET'),
        signOptions: { expiresIn: '15m' },
      }),
      inject: [ConfigService],
    }),
    ThrottlerModule.forRoot({
      ttl: 60,
      limit: 10,
    }),
  ],
  controllers: [AuthController, ProfileController],
  providers: [
    // Use Cases
    LoginUserUseCase,
    RegisterUserUseCase,
    // Repositories
    { provide: 'UserRepository', useClass: UserRepositoryImpl },
    // Services
    { provide: 'PasswordHashingService', useClass: BcryptPasswordService },
    // Strategies
    JwtStrategy,
    GoogleOAuthStrategy,
    // Guards
    JwtAuthGuard,
  ],
})
export class AuthModule {}
```

#### NestJS + TypeORM Integration

```typescript
@Entity('users')
export class UserOrmEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ name: 'password_hash', nullable: true })
  passwordHash: string;

  @Column()
  name: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
```

#### External Services with NestJS

```typescript
@Injectable()
export class GoogleOAuthService implements OAuthService {
  constructor(
    @Inject('GOOGLE_CONFIG') private googleConfig: GoogleConfig,
    private httpService: HttpService,
  ) {}

  async exchangeCodeForTokens(code: string): Promise<OAuthTokens> {
    // Google OAuth implementation using @nestjs/axios
  }
}
```

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
