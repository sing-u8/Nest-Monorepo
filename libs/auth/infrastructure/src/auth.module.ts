import { Module, Global, MiddlewareConsumer, NestModule, RequestMethod } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

// Database
import { DatabaseModule } from './database/database.module';

// Controllers
import { AuthController } from './controllers/auth.controller';
import { SocialAuthController } from './controllers/social-auth.controller';
import { ProfileController } from './controllers/profile.controller';

// Use Cases (Domain Layer)
import {
  RegisterUserUseCase,
  LoginUserUseCase,
  RefreshTokenUseCase,
  LogoutUserUseCase,
  SocialLoginUseCase,
  UpdateProfileUseCase,
  GetUserProfileUseCase,
} from '@auth/domain';

// Repository Implementations
import { TypeOrmUserRepository } from './repositories/typeorm-user.repository';
import { TypeOrmTokenRepository } from './repositories/typeorm-token.repository';
import { TypeOrmAuthSessionRepository } from './repositories/typeorm-auth-session.repository';

// Service Implementations
import { BcryptPasswordHashingService } from './services/bcrypt-password-hashing.service';
import { JwtTokenService } from './services/jwt-token.service';
import { GoogleOAuthService } from './services/google-oauth.service';
import { AppleOAuthService } from './services/apple-oauth.service';
import { AuditLoggerService } from './services/audit-logger.service';

// Presenter Implementations
import { AuthPresenter } from './presenters/auth.presenter';
import { ProfilePresenter } from './presenters/profile.presenter';
import { ErrorPresenter } from './presenters/error.presenter';

// Guards and Strategies
import { JwtAuthGuard, MTLSAuthGuard, RateLimitGuard } from './guards';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { AppleStrategy } from './strategies/apple.strategy';

// Middleware
import { RateLimitingMiddleware } from './middleware/rate-limiting.middleware';
import { InputSanitizationMiddleware } from './middleware/input-sanitization.middleware';
import { SecurityHeadersMiddleware } from './middleware/security-headers.middleware';

// Configuration
import { getJwtConfig } from './config/jwt.config';
import { getPasswordHashingConfig } from './config/password-hashing.config';
import { getOAuthConfig } from './config/oauth.config';
import { getRateLimitingConfig } from './config/rate-limiting.config';

/**
 * Auth Module
 * 
 * Main module for authentication system that configures all dependencies,
 * use cases, repositories, services, and middleware using NestJS DI.
 * 
 * Follows clean architecture principles with proper layer separation.
 */
@Global()
@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
      expandVariables: true,
    }),
    
    // Database
    DatabaseModule,
    
    // Passport
    PassportModule.register({
      defaultStrategy: 'jwt',
      property: 'user',
      session: false,
    }),
    
    // JWT
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        const jwtConfig = getJwtConfig();
        return {
          secret: jwtConfig.secret,
          signOptions: {
            expiresIn: jwtConfig.accessTokenExpiration,
            algorithm: jwtConfig.algorithm,
            issuer: jwtConfig.issuer,
            audience: jwtConfig.audience,
          },
          verifyOptions: {
            algorithms: [jwtConfig.algorithm],
            issuer: jwtConfig.issuer,
            audience: jwtConfig.audience,
            clockTolerance: jwtConfig.clockTolerance,
          },
        };
      },
      inject: [ConfigService],
    }),
  ],
  
  controllers: [
    AuthController,
    SocialAuthController,
    ProfileController,
  ],
  
  providers: [
    // Repository Providers (Infrastructure → Domain)
    {
      provide: 'UserRepository',
      useClass: TypeOrmUserRepository,
    },
    {
      provide: 'TokenRepository',
      useClass: TypeOrmTokenRepository,
    },
    {
      provide: 'AuthSessionRepository',
      useClass: TypeOrmAuthSessionRepository,
    },
    
    // Service Providers (Infrastructure → Domain)
    {
      provide: 'PasswordHashingService',
      useFactory: () => {
        const config = getPasswordHashingConfig();
        return new BcryptPasswordHashingService(config);
      },
    },
    {
      provide: 'TokenService',
      useFactory: () => {
        const config = getJwtConfig();
        return new JwtTokenService(config);
      },
    },
    {
      provide: 'GoogleOAuthService',
      useFactory: () => {
        const config = getOAuthConfig();
        return new GoogleOAuthService(config.google);
      },
    },
    {
      provide: 'AppleOAuthService',
      useFactory: () => {
        const config = getOAuthConfig();
        return new AppleOAuthService(config.apple);
      },
    },
    
    // Audit Logger
    AuditLoggerService,
    
    // Presenter Providers (Infrastructure)
    {
      provide: 'AuthPresenter',
      useClass: AuthPresenter,
    },
    {
      provide: 'ProfilePresenter',
      useClass: ProfilePresenter,
    },
    {
      provide: 'ErrorPresenter',
      useClass: ErrorPresenter,
    },
    
    // Use Case Providers (Domain Layer)
    {
      provide: 'RegisterUserUseCase',
      useFactory: (
        userRepository: any,
        tokenRepository: any,
        authSessionRepository: any,
        passwordHashingService: any,
        tokenService: any,
        authPresenter: any,
      ) => new RegisterUserUseCase(
        userRepository,
        tokenRepository,
        authSessionRepository,
        passwordHashingService,
        tokenService,
        authPresenter,
      ),
      inject: [
        'UserRepository',
        'TokenRepository',
        'AuthSessionRepository',
        'PasswordHashingService',
        'TokenService',
        'AuthPresenter',
      ],
    },
    {
      provide: 'LoginUserUseCase',
      useFactory: (
        userRepository: any,
        tokenRepository: any,
        authSessionRepository: any,
        passwordHashingService: any,
        tokenService: any,
        authPresenter: any,
      ) => new LoginUserUseCase(
        userRepository,
        tokenRepository,
        authSessionRepository,
        passwordHashingService,
        tokenService,
        authPresenter,
      ),
      inject: [
        'UserRepository',
        'TokenRepository',
        'AuthSessionRepository',
        'PasswordHashingService',
        'TokenService',
        'AuthPresenter',
      ],
    },
    {
      provide: 'RefreshTokenUseCase',
      useFactory: (
        userRepository: any,
        tokenRepository: any,
        authSessionRepository: any,
        tokenService: any,
        authPresenter: any,
      ) => new RefreshTokenUseCase(
        userRepository,
        tokenRepository,
        authSessionRepository,
        tokenService,
        authPresenter,
      ),
      inject: [
        'UserRepository',
        'TokenRepository',
        'AuthSessionRepository',
        'TokenService',
        'AuthPresenter',
      ],
    },
    {
      provide: 'LogoutUserUseCase',
      useFactory: (
        userRepository: any,
        tokenRepository: any,
        authSessionRepository: any,
        tokenService: any,
        authPresenter: any,
      ) => new LogoutUserUseCase(
        userRepository,
        tokenRepository,
        authSessionRepository,
        tokenService,
        authPresenter,
      ),
      inject: [
        'UserRepository',
        'TokenRepository',
        'AuthSessionRepository',
        'TokenService',
        'AuthPresenter',
      ],
    },
    {
      provide: 'SocialLoginUseCase',
      useFactory: (
        userRepository: any,
        tokenRepository: any,
        authSessionRepository: any,
        tokenService: any,
        googleOAuthService: any,
        appleOAuthService: any,
        authPresenter: any,
      ) => new SocialLoginUseCase(
        userRepository,
        tokenRepository,
        authSessionRepository,
        tokenService,
        googleOAuthService,
        appleOAuthService,
        authPresenter,
      ),
      inject: [
        'UserRepository',
        'TokenRepository',
        'AuthSessionRepository',
        'TokenService',
        'GoogleOAuthService',
        'AppleOAuthService',
        'AuthPresenter',
      ],
    },
    {
      provide: 'UpdateProfileUseCase',
      useFactory: (
        userRepository: any,
        profilePresenter: any,
      ) => new UpdateProfileUseCase(
        userRepository,
        profilePresenter,
      ),
      inject: [
        'UserRepository',
        'ProfilePresenter',
      ],
    },
    {
      provide: 'GetUserProfileUseCase',
      useFactory: (
        userRepository: any,
        authSessionRepository: any,
      ) => new GetUserProfileUseCase(
        userRepository,
        authSessionRepository,
      ),
      inject: [
        'UserRepository',
        'AuthSessionRepository',
      ],
    },
    
    // Guards
    JwtAuthGuard,
    MTLSAuthGuard,
    RateLimitGuard,
    
    // Passport Strategies
    {
      provide: JwtStrategy,
      useFactory: (userRepository: any) => new JwtStrategy(userRepository),
      inject: ['UserRepository'],
    },
    {
      provide: GoogleStrategy,
      useFactory: (socialLoginUseCase: any) => new GoogleStrategy(socialLoginUseCase),
      inject: ['SocialLoginUseCase'],
    },
    {
      provide: AppleStrategy,
      useFactory: (socialLoginUseCase: any) => new AppleStrategy(socialLoginUseCase),
      inject: ['SocialLoginUseCase'],
    },
    
    // Middleware Providers
    {
      provide: RateLimitingMiddleware,
      useFactory: () => {
        const config = getRateLimitingConfig();
        return new RateLimitingMiddleware(config);
      },
    },
    InputSanitizationMiddleware,
    SecurityHeadersMiddleware,
  ],
  
  exports: [
    // Export use cases for potential external modules
    'RegisterUserUseCase',
    'LoginUserUseCase',
    'RefreshTokenUseCase',
    'LogoutUserUseCase',
    'SocialLoginUseCase',
    'UpdateProfileUseCase',
    'GetUserProfileUseCase',
    
    // Export repositories for potential external modules
    'UserRepository',
    'TokenRepository',
    'AuthSessionRepository',
    
    // Export services for potential external modules
    'PasswordHashingService',
    'TokenService',
    'GoogleOAuthService',
    'AppleOAuthService',
    AuditLoggerService,
    
    // Export presenters
    'AuthPresenter',
    'ProfilePresenter',
    'ErrorPresenter',
    
    // Export guards for use in other modules
    JwtAuthGuard,
    MTLSAuthGuard,
    RateLimitGuard,
    
    // Export strategies
    JwtStrategy,
    GoogleStrategy,
    AppleStrategy,
    
    // Export database module
    DatabaseModule,
    
    // Export JWT module for external token operations
    JwtModule,
  ],
})
export class AuthModule implements NestModule {
  constructor() {
    console.log('🔐 AuthModule initialized successfully');
    console.log('📊 All authentication services configured');
    console.log('🛡️ Security middleware enabled');
    console.log('🗄️ Database connections established');
  }

  /**
   * Configure middleware for authentication routes
   * @param consumer - Middleware consumer for route configuration
   */
  configure(consumer: MiddlewareConsumer): void {
    // Apply security headers to all routes
    consumer
      .apply(SecurityHeadersMiddleware)
      .forRoutes('*');

    // Apply input sanitization to all routes
    consumer
      .apply(InputSanitizationMiddleware)
      .forRoutes('*');

    // Apply rate limiting to authentication routes
    consumer
      .apply(RateLimitingMiddleware)
      .forRoutes(
        { path: '/auth/register', method: RequestMethod.POST },
        { path: '/auth/login', method: RequestMethod.POST },
        { path: '/auth/refresh', method: RequestMethod.POST },
        { path: '/auth/logout', method: RequestMethod.POST },
        { path: '/auth/social/google', method: RequestMethod.POST },
        { path: '/auth/social/apple', method: RequestMethod.POST },
      );

    console.log('🛡️ Authentication middleware configured');
    console.log('   - Security headers: All routes');
    console.log('   - Input sanitization: All routes');
    console.log('   - Rate limiting: Auth endpoints');
  }
}