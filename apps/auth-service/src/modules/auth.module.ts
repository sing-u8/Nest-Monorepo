import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { HttpModule } from '@nestjs/axios';

// Database Module
import { DatabaseModule } from './database.module';

// Controllers
import { AuthController } from '../infrastructure/controllers/auth.controller';
import { SocialAuthController } from '../infrastructure/controllers/social-auth.controller';
import { ProfileController } from '../infrastructure/controllers/profile.controller';

// Use Cases
import { RegisterUserUseCase } from '../domain/use-cases/register-user.use-case';
import { LoginUserUseCase } from '../domain/use-cases/login-user.use-case';
import { RefreshTokenUseCase } from '../domain/use-cases/refresh-token.use-case';
import { SocialLoginUseCase } from '../domain/use-cases/social-login.use-case';
import { UpdateProfileUseCase } from '../domain/use-cases/update-profile.use-case';

// Repository Ports & Implementations
import { UserRepository } from '../domain/ports/user.repository';
import { TokenRepository } from '../domain/ports/token.repository';
import { AuthSessionRepository } from '../domain/ports/auth-session.repository';
import { UserRepositoryImpl } from '../infrastructure/repositories/user.repository.impl';
import { TokenRepositoryImpl } from '../infrastructure/repositories/token.repository.impl';
import { AuthSessionRepositoryImpl } from '../infrastructure/repositories/auth-session.repository.impl';

// Service Ports & Implementations
import { PasswordHashingService } from '../domain/ports/password-hashing.service';
import { TokenService } from '../domain/ports/token.service';
import { GoogleOAuthService } from '../domain/ports/google-oauth.service';
import { AppleOAuthService } from '../domain/ports/apple-oauth.service';
import { PasswordHashingServiceImpl } from '../infrastructure/services/password-hashing.service.impl';
import { JwtTokenServiceImpl } from '../infrastructure/services/jwt-token.service.impl';
import { GoogleOAuthServiceImpl } from '../infrastructure/external/google-oauth.service.impl';
import { AppleOAuthServiceImpl } from '../infrastructure/external/apple-oauth.service.impl';

// Presenters
import { AuthPresenter } from '../infrastructure/presenters/auth.presenter';
import { ProfilePresenter } from '../infrastructure/presenters/profile.presenter';
import { ErrorPresenter } from '../infrastructure/presenters/error.presenter';

// Guards & Strategies
import { JwtAuthGuard } from '../infrastructure/guards/jwt-auth.guard';
import { MtlsAuthGuard } from '../infrastructure/guards/mtls-auth.guard';
import { RolesGuard } from '../infrastructure/guards/roles.guard';
import { JwtStrategy } from '../infrastructure/strategies/jwt.strategy';
import { GoogleStrategy } from '../infrastructure/strategies/google.strategy';
import { AppleStrategy } from '../infrastructure/strategies/apple.strategy';

// Security Module
import { SecurityModule } from '../infrastructure/security/security.module';

/**
 * Authentication Module
 * 
 * Main module for authentication functionality with clean architecture
 * separation and comprehensive dependency injection configuration.
 */
@Module({
  imports: [
    ConfigModule,
    DatabaseModule,
    SecurityModule,
    HttpModule.register({
      timeout: 10000,
      maxRedirects: 5,
    }),
    PassportModule.register({ 
      defaultStrategy: 'jwt',
      session: false,
    }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('jwt.accessToken.secret'),
        signOptions: {
          expiresIn: configService.get<string>('jwt.accessToken.expiresIn', '15m'),
          issuer: 'auth-service',
          audience: 'auth-service-users',
        },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [
    AuthController,
    SocialAuthController,
    ProfileController,
  ],
  providers: [
    // Use Cases
    RegisterUserUseCase,
    LoginUserUseCase,
    RefreshTokenUseCase,
    SocialLoginUseCase,
    UpdateProfileUseCase,

    // Repository Implementations with Interface Injection
    {
      provide: UserRepository,
      useClass: UserRepositoryImpl,
    },
    {
      provide: TokenRepository,
      useClass: TokenRepositoryImpl,
    },
    {
      provide: AuthSessionRepository,
      useClass: AuthSessionRepositoryImpl,
    },

    // Service Implementations with Interface Injection
    {
      provide: PasswordHashingService,
      useClass: PasswordHashingServiceImpl,
    },
    {
      provide: TokenService,
      useClass: JwtTokenServiceImpl,
    },
    {
      provide: GoogleOAuthService,
      useClass: GoogleOAuthServiceImpl,
    },
    {
      provide: AppleOAuthService,
      useClass: AppleOAuthServiceImpl,
    },

    // Presenters
    AuthPresenter,
    ProfilePresenter,
    ErrorPresenter,

    // Guards
    JwtAuthGuard,
    MtlsAuthGuard,
    RolesGuard,

    // Strategies
    JwtStrategy,
    GoogleStrategy,
    AppleStrategy,
  ],
  exports: [
    // Export modules for other parts of the application
    PassportModule,
    JwtModule,
    
    // Export use cases for testing or other modules
    RegisterUserUseCase,
    LoginUserUseCase,
    RefreshTokenUseCase,
    SocialLoginUseCase,
    UpdateProfileUseCase,
    
    // Export services for other modules
    PasswordHashingService,
    TokenService,
    GoogleOAuthService,
    AppleOAuthService,
    
    // Export presenters
    AuthPresenter,
    ProfilePresenter,
    ErrorPresenter,
    
    // Export guards and strategies
    JwtAuthGuard,
    JwtStrategy,
  ],
})
export class AuthModule {}