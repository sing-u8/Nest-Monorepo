import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from '../app.module';
import { 
  UserRepository,
  TokenRepository,
  AuthSessionRepository,
  PasswordHashingService,
  TokenService,
  AuditLoggerService,
} from '@auth/domain';
import {
  TypeOrmUserRepository,
  TypeOrmTokenRepository,
  TypeOrmAuthSessionRepository,
  BcryptPasswordHashingService,
  JwtTokenService,
} from '@auth/infrastructure';
import { DataSource } from 'typeorm';
import { AppConfig } from '@auth/infrastructure';

describe('Configuration and Dependency Injection Integration Tests', () => {
  let app: INestApplication;
  let module: TestingModule;
  let configService: ConfigService;
  let dataSource: DataSource;

  beforeAll(async () => {
    // Set comprehensive test environment variables
    process.env.NODE_ENV = 'test';
    process.env.PORT = '3003';
    process.env.API_PREFIX = 'api/v1';
    
    // JWT Configuration
    process.env.JWT_SECRET = 'test-jwt-secret-key-for-configuration-testing-very-long-secret';
    process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key-for-configuration-testing-very-long-secret';
    process.env.JWT_ISSUER = 'auth-service-test';
    process.env.JWT_AUDIENCE = 'auth-api-test';
    process.env.JWT_ACCESS_TOKEN_EXPIRATION = '15m';
    process.env.JWT_REFRESH_TOKEN_EXPIRATION = '7d';
    
    // Database Configuration
    process.env.DATABASE_TYPE = 'postgres';
    process.env.DATABASE_HOST = 'localhost';
    process.env.DATABASE_PORT = '5432';
    process.env.DATABASE_USERNAME = 'test_user';
    process.env.DATABASE_PASSWORD = 'test_password';
    process.env.DATABASE_NAME = 'test_auth_config_db';
    process.env.DATABASE_SYNCHRONIZE = 'true';
    process.env.DATABASE_DROP_SCHEMA = 'true';
    process.env.DATABASE_POOL_MAX = '10';
    process.env.DATABASE_POOL_MIN = '2';
    
    // Security Configuration
    process.env.SECURITY_ENABLE_RATE_LIMITING = 'false';
    process.env.SECURITY_ENABLE_HELMET = 'true';
    process.env.SECURITY_ENABLE_MTLS = 'false';
    process.env.API_ENABLE_CORS = 'true';
    
    // OAuth Configuration (optional)
    process.env.GOOGLE_CLIENT_ID = 'test-google-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';
    process.env.GOOGLE_CALLBACK_URL = 'http://localhost:3003/auth/google/callback';
    
    // Apple OAuth
    process.env.APPLE_CLIENT_ID = 'test-apple-client-id';
    process.env.APPLE_TEAM_ID = 'test-apple-team-id';
    process.env.APPLE_KEY_ID = 'test-apple-key-id';
    process.env.APPLE_PRIVATE_KEY = 'test-apple-private-key';
    process.env.APPLE_CALLBACK_URL = 'http://localhost:3003/auth/apple/callback';
    
    // Monitoring Configuration
    process.env.MONITORING_ENABLE_HEALTH_CHECK = 'true';
    process.env.MONITORING_ENABLE_METRICS = 'false';
    process.env.MONITORING_HEALTH_CHECK_PATH = '/health';
    
    // Logging Configuration
    process.env.LOG_LEVEL = 'error';
    process.env.LOG_ENABLE_CONSOLE = 'false';
    process.env.LOG_ENABLE_FILE = 'false';

    module = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = module.createNestApplication();
    configService = module.get<ConfigService>(ConfigService);
    dataSource = module.get<DataSource>(DataSource);

    await app.init();
  });

  afterAll(async () => {
    if (dataSource?.isInitialized) {
      await dataSource.destroy();
    }
    await app.close();
  });

  describe('Configuration Service', () => {
    it('should load configuration from environment variables', () => {
      const config = configService.get<AppConfig>('app');
      
      expect(config).toBeDefined();
      expect(config.NODE_ENV).toBe('test');
      expect(config.PORT).toBe(3003);
      expect(config.API_PREFIX).toBe('api/v1');
    });

    it('should have correct JWT configuration', () => {
      const config = configService.get<AppConfig>('app');
      
      expect(config.JWT_SECRET).toBe('test-jwt-secret-key-for-configuration-testing-very-long-secret');
      expect(config.JWT_REFRESH_SECRET).toBe('test-refresh-secret-key-for-configuration-testing-very-long-secret');
      expect(config.JWT_ISSUER).toBe('auth-service-test');
      expect(config.JWT_AUDIENCE).toBe('auth-api-test');
      expect(config.JWT_ACCESS_TOKEN_EXPIRATION).toBe('15m');
      expect(config.JWT_REFRESH_TOKEN_EXPIRATION).toBe('7d');
    });

    it('should have correct database configuration', () => {
      const config = configService.get<AppConfig>('app');
      
      expect(config.DATABASE_TYPE).toBe('postgres');
      expect(config.DATABASE_HOST).toBe('localhost');
      expect(config.DATABASE_PORT).toBe(5432);
      expect(config.DATABASE_USERNAME).toBe('test_user');
      expect(config.DATABASE_PASSWORD).toBe('test_password');
      expect(config.DATABASE_NAME).toBe('test_auth_config_db');
      expect(config.DATABASE_SYNCHRONIZE).toBe(true);
      expect(config.DATABASE_DROP_SCHEMA).toBe(true);
      expect(config.DATABASE_POOL_MAX).toBe(10);
      expect(config.DATABASE_POOL_MIN).toBe(2);
    });

    it('should have correct security configuration', () => {
      const config = configService.get<AppConfig>('app');
      
      expect(config.SECURITY_ENABLE_RATE_LIMITING).toBe(false);
      expect(config.SECURITY_ENABLE_HELMET).toBe(true);
      expect(config.SECURITY_ENABLE_MTLS).toBe(false);
      expect(config.API_ENABLE_CORS).toBe(true);
    });

    it('should have correct OAuth configuration', () => {
      const config = configService.get<AppConfig>('app');
      
      expect(config.GOOGLE_CLIENT_ID).toBe('test-google-client-id');
      expect(config.GOOGLE_CLIENT_SECRET).toBe('test-google-client-secret');
      expect(config.GOOGLE_CALLBACK_URL).toBe('http://localhost:3003/auth/google/callback');
      
      expect(config.APPLE_CLIENT_ID).toBe('test-apple-client-id');
      expect(config.APPLE_TEAM_ID).toBe('test-apple-team-id');
      expect(config.APPLE_KEY_ID).toBe('test-apple-key-id');
      expect(config.APPLE_PRIVATE_KEY).toBe('test-apple-private-key');
      expect(config.APPLE_CALLBACK_URL).toBe('http://localhost:3003/auth/apple/callback');
    });

    it('should have correct monitoring configuration', () => {
      const config = configService.get<AppConfig>('app');
      
      expect(config.MONITORING_ENABLE_HEALTH_CHECK).toBe(true);
      expect(config.MONITORING_ENABLE_METRICS).toBe(false);
      expect(config.MONITORING_HEALTH_CHECK_PATH).toBe('/health');
    });

    it('should have correct logging configuration', () => {
      const config = configService.get<AppConfig>('app');
      
      expect(config.LOG_LEVEL).toBe('error');
      expect(config.LOG_ENABLE_CONSOLE).toBe(false);
      expect(config.LOG_ENABLE_FILE).toBe(false);
    });
  });

  describe('Repository Dependency Injection', () => {
    it('should inject UserRepository correctly', () => {
      const userRepository = module.get<UserRepository>('UserRepository');
      
      expect(userRepository).toBeDefined();
      expect(userRepository).toBeInstanceOf(TypeOrmUserRepository);
    });

    it('should inject TokenRepository correctly', () => {
      const tokenRepository = module.get<TokenRepository>('TokenRepository');
      
      expect(tokenRepository).toBeDefined();
      expect(tokenRepository).toBeInstanceOf(TypeOrmTokenRepository);
    });

    it('should inject AuthSessionRepository correctly', () => {
      const sessionRepository = module.get<AuthSessionRepository>('AuthSessionRepository');
      
      expect(sessionRepository).toBeDefined();
      expect(sessionRepository).toBeInstanceOf(TypeOrmAuthSessionRepository);
    });

    it('should ensure repositories are singletons', () => {
      const userRepository1 = module.get<UserRepository>('UserRepository');
      const userRepository2 = module.get<UserRepository>('UserRepository');
      
      expect(userRepository1).toBe(userRepository2);
    });
  });

  describe('Service Dependency Injection', () => {
    it('should inject PasswordHashingService correctly', () => {
      const passwordService = module.get<PasswordHashingService>('PasswordHashingService');
      
      expect(passwordService).toBeDefined();
      expect(passwordService).toBeInstanceOf(BcryptPasswordHashingService);
    });

    it('should inject TokenService correctly', () => {
      const tokenService = module.get<TokenService>('TokenService');
      
      expect(tokenService).toBeDefined();
      expect(tokenService).toBeInstanceOf(JwtTokenService);
    });

    it('should inject AuditLoggerService correctly', () => {
      const auditLogger = module.get<AuditLoggerService>(AuditLoggerService);
      
      expect(auditLogger).toBeDefined();
      expect(auditLogger).toBeInstanceOf(AuditLoggerService);
    });

    it('should ensure services are singletons', () => {
      const tokenService1 = module.get<TokenService>('TokenService');
      const tokenService2 = module.get<TokenService>('TokenService');
      
      expect(tokenService1).toBe(tokenService2);
    });
  });

  describe('Database Connection Injection', () => {
    it('should inject DataSource correctly', () => {
      expect(dataSource).toBeDefined();
      expect(dataSource.isInitialized).toBe(true);
    });

    it('should have correct database configuration in DataSource', () => {
      expect(dataSource.options.type).toBe('postgres');
      expect(dataSource.options.host).toBe('localhost');
      expect(dataSource.options.port).toBe(5432);
      expect(dataSource.options.database).toBe('test_auth_config_db');
      expect(dataSource.options.username).toBe('test_user');
    });

    it('should have correct connection pool configuration', () => {
      const poolConfig = dataSource.options.extra;
      expect(poolConfig.max).toBe(10);
      expect(poolConfig.min).toBe(2);
    });
  });

  describe('Cross-Service Dependencies', () => {
    it('should inject dependencies into use cases correctly', async () => {
      // Test that use cases have their dependencies injected
      const registerUseCase = module.get('RegisterUserUseCase');
      const loginUseCase = module.get('LoginUserUseCase');
      const refreshTokenUseCase = module.get('RefreshTokenUseCase');
      
      expect(registerUseCase).toBeDefined();
      expect(loginUseCase).toBeDefined();
      expect(refreshTokenUseCase).toBeDefined();
    });

    it('should maintain proper dependency hierarchy', () => {
      // Controllers should have use cases injected
      const authController = module.get('AuthController');
      expect(authController).toBeDefined();

      // Use cases should have repositories and services injected
      const userRepository = module.get<UserRepository>('UserRepository');
      const passwordService = module.get<PasswordHashingService>('PasswordHashingService');
      const tokenService = module.get<TokenService>('TokenService');
      
      expect(userRepository).toBeDefined();
      expect(passwordService).toBeDefined();
      expect(tokenService).toBeDefined();
    });
  });

  describe('Module Loading', () => {
    it('should load all required modules', () => {
      // Verify that core modules are loaded
      const loadedModules = module['moduleMetadata'];
      expect(loadedModules).toBeDefined();
    });

    it('should load infrastructure module correctly', () => {
      // Test that infrastructure providers are available
      const userRepository = module.get('UserRepository');
      const tokenRepository = module.get('TokenRepository');
      const sessionRepository = module.get('AuthSessionRepository');
      
      expect(userRepository).toBeDefined();
      expect(tokenRepository).toBeDefined();
      expect(sessionRepository).toBeDefined();
    });

    it('should load domain module correctly', () => {
      // Test that domain services are available
      const passwordService = module.get('PasswordHashingService');
      const tokenService = module.get('TokenService');
      
      expect(passwordService).toBeDefined();
      expect(tokenService).toBeDefined();
    });
  });

  describe('Configuration Validation', () => {
    it('should validate required configuration values', () => {
      const config = configService.get<AppConfig>('app');
      
      // JWT secrets should be long enough
      expect(config.JWT_SECRET.length).toBeGreaterThan(32);
      expect(config.JWT_REFRESH_SECRET.length).toBeGreaterThan(32);
      
      // Database configuration should be complete
      expect(config.DATABASE_HOST).toBeTruthy();
      expect(config.DATABASE_PORT).toBeGreaterThan(0);
      expect(config.DATABASE_USERNAME).toBeTruthy();
      expect(config.DATABASE_PASSWORD).toBeTruthy();
      expect(config.DATABASE_NAME).toBeTruthy();
    });

    it('should have appropriate defaults for optional values', () => {
      const config = configService.get<AppConfig>('app');
      
      // Should have default values for optional configurations
      expect(typeof config.SECURITY_ENABLE_RATE_LIMITING).toBe('boolean');
      expect(typeof config.SECURITY_ENABLE_HELMET).toBe('boolean');
      expect(typeof config.API_ENABLE_CORS).toBe('boolean');
    });
  });

  describe('Environment-Specific Configuration', () => {
    it('should have test-specific configuration', () => {
      const config = configService.get<AppConfig>('app');
      
      expect(config.NODE_ENV).toBe('test');
      expect(config.DATABASE_SYNCHRONIZE).toBe(true);
      expect(config.DATABASE_DROP_SCHEMA).toBe(true);
      expect(config.LOG_LEVEL).toBe('error');
      expect(config.LOG_ENABLE_CONSOLE).toBe(false);
    });

    it('should disable certain features in test environment', () => {
      const config = configService.get<AppConfig>('app');
      
      expect(config.SECURITY_ENABLE_RATE_LIMITING).toBe(false);
      expect(config.MONITORING_ENABLE_METRICS).toBe(false);
      expect(config.LOG_ENABLE_FILE).toBe(false);
    });
  });

  describe('Circular Dependency Prevention', () => {
    it('should not have circular dependencies in repositories', () => {
      // This test ensures that repository injections don't cause circular dependencies
      const userRepository = module.get<UserRepository>('UserRepository');
      const tokenRepository = module.get<TokenRepository>('TokenRepository');
      const sessionRepository = module.get<AuthSessionRepository>('AuthSessionRepository');
      
      expect(userRepository).toBeDefined();
      expect(tokenRepository).toBeDefined();
      expect(sessionRepository).toBeDefined();
      
      // All should be different instances
      expect(userRepository).not.toBe(tokenRepository);
      expect(userRepository).not.toBe(sessionRepository);
      expect(tokenRepository).not.toBe(sessionRepository);
    });

    it('should not have circular dependencies in services', () => {
      const passwordService = module.get<PasswordHashingService>('PasswordHashingService');
      const tokenService = module.get<TokenService>('TokenService');
      const auditLogger = module.get<AuditLoggerService>(AuditLoggerService);
      
      expect(passwordService).toBeDefined();
      expect(tokenService).toBeDefined();
      expect(auditLogger).toBeDefined();
      
      // All should be different instances
      expect(passwordService).not.toBe(tokenService);
      expect(passwordService).not.toBe(auditLogger);
      expect(tokenService).not.toBe(auditLogger);
    });
  });

  describe('Dynamic Configuration Updates', () => {
    it('should handle missing optional configuration gracefully', () => {
      // Test with missing OAuth configuration
      delete process.env.GOOGLE_CLIENT_ID;
      
      // Should still work without crashing
      const config = configService.get<AppConfig>('app');
      expect(config).toBeDefined();
      expect(config.GOOGLE_CLIENT_ID).toBeUndefined();
    });

    it('should maintain configuration immutability', () => {
      const config1 = configService.get<AppConfig>('app');
      const config2 = configService.get<AppConfig>('app');
      
      expect(config1).toEqual(config2);
      
      // Attempting to modify should not affect other references
      (config1 as any).JWT_SECRET = 'modified-secret';
      expect(config2.JWT_SECRET).not.toBe('modified-secret');
    });
  });

  describe('Provider Scoping', () => {
    it('should have correct provider scopes', () => {
      // Repositories should be singleton scoped
      const userRepo1 = module.get<UserRepository>('UserRepository');
      const userRepo2 = module.get<UserRepository>('UserRepository');
      expect(userRepo1).toBe(userRepo2);
      
      // Services should be singleton scoped
      const tokenService1 = module.get<TokenService>('TokenService');
      const tokenService2 = module.get<TokenService>('TokenService');
      expect(tokenService1).toBe(tokenService2);
    });
  });

  describe('Graceful Shutdown', () => {
    it('should handle module cleanup properly', async () => {
      // This test verifies that the module can be closed without errors
      const testModule = await Test.createTestingModule({
        imports: [AppModule],
      }).compile();

      const testApp = testModule.createNestApplication();
      await testApp.init();
      
      // Should close without throwing errors
      await expect(testApp.close()).resolves.not.toThrow();
    });
  });
});