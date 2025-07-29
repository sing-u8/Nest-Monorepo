import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { HealthService } from './health.service';
import { AppConfig } from '@auth/infrastructure';

describe('HealthService', () => {
  let service: HealthService;
  let configService: jest.Mocked<ConfigService>;

  const mockAppConfig: Partial<AppConfig> = {
    NODE_ENV: 'test',
    JWT_SECRET: 'test-jwt-secret-with-sufficient-length-for-validation',
    JWT_REFRESH_SECRET: 'test-refresh-secret-with-sufficient-length-for-validation',
    JWT_ISSUER: 'auth-service',
    JWT_AUDIENCE: 'auth-api',
    JWT_ACCESS_TOKEN_EXPIRATION: '15m',
    JWT_REFRESH_TOKEN_EXPIRATION: '7d',
    DATABASE_USERNAME: 'test_user',
    DATABASE_PASSWORD: 'test_password',
    DATABASE_NAME: 'test_db',
    DATABASE_TYPE: 'postgres',
    DATABASE_HOST: 'localhost',
    DATABASE_PORT: 5432,
    GOOGLE_CLIENT_ID: 'google-client-id',
    GOOGLE_CLIENT_SECRET: 'google-client-secret',
    GOOGLE_CALLBACK_URL: 'http://localhost:3000/auth/google/callback',
    APPLE_CLIENT_ID: 'apple-client-id',
    APPLE_TEAM_ID: 'apple-team-id',
    APPLE_KEY_ID: 'apple-key-id',
    APPLE_PRIVATE_KEY: 'apple-private-key',
    APPLE_CALLBACK_URL: 'http://localhost:3000/auth/apple/callback',
    APP_NAME: 'Auth Service',
    APP_VERSION: '1.0.0',
    APP_DESCRIPTION: 'NestJS Authentication Service',
    PORT: 3000,
    API_PREFIX: 'api/v1',
    API_ENABLE_CORS: true,
    SECURITY_ENABLE_HELMET: true,
    SECURITY_ENABLE_RATE_LIMITING: true,
    SECURITY_ENABLE_MTLS: false,
    MONITORING_ENABLE_HEALTH_CHECK: true,
    MONITORING_ENABLE_METRICS: true,
    MONITORING_HEALTH_CHECK_PATH: '/health',
    MONITORING_METRICS_PATH: '/metrics',
  };

  beforeEach(async () => {
    const mockConfigService = {
      get: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        HealthService,
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    service = module.get<HealthService>(HealthService);
    configService = module.get(ConfigService);
    
    // Default mock behavior
    configService.get.mockReturnValue(mockAppConfig);
  });

  describe('checkJWTConfiguration', () => {
    it('should pass JWT configuration check with valid config', async () => {
      // Act
      const result = await service.checkJWTConfiguration();

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          jwt_config: expect.objectContaining({
            status: 'up',
            jwtSecretLength: expect.any(Number),
            refreshSecretLength: expect.any(Number),
            issuer: 'auth-service',
            audience: 'auth-api',
            accessTokenExpiration: '15m',
            refreshTokenExpiration: '7d',
          }),
        })
      );
    });

    it('should fail when configuration is not available', async () => {
      // Arrange
      configService.get.mockReturnValue(null);

      // Act & Assert
      await expect(service.checkJWTConfiguration()).rejects.toThrow(
        'JWT configuration is unhealthy: Application configuration not available'
      );
    });

    it('should fail when JWT secret is missing', async () => {
      // Arrange
      const invalidConfig = { ...mockAppConfig, JWT_SECRET: undefined };
      configService.get.mockReturnValue(invalidConfig);

      // Act & Assert
      await expect(service.checkJWTConfiguration()).rejects.toThrow(
        'JWT configuration is unhealthy: JWT secret is missing or too short'
      );
    });

    it('should fail when JWT secret is too short', async () => {
      // Arrange
      const invalidConfig = { ...mockAppConfig, JWT_SECRET: 'short' };
      configService.get.mockReturnValue(invalidConfig);

      // Act & Assert
      await expect(service.checkJWTConfiguration()).rejects.toThrow(
        'JWT configuration is unhealthy: JWT secret is missing or too short'
      );
    });

    it('should fail when refresh secret is missing', async () => {
      // Arrange
      const invalidConfig = { ...mockAppConfig, JWT_REFRESH_SECRET: undefined };
      configService.get.mockReturnValue(invalidConfig);

      // Act & Assert
      await expect(service.checkJWTConfiguration()).rejects.toThrow(
        'JWT configuration is unhealthy: JWT refresh secret is missing or too short'
      );
    });

    it('should fail when refresh secret is too short', async () => {
      // Arrange
      const invalidConfig = { ...mockAppConfig, JWT_REFRESH_SECRET: 'short' };
      configService.get.mockReturnValue(invalidConfig);

      // Act & Assert
      await expect(service.checkJWTConfiguration()).rejects.toThrow(
        'JWT configuration is unhealthy: JWT refresh secret is missing or too short'
      );
    });
  });

  describe('checkOAuthConfiguration', () => {
    it('should pass OAuth configuration check with valid config', async () => {
      // Act
      const result = await service.checkOAuthConfiguration();

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          oauth_config: expect.objectContaining({
            status: 'up',
            google: expect.objectContaining({
              configured: true,
              hasClientId: true,
              hasClientSecret: true,
              hasCallbackUrl: true,
            }),
            apple: expect.objectContaining({
              configured: true,
              hasClientId: true,
              hasTeamId: true,
              hasKeyId: true,
              hasPrivateKey: true,
              hasCallbackUrl: true,
            }),
          }),
        })
      );
    });

    it('should handle partial OAuth configuration', async () => {
      // Arrange
      const partialConfig = {
        ...mockAppConfig,
        GOOGLE_CLIENT_ID: 'google-client-id',
        GOOGLE_CLIENT_SECRET: undefined, // Missing Google secret
        APPLE_CLIENT_ID: undefined, // Missing Apple config
      };
      configService.get.mockReturnValue(partialConfig);

      // Act
      const result = await service.checkOAuthConfiguration();

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          oauth_config: expect.objectContaining({
            status: 'up',
            google: expect.objectContaining({
              configured: false,
              hasClientId: true,
              hasClientSecret: false,
            }),
            apple: expect.objectContaining({
              configured: false,
              hasClientId: false,
            }),
          }),
        })
      );
    });

    it('should handle missing configuration gracefully', async () => {
      // Arrange
      configService.get.mockReturnValue(null);

      // Act
      const result = await service.checkOAuthConfiguration();

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          oauth_config: expect.objectContaining({
            status: 'down',
            error: 'Application configuration not available',
          }),
        })
      );
    });

    it('should not throw error for OAuth failures (optional service)', async () => {
      // Arrange
      configService.get.mockImplementation(() => {
        throw new Error('Configuration error');
      });

      // Act & Assert
      const result = await service.checkOAuthConfiguration();
      expect(result).toEqual(
        expect.objectContaining({
          oauth_config: expect.objectContaining({
            status: 'down',
            error: 'Configuration error',
          }),
        })
      );
    });
  });

  describe('checkRequiredEnvironmentVariables', () => {
    it('should pass when all required variables are present', async () => {
      // Act
      const result = await service.checkRequiredEnvironmentVariables();

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          environment_variables: expect.objectContaining({
            status: 'up',
            totalRequired: 6,
            present: 6,
            missing: 0,
            presentVars: [
              'NODE_ENV',
              'JWT_SECRET',
              'JWT_REFRESH_SECRET',
              'DATABASE_USERNAME',
              'DATABASE_PASSWORD',
              'DATABASE_NAME',
            ],
            environment: 'test',
          }),
        })
      );
    });

    it('should fail when required variables are missing', async () => {
      // Arrange
      const incompleteConfig = {
        ...mockAppConfig,
        DATABASE_USERNAME: undefined,
        DATABASE_PASSWORD: '',
      };
      configService.get.mockReturnValue(incompleteConfig);

      // Act & Assert
      await expect(service.checkRequiredEnvironmentVariables()).rejects.toThrow(
        'Required environment variables check failed: Missing required environment variables: DATABASE_USERNAME, DATABASE_PASSWORD'
      );
    });

    it('should handle configuration not available', async () => {
      // Arrange
      configService.get.mockReturnValue(null);

      // Act & Assert
      await expect(service.checkRequiredEnvironmentVariables()).rejects.toThrow(
        'Required environment variables check failed: Application configuration not available'
      );
    });

    it('should handle empty string values as missing', async () => {
      // Arrange
      const configWithEmptyStrings = {
        ...mockAppConfig,
        JWT_SECRET: '   ', // Whitespace only
        DATABASE_NAME: '', // Empty string
      };
      configService.get.mockReturnValue(configWithEmptyStrings);

      // Act & Assert
      await expect(service.checkRequiredEnvironmentVariables()).rejects.toThrow(
        'Missing required environment variables: JWT_SECRET, DATABASE_NAME'
      );
    });
  });

  describe('checkApplicationUptime', () => {
    it('should pass when uptime is sufficient', async () => {
      // Arrange
      // Wait a small amount to ensure uptime > 10 seconds threshold
      await new Promise(resolve => setTimeout(resolve, 10));

      // Act
      const result = await service.checkApplicationUptime();

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          application_uptime: expect.objectContaining({
            status: 'up',
            uptimeMs: expect.any(Number),
            uptimeSeconds: expect.any(Number),
            startTime: expect.any(String),
            currentTime: expect.any(String),
          }),
        })
      );
    });

    it('should fail when uptime is too low', async () => {
      // Arrange
      // Create a new service instance to reset start time
      const newService = new (HealthService as any)(configService);
      // Mock the startTime to be very recent
      (newService as any).startTime = Date.now() - 5000; // 5 seconds ago

      // Act & Assert
      await expect(newService.checkApplicationUptime()).rejects.toThrow(
        'Application uptime check failed: Application uptime too low: 5 seconds'
      );
    });

    it('should include uptime information in result', async () => {
      // Act
      const result = await service.checkApplicationUptime();

      // Assert
      expect(result.application_uptime).toHaveProperty('uptimeMs');
      expect(result.application_uptime).toHaveProperty('uptimeSeconds');
      expect(result.application_uptime).toHaveProperty('startTime');
      expect(result.application_uptime).toHaveProperty('currentTime');
      expect(typeof result.application_uptime.uptimeMs).toBe('number');
      expect(typeof result.application_uptime.uptimeSeconds).toBe('number');
    });
  });

  describe('getApplicationInfo', () => {
    it('should return comprehensive application information', () => {
      // Act
      const result = service.getApplicationInfo();

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          name: 'Auth Service',
          version: '1.0.0',
          description: 'NestJS Authentication Service',
          environment: 'test',
          uptime: expect.any(Number),
          uptimeMs: expect.any(Number),
          startTime: expect.any(String),
          timestamp: expect.any(String),
          nodeVersion: expect.any(String),
          platform: expect.any(String),
          architecture: expect.any(String),
          pid: expect.any(Number),
          memoryUsage: expect.any(Object),
          cpuUsage: expect.any(Object),
          versions: expect.any(Object),
          env: expect.objectContaining({
            nodeEnv: expect.any(String),
            port: 3000,
            apiPrefix: 'api/v1',
          }),
          database: expect.objectContaining({
            type: 'postgres',
            host: 'localhost',
            port: 5432,
            name: 'test_db',
          }),
          security: expect.objectContaining({
            corsEnabled: true,
            helmetEnabled: true,
            rateLimitingEnabled: true,
            mtlsEnabled: false,
          }),
          monitoring: expect.objectContaining({
            healthCheckEnabled: true,
            metricsEnabled: true,
            healthCheckPath: '/health',
            metricsPath: '/metrics',
          }),
        })
      );
    });

    it('should use default values when config is missing', () => {
      // Arrange
      configService.get.mockReturnValue(null);

      // Act
      const result = service.getApplicationInfo();

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          name: 'Auth Service',
          version: '1.0.0',
          description: 'NestJS Authentication Service',
          environment: 'development',
        })
      );
    });

    it('should include process information', () => {
      // Act
      const result = service.getApplicationInfo();

      // Assert
      expect(result.nodeVersion).toBe(process.version);
      expect(result.platform).toBe(process.platform);
      expect(result.architecture).toBe(process.arch);
      expect(result.pid).toBe(process.pid);
      expect(result.memoryUsage).toEqual(process.memoryUsage());
      expect(result.versions).toBe(process.versions);
    });
  });

  describe('getHealthStatus', () => {
    it('should return simple health status', () => {
      // Act
      const result = service.getHealthStatus();

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          status: 'healthy',
          timestamp: expect.any(String),
          uptime: expect.any(Number),
          memory: expect.objectContaining({
            heapUsed: expect.any(Number),
            heapTotal: expect.any(Number),
            rss: expect.any(Number),
            external: expect.any(Number),
            arrayBuffers: expect.any(Number),
          }),
          system: expect.objectContaining({
            platform: process.platform,
            arch: process.arch,
            nodeVersion: process.version,
            pid: process.pid,
          }),
        })
      );
    });

    it('should include current memory usage', () => {
      // Act
      const result = service.getHealthStatus();

      // Assert
      const currentMemory = process.memoryUsage();
      expect(result.memory.heapUsed).toBe(currentMemory.heapUsed);
      expect(result.memory.heapTotal).toBe(currentMemory.heapTotal);
      expect(result.memory.rss).toBe(currentMemory.rss);
    });

    it('should always return healthy status', () => {
      // Act
      const result = service.getHealthStatus();

      // Assert
      expect(result.status).toBe('healthy');
    });
  });

  describe('error handling', () => {
    it('should handle configuration service errors in JWT check', async () => {
      // Arrange
      configService.get.mockImplementation(() => {
        throw new Error('Configuration service error');
      });

      // Act & Assert
      await expect(service.checkJWTConfiguration()).rejects.toThrow(
        'JWT configuration is unhealthy: Configuration service error'
      );
    });

    it('should handle configuration service errors in environment check', async () => {
      // Arrange
      configService.get.mockImplementation(() => {
        throw new Error('Configuration service error');
      });

      // Act & Assert
      await expect(service.checkRequiredEnvironmentVariables()).rejects.toThrow(
        'Required environment variables check failed: Configuration service error'
      );
    });
  });
});