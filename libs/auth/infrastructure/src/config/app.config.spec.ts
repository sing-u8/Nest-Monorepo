import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { AppConfig, Environment, getAppConfig, getEnvironmentPreset, appConfig } from './app.config';

describe('AppConfig', () => {
  describe('AppConfig class validation', () => {
    it('should validate a valid configuration', async () => {
      const validConfig = {
        NODE_ENV: 'development',
        PORT: '3000',
        APP_NAME: 'Test App',
        JWT_SECRET: 'super-secret-jwt-key-for-testing',
        JWT_REFRESH_SECRET: 'super-secret-refresh-key-for-testing',
        DATABASE_HOST: 'localhost',
        DATABASE_PORT: '5432',
        DATABASE_USERNAME: 'test_user',
        DATABASE_PASSWORD: 'test_password',
        DATABASE_NAME: 'test_db',
      };

      const config = plainToInstance(AppConfig, validConfig, {
        enableImplicitConversion: true,
      });

      const errors = await validate(config);
      expect(errors).toHaveLength(0);
    });

    it('should reject invalid environment', async () => {
      const invalidConfig = {
        NODE_ENV: 'invalid-env',
        PORT: '3000',
        JWT_SECRET: 'secret',
        JWT_REFRESH_SECRET: 'refresh-secret',
        DATABASE_HOST: 'localhost',
        DATABASE_PORT: '5432',
        DATABASE_USERNAME: 'user',
        DATABASE_PASSWORD: 'password',
        DATABASE_NAME: 'db',
      };

      const config = plainToInstance(AppConfig, invalidConfig, {
        enableImplicitConversion: true,
      });

      const errors = await validate(config);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].property).toBe('NODE_ENV');
    });

    it('should reject invalid port numbers', async () => {
      const invalidConfigs = [
        { PORT: '0' },     // Too low
        { PORT: '65536' }, // Too high
        { PORT: 'abc' },   // Not a number
      ];

      for (const invalidConfig of invalidConfigs) {
        const config = plainToInstance(AppConfig, {
          NODE_ENV: 'development',
          JWT_SECRET: 'secret',
          JWT_REFRESH_SECRET: 'refresh-secret',
          DATABASE_HOST: 'localhost',
          DATABASE_PORT: '5432',
          DATABASE_USERNAME: 'user',
          DATABASE_PASSWORD: 'password',
          DATABASE_NAME: 'db',
          ...invalidConfig,
        }, {
          enableImplicitConversion: true,
        });

        const errors = await validate(config);
        expect(errors.length).toBeGreaterThan(0);
        
        const portError = errors.find(error => error.property === 'PORT');
        expect(portError).toBeDefined();
      }
    });

    it('should handle boolean transformations correctly', async () => {
      const config = plainToInstance(AppConfig, {
        NODE_ENV: 'development',
        PORT: '3000',
        JWT_SECRET: 'secret',
        JWT_REFRESH_SECRET: 'refresh-secret',
        DATABASE_HOST: 'localhost',
        DATABASE_PORT: '5432',
        DATABASE_USERNAME: 'user',
        DATABASE_PASSWORD: 'password',
        DATABASE_NAME: 'db',
        API_ENABLE_CORS: 'true',
        DATABASE_SYNCHRONIZE: 'false',
        LOG_ENABLE_CONSOLE: 'true',
        SECURITY_ENABLE_RATE_LIMITING: 'false',
      }, {
        enableImplicitConversion: true,
      });

      const errors = await validate(config);
      expect(errors).toHaveLength(0);

      expect(config.API_ENABLE_CORS).toBe(true);
      expect(config.DATABASE_SYNCHRONIZE).toBe(false);
      expect(config.LOG_ENABLE_CONSOLE).toBe(true);
      expect(config.SECURITY_ENABLE_RATE_LIMITING).toBe(false);
    });

    it('should apply default values when properties are not provided', async () => {
      const minimalConfig = {
        NODE_ENV: 'development',
        JWT_SECRET: 'secret',
        JWT_REFRESH_SECRET: 'refresh-secret',
        DATABASE_USERNAME: 'user',
        DATABASE_PASSWORD: 'password',
        DATABASE_NAME: 'db',
      };

      const config = plainToInstance(AppConfig, minimalConfig, {
        enableImplicitConversion: true,
      });

      const errors = await validate(config);
      expect(errors).toHaveLength(0);

      expect(config.PORT).toBe(3000);
      expect(config.APP_NAME).toBe('Auth Service');
      expect(config.API_PREFIX).toBe('api/v1');
      expect(config.DATABASE_HOST).toBe('localhost');
      expect(config.DATABASE_PORT).toBe(5432);
      expect(config.LOG_LEVEL).toBe('info');
    });

    it('should validate URL fields correctly', async () => {
      const configWithUrls = {
        NODE_ENV: 'development',
        PORT: '3000',
        JWT_SECRET: 'secret',
        JWT_REFRESH_SECRET: 'refresh-secret',
        DATABASE_HOST: 'localhost',
        DATABASE_PORT: '5432',
        DATABASE_USERNAME: 'user',
        DATABASE_PASSWORD: 'password',
        DATABASE_NAME: 'db',
        GOOGLE_CALLBACK_URL: 'https://example.com/callback',
        APPLE_CALLBACK_URL: 'https://example.com/apple-callback',
      };

      const config = plainToInstance(AppConfig, configWithUrls, {
        enableImplicitConversion: true,
      });

      const errors = await validate(config);
      expect(errors).toHaveLength(0);
    });

    it('should reject invalid URLs', async () => {
      const configWithInvalidUrl = {
        NODE_ENV: 'development',
        PORT: '3000',
        JWT_SECRET: 'secret',
        JWT_REFRESH_SECRET: 'refresh-secret',
        DATABASE_HOST: 'localhost',
        DATABASE_PORT: '5432',
        DATABASE_USERNAME: 'user',
        DATABASE_PASSWORD: 'password',
        DATABASE_NAME: 'db',
        GOOGLE_CALLBACK_URL: 'not-a-valid-url',
      };

      const config = plainToInstance(AppConfig, configWithInvalidUrl, {
        enableImplicitConversion: true,
      });

      const errors = await validate(config);
      expect(errors.length).toBeGreaterThan(0);
      
      const urlError = errors.find(error => error.property === 'GOOGLE_CALLBACK_URL');
      expect(urlError).toBeDefined();
    });
  });

  describe('getAppConfig function', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      // Clear environment variables
      process.env = {};
    });

    afterEach(() => {
      // Restore original environment
      process.env = originalEnv;
    });

    it('should return valid configuration with required environment variables', () => {
      process.env = {
        NODE_ENV: 'development',
        PORT: '3000',
        JWT_SECRET: 'super-secret-jwt-key',
        JWT_REFRESH_SECRET: 'super-secret-refresh-key',
        DATABASE_HOST: 'localhost',
        DATABASE_PORT: '5432',
        DATABASE_USERNAME: 'test_user',
        DATABASE_PASSWORD: 'test_password',
        DATABASE_NAME: 'test_db',
      };

      const config = getAppConfig();
      
      expect(config).toBeInstanceOf(AppConfig);
      expect(config.NODE_ENV).toBe(Environment.DEVELOPMENT);
      expect(config.PORT).toBe(3000);
      expect(config.JWT_SECRET).toBe('super-secret-jwt-key');
      expect(config.DATABASE_HOST).toBe('localhost');
    });

    it('should throw error when required environment variables are missing', () => {
      process.env = {
        NODE_ENV: 'development',
        // Missing required JWT_SECRET, JWT_REFRESH_SECRET, etc.
      };

      expect(() => getAppConfig()).toThrow(/Configuration validation failed/);
    });

    it('should throw error with descriptive messages for validation failures', () => {
      process.env = {
        NODE_ENV: 'invalid-environment',
        PORT: 'not-a-number',
        JWT_SECRET: 'secret',
      };

      expect(() => getAppConfig()).toThrow(/Configuration validation failed/);
    });
  });

  describe('getEnvironmentPreset function', () => {
    it('should return development preset for development environment', () => {
      const preset = getEnvironmentPreset(Environment.DEVELOPMENT);
      
      expect(preset.DATABASE_SYNCHRONIZE).toBe(true);
      expect(preset.DATABASE_LOGGING).toBe(true);
      expect(preset.LOG_LEVEL).toBe('debug');
      expect(preset.SECURITY_ENABLE_RATE_LIMITING).toBe(false);
    });

    it('should return production preset for production environment', () => {
      const preset = getEnvironmentPreset(Environment.PRODUCTION);
      
      expect(preset.DATABASE_SYNCHRONIZE).toBe(false);
      expect(preset.DATABASE_LOGGING).toBe(false);
      expect(preset.LOG_LEVEL).toBe('warn');
      expect(preset.SECURITY_ENABLE_RATE_LIMITING).toBe(true);
      expect(preset.SECURITY_ENABLE_MTLS).toBe(true);
    });

    it('should return staging preset for staging environment', () => {
      const preset = getEnvironmentPreset(Environment.STAGING);
      
      expect(preset.DATABASE_SYNCHRONIZE).toBe(false);
      expect(preset.LOG_LEVEL).toBe('info');
      expect(preset.LOG_ENABLE_FILE).toBe(true);
      expect(preset.SECURITY_ENABLE_RATE_LIMITING).toBe(true);
      expect(preset.MONITORING_ENABLE_METRICS).toBe(true);
    });

    it('should return test preset for test environment', () => {
      const preset = getEnvironmentPreset(Environment.TEST);
      
      expect(preset.DATABASE_SYNCHRONIZE).toBe(true);
      expect(preset.LOG_LEVEL).toBe('error');
      expect(preset.LOG_ENABLE_CONSOLE).toBe(false);
      expect(preset.SECURITY_ENABLE_RATE_LIMITING).toBe(false);
      expect(preset.SECURITY_ENABLE_HELMET).toBe(false);
    });

    it('should return development preset for unknown environment', () => {
      const preset = getEnvironmentPreset('unknown' as Environment);
      
      expect(preset).toEqual(getEnvironmentPreset(Environment.DEVELOPMENT));
    });
  });

  describe('appConfig factory', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = {};
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should create configuration factory for NestJS ConfigModule', () => {
      process.env = {
        NODE_ENV: 'development',
        PORT: '3000',
        JWT_SECRET: 'secret',
        JWT_REFRESH_SECRET: 'refresh-secret',
        DATABASE_HOST: 'localhost',
        DATABASE_PORT: '5432',
        DATABASE_USERNAME: 'user',
        DATABASE_PASSWORD: 'password',
        DATABASE_NAME: 'db',
      };

      const factory = appConfig();
      expect(factory).toBeInstanceOf(AppConfig);
      expect(factory.NODE_ENV).toBe(Environment.DEVELOPMENT);
    });
  });

  describe('Configuration environment variable integration', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = {};
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should override default values with environment variables', () => {
      process.env = {
        NODE_ENV: 'production',
        PORT: '8080',
        APP_NAME: 'Custom Auth Service',
        JWT_SECRET: 'production-secret',
        JWT_REFRESH_SECRET: 'production-refresh-secret',
        JWT_ISSUER: 'custom-issuer',
        JWT_AUDIENCE: 'custom-audience',
        DATABASE_HOST: 'prod-db-host',
        DATABASE_PORT: '5433',
        DATABASE_USERNAME: 'prod_user',
        DATABASE_PASSWORD: 'prod_password',
        DATABASE_NAME: 'prod_db',
        API_PREFIX: 'v2',
        LOG_LEVEL: 'error',
      };

      const config = getAppConfig();

      expect(config.NODE_ENV).toBe(Environment.PRODUCTION);
      expect(config.PORT).toBe(8080);
      expect(config.APP_NAME).toBe('Custom Auth Service');
      expect(config.JWT_SECRET).toBe('production-secret');
      expect(config.JWT_ISSUER).toBe('custom-issuer');
      expect(config.DATABASE_HOST).toBe('prod-db-host');
      expect(config.DATABASE_PORT).toBe(5433);
      expect(config.API_PREFIX).toBe('v2');
      expect(config.LOG_LEVEL).toBe('error');
    });

    it('should handle optional environment variables correctly', () => {
      process.env = {
        NODE_ENV: 'development',
        JWT_SECRET: 'secret',
        JWT_REFRESH_SECRET: 'refresh-secret',
        DATABASE_USERNAME: 'user',
        DATABASE_PASSWORD: 'password',
        DATABASE_NAME: 'db',
        // Optional variables
        APP_VERSION: '2.0.0',
        REDIS_HOST: 'custom-redis-host',
        SMTP_HOST: 'custom-smtp-host',
      };

      const config = getAppConfig();

      expect(config.APP_VERSION).toBe('2.0.0');
      expect(config.REDIS_HOST).toBe('custom-redis-host');
      expect(config.SMTP_HOST).toBe('custom-smtp-host');
      
      // Check that defaults are still applied for non-provided optionals
      expect(config.REDIS_PORT).toBe(6379);
      expect(config.REDIS_DB).toBe(0);
    });
  });
});