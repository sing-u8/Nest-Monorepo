import { registerAs } from '@nestjs/config';
import { plainToInstance, Transform } from 'class-transformer';
import { IsString, IsNumber, IsBoolean, IsEnum, IsOptional, validateSync, IsUrl, Min, Max } from 'class-validator';

/**
 * Application Environment Types
 */
export enum Environment {
  DEVELOPMENT = 'development',
  STAGING = 'staging',
  PRODUCTION = 'production',
  TEST = 'test',
}

/**
 * Application Configuration Schema
 * 
 * Validates all application settings with proper types and constraints.
 * Uses class-validator for runtime validation.
 */
export class AppConfig {
  // Application Settings
  @IsEnum(Environment)
  NODE_ENV: Environment = Environment.DEVELOPMENT;

  @IsNumber()
  @Min(1000)
  @Max(65535)
  @Transform(({ value }) => parseInt(value, 10))
  PORT: number = 3000;

  @IsString()
  APP_NAME: string = 'Auth Service';

  @IsString()
  @IsOptional()
  APP_VERSION?: string;

  @IsString()
  @IsOptional()
  APP_DESCRIPTION?: string;

  // API Configuration
  @IsString()
  API_PREFIX: string = 'api/v1';

  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  API_ENABLE_CORS: boolean = true;

  @IsString()
  @IsOptional()
  API_CORS_ORIGIN?: string;

  // Security Settings
  @IsString()
  JWT_SECRET: string;

  @IsString()
  JWT_REFRESH_SECRET: string;

  @IsString()
  @IsOptional()
  JWT_ISSUER?: string = 'auth-service';

  @IsString()
  @IsOptional()
  JWT_AUDIENCE?: string = 'auth-service-users';

  @IsString()
  JWT_ACCESS_TOKEN_EXPIRATION: string = '15m';

  @IsString()
  JWT_REFRESH_TOKEN_EXPIRATION: string = '7d';

  // Database Configuration
  @IsString()
  DATABASE_TYPE: string = 'postgres';

  @IsString()
  DATABASE_HOST: string = 'localhost';

  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10))
  DATABASE_PORT: number = 5432;

  @IsString()
  DATABASE_USERNAME: string;

  @IsString()
  DATABASE_PASSWORD: string;

  @IsString()
  DATABASE_NAME: string;

  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  DATABASE_SYNCHRONIZE: boolean = false;

  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  DATABASE_LOGGING: boolean = false;

  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10))
  @IsOptional()
  DATABASE_MAX_CONNECTIONS?: number = 10;

  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10))
  @IsOptional()
  DATABASE_CONNECTION_TIMEOUT?: number = 30000;

  // OAuth Configuration
  @IsString()
  @IsOptional()
  GOOGLE_CLIENT_ID?: string;

  @IsString()
  @IsOptional()
  GOOGLE_CLIENT_SECRET?: string;

  @IsUrl()
  @IsOptional()
  GOOGLE_CALLBACK_URL?: string;

  @IsString()
  @IsOptional()
  APPLE_CLIENT_ID?: string;

  @IsString()
  @IsOptional()
  APPLE_TEAM_ID?: string;

  @IsString()
  @IsOptional()
  APPLE_KEY_ID?: string;

  @IsString()
  @IsOptional()
  APPLE_PRIVATE_KEY?: string;

  @IsUrl()
  @IsOptional()
  APPLE_CALLBACK_URL?: string;

  // Email Configuration (for future email features)
  @IsString()
  @IsOptional()
  SMTP_HOST?: string;

  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10))
  @IsOptional()
  SMTP_PORT?: number;

  @IsString()
  @IsOptional()
  SMTP_USERNAME?: string;

  @IsString()
  @IsOptional()
  SMTP_PASSWORD?: string;

  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  @IsOptional()
  SMTP_SECURE?: boolean = true;

  // Redis Configuration (for future caching features)
  @IsString()
  @IsOptional()
  REDIS_HOST?: string = 'localhost';

  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10))
  @IsOptional()
  REDIS_PORT?: number = 6379;

  @IsString()
  @IsOptional()
  REDIS_PASSWORD?: string;

  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10))
  @IsOptional()
  REDIS_DB?: number = 0;

  // Logging Configuration
  @IsString()
  LOG_LEVEL: string = 'info';

  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  LOG_ENABLE_CONSOLE: boolean = true;

  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  LOG_ENABLE_FILE: boolean = false;

  @IsString()
  @IsOptional()
  LOG_FILE_PATH?: string;

  // Security Configuration
  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  SECURITY_ENABLE_RATE_LIMITING: boolean = true;

  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  SECURITY_ENABLE_HELMET: boolean = true;

  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  SECURITY_ENABLE_MTLS: boolean = false;

  @IsString()
  @IsOptional()
  SECURITY_MTLS_CA_PATH?: string;

  @IsString()
  @IsOptional()
  SECURITY_MTLS_CERT_PATH?: string;

  @IsString()
  @IsOptional()
  SECURITY_MTLS_KEY_PATH?: string;

  // Monitoring Configuration
  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  MONITORING_ENABLE_METRICS: boolean = false;

  @IsString()
  @IsOptional()
  MONITORING_METRICS_PATH?: string = '/metrics';

  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  MONITORING_ENABLE_HEALTH_CHECK: boolean = true;

  @IsString()
  @IsOptional()
  MONITORING_HEALTH_CHECK_PATH?: string = '/health';
}

/**
 * Validate configuration and throw descriptive errors
 */
function validateConfig(config: Record<string, unknown>): AppConfig {
  const validatedConfig = plainToInstance(AppConfig, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
    forbidUnknownValues: true,
    whitelist: true,
  });

  if (errors.length > 0) {
    const errorMessages = errors.map(error => {
      const constraints = error.constraints;
      const property = error.property;
      const constraintMessages = constraints ? Object.values(constraints) : ['Unknown validation error'];
      return `${property}: ${constraintMessages.join(', ')}`;
    });

    throw new Error(`Configuration validation failed:\n${errorMessages.join('\n')}`);
  }

  return validatedConfig;
}

/**
 * Configuration factory for NestJS ConfigModule
 */
export const appConfig = registerAs('app', (): AppConfig => {
  return validateConfig(process.env);
});

/**
 * Get validated configuration instance
 */
export function getAppConfig(): AppConfig {
  return validateConfig(process.env);
}

/**
 * Environment-specific configuration presets
 */
export const environmentPresets = {
  development: {
    DATABASE_SYNCHRONIZE: true,
    DATABASE_LOGGING: true,
    LOG_LEVEL: 'debug',
    LOG_ENABLE_CONSOLE: true,
    LOG_ENABLE_FILE: false,
    API_ENABLE_CORS: true,
    SECURITY_ENABLE_RATE_LIMITING: false, // Disabled for development ease
    SECURITY_ENABLE_HELMET: true,
    MONITORING_ENABLE_METRICS: false,
    MONITORING_ENABLE_HEALTH_CHECK: true,
  },
  staging: {
    DATABASE_SYNCHRONIZE: false,
    DATABASE_LOGGING: false,
    LOG_LEVEL: 'info',
    LOG_ENABLE_CONSOLE: true,
    LOG_ENABLE_FILE: true,
    API_ENABLE_CORS: true, // Allow CORS for staging testing
    SECURITY_ENABLE_RATE_LIMITING: true,
    SECURITY_ENABLE_HELMET: true,
    MONITORING_ENABLE_METRICS: true,
    MONITORING_ENABLE_HEALTH_CHECK: true,
  },
  production: {
    DATABASE_SYNCHRONIZE: false,
    DATABASE_LOGGING: false,
    LOG_LEVEL: 'warn',
    LOG_ENABLE_CONSOLE: false,
    LOG_ENABLE_FILE: true,
    API_ENABLE_CORS: false, // Restrict CORS in production
    SECURITY_ENABLE_RATE_LIMITING: true,
    SECURITY_ENABLE_HELMET: true,
    SECURITY_ENABLE_MTLS: true, // Enable mTLS in production
    MONITORING_ENABLE_METRICS: true,
    MONITORING_ENABLE_HEALTH_CHECK: true,
  },
  test: {
    DATABASE_SYNCHRONIZE: true,
    DATABASE_LOGGING: false,
    LOG_LEVEL: 'error',
    LOG_ENABLE_CONSOLE: false,
    LOG_ENABLE_FILE: false,
    API_ENABLE_CORS: true,
    SECURITY_ENABLE_RATE_LIMITING: false, // Disabled for faster testing
    SECURITY_ENABLE_HELMET: false,
    MONITORING_ENABLE_METRICS: false,
    MONITORING_ENABLE_HEALTH_CHECK: false,
  },
};

/**
 * Get environment-specific preset configuration
 */
export function getEnvironmentPreset(env: Environment): Partial<AppConfig> {
  return environmentPresets[env] || environmentPresets.development;
}