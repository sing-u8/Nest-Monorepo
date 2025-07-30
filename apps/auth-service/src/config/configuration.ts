import { registerAs } from '@nestjs/config';
import * as Joi from 'joi';

/**
 * Application Configuration Schema
 * 
 * Defines all configuration settings with validation and defaults
 * for the authentication service application.
 */

/**
 * Environment validation schema
 */
export const configValidationSchema = Joi.object({
  // Application
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().default(3000),
  API_PREFIX: Joi.string().default('api'),
  
  // Database
  DB_HOST: Joi.string().default('localhost'),
  DB_PORT: Joi.number().default(5432),
  DB_USERNAME: Joi.string().default('auth_service'),
  DB_PASSWORD: Joi.string().default('password'),
  DB_NAME: Joi.string().default('auth_service_db'),
  DB_POOL_MAX: Joi.number().default(20),
  DB_POOL_MIN: Joi.number().default(5),
  
  // JWT Configuration
  JWT_ACCESS_SECRET: Joi.string().required(),
  JWT_REFRESH_SECRET: Joi.string().required(),
  JWT_ACCESS_EXPIRES_IN: Joi.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: Joi.string().default('7d'),
  
  // OAuth Configuration
  GOOGLE_CLIENT_ID: Joi.string().required(),
  GOOGLE_CLIENT_SECRET: Joi.string().required(),
  GOOGLE_REDIRECT_URI: Joi.string().required(),
  
  APPLE_CLIENT_ID: Joi.string().required(),
  APPLE_TEAM_ID: Joi.string().required(),
  APPLE_KEY_ID: Joi.string().required(),
  APPLE_PRIVATE_KEY: Joi.string().required(),
  APPLE_REDIRECT_URI: Joi.string().required(),
  
  // Security Configuration
  BCRYPT_SALT_ROUNDS: Joi.number().default(12),
  SESSION_SECRET: Joi.string().required(),
  
  // Rate Limiting
  RATE_LIMIT_GLOBAL_TTL: Joi.number().default(60000),
  RATE_LIMIT_GLOBAL_LIMIT: Joi.number().default(100),
  RATE_LIMIT_AUTH_TTL: Joi.number().default(60000),
  RATE_LIMIT_AUTH_LIMIT: Joi.number().default(10),
  RATE_LIMIT_LOGIN_TTL: Joi.number().default(300000),
  RATE_LIMIT_LOGIN_LIMIT: Joi.number().default(5),
  
  // CORS Configuration
  CORS_ALLOWED_ORIGINS: Joi.string().default('http://localhost:3000,http://localhost:3001'),
  CORS_ALLOWED_PATTERNS: Joi.string().default(''),
  
  // Audit Configuration
  AUDIT_ENABLED: Joi.boolean().default(true),
  AUDIT_LEVEL: Joi.string().valid('minimal', 'standard', 'detailed').default('standard'),
  
  // mTLS Configuration
  MTLS_ENABLED: Joi.boolean().default(false),
  MTLS_REQUIRE_CLIENT_CERT: Joi.boolean().default(false),
  MTLS_TRUSTED_CAS: Joi.string().default(''),
  MTLS_ALLOWED_SUBJECTS: Joi.string().default(''),
});

/**
 * Application configuration
 */
export const appConfig = registerAs('app', () => ({
  nodeEnv: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '3000', 10),
  apiPrefix: process.env.API_PREFIX || 'api',
  isDevelopment: process.env.NODE_ENV === 'development',
  isProduction: process.env.NODE_ENV === 'production',
  isTest: process.env.NODE_ENV === 'test',
}));

/**
 * Database configuration
 */
export const databaseConfig = registerAs('database', () => ({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USERNAME || 'auth_service',
  password: process.env.DB_PASSWORD || 'password',
  database: process.env.DB_NAME || 'auth_service_db',
  pool: {
    max: parseInt(process.env.DB_POOL_MAX || '20', 10),
    min: parseInt(process.env.DB_POOL_MIN || '5', 10),
    acquire: parseInt(process.env.DB_POOL_ACQUIRE_TIMEOUT || '30000', 10),
    idle: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || '10000', 10),
  },
}));

/**
 * JWT configuration
 */
export const jwtConfig = registerAs('jwt', () => ({
  accessToken: {
    secret: process.env.JWT_ACCESS_SECRET,
    expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
  },
  refreshToken: {
    secret: process.env.JWT_REFRESH_SECRET,
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  },
}));

/**
 * OAuth configuration
 */
export const oauthConfig = registerAs('oauth', () => ({
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    redirectUri: process.env.GOOGLE_REDIRECT_URI,
    scope: ['openid', 'profile', 'email'],
  },
  apple: {
    clientId: process.env.APPLE_CLIENT_ID,
    teamId: process.env.APPLE_TEAM_ID,
    keyId: process.env.APPLE_KEY_ID,
    privateKey: process.env.APPLE_PRIVATE_KEY,
    redirectUri: process.env.APPLE_REDIRECT_URI,
    scope: ['name', 'email'],
  },
}));

/**
 * Security configuration
 */
export const securityConfig = registerAs('security', () => ({
  bcrypt: {
    saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10),
  },
  session: {
    secret: process.env.SESSION_SECRET,
  },
  rateLimit: {
    global: {
      ttl: parseInt(process.env.RATE_LIMIT_GLOBAL_TTL || '60000', 10),
      limit: parseInt(process.env.RATE_LIMIT_GLOBAL_LIMIT || '100', 10),
    },
    auth: {
      ttl: parseInt(process.env.RATE_LIMIT_AUTH_TTL || '60000', 10),
      limit: parseInt(process.env.RATE_LIMIT_AUTH_LIMIT || '10', 10),
    },
    login: {
      ttl: parseInt(process.env.RATE_LIMIT_LOGIN_TTL || '300000', 10),
      limit: parseInt(process.env.RATE_LIMIT_LOGIN_LIMIT || '5', 10),
    },
    storage: 'memory',
  },
  cors: {
    allowedOrigins: (process.env.CORS_ALLOWED_ORIGINS || '').split(',').filter(Boolean),
    allowedPatterns: (process.env.CORS_ALLOWED_PATTERNS || '').split(',').filter(Boolean),
  },
  redirectUrls: {
    allowedDomains: ['localhost', 'example.com'],
  },
  audit: {
    enabled: process.env.AUDIT_ENABLED === 'true',
    level: process.env.AUDIT_LEVEL || 'standard',
  },
  mtls: {
    enabled: process.env.MTLS_ENABLED === 'true',
    requireClientCert: process.env.MTLS_REQUIRE_CLIENT_CERT === 'true',
    trustedCAs: (process.env.MTLS_TRUSTED_CAS || '').split(',').filter(Boolean),
    allowedSubjects: (process.env.MTLS_ALLOWED_SUBJECTS || '').split(',').filter(Boolean),
  },
}));

/**
 * All configuration exports
 */
export const configurations = [
  appConfig,
  databaseConfig,
  jwtConfig,
  oauthConfig,
  securityConfig,
];

/**
 * Configuration type definitions
 */
export type AppConfig = ReturnType<typeof appConfig>;
export type DatabaseConfig = ReturnType<typeof databaseConfig>;
export type JwtConfig = ReturnType<typeof jwtConfig>;
export type OAuthConfig = ReturnType<typeof oauthConfig>;
export type SecurityConfig = ReturnType<typeof securityConfig>;