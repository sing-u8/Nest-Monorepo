import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { UserEntity } from '../database/entities/user.entity';
import { TokenEntity } from '../database/entities/token.entity';
import { AuthSessionEntity } from '../database/entities/auth-session.entity';

/**
 * Database Configuration for TypeORM
 * 
 * Provides database connection settings for different environments
 * with proper entity registration and migration support.
 */
export const getDatabaseConfig = (): TypeOrmModuleOptions => {
  const nodeEnv = process.env['NODE_ENV'] || 'development';
  
  const baseConfig: TypeOrmModuleOptions = {
    type: 'postgres',
    host: process.env['DB_HOST'] || 'localhost',
    port: parseInt(process.env['DB_PORT'] || '5432', 10),
    username: process.env['DB_USERNAME'] || 'postgres',
    password: process.env['DB_PASSWORD'] || 'postgres',
    database: process.env['DB_DATABASE'] || 'auth_service',
    entities: [UserEntity, TokenEntity, AuthSessionEntity],
    migrations: ['libs/auth/infrastructure/src/database/migrations/*.ts'],
    migrationsRun: false, // Don't run migrations automatically in production
    synchronize: false, // Never use synchronize in production
    logging: nodeEnv === 'development' ? ['query', 'error'] : ['error'],
    ssl: process.env['DB_SSL'] === 'true' ? {
      rejectUnauthorized: process.env['DB_SSL_REJECT_UNAUTHORIZED'] !== 'false'
    } : false,
    extra: {
      // Connection pool settings
      max: parseInt(process.env['DB_POOL_MAX'] || '10', 10),
      min: parseInt(process.env['DB_POOL_MIN'] || '1', 10),
      acquire: parseInt(process.env['DB_POOL_ACQUIRE_TIMEOUT'] || '30000', 10),
      idle: parseInt(process.env['DB_POOL_IDLE_TIMEOUT'] || '10000', 10),
    },
  };

  // Environment-specific configurations
  switch (nodeEnv) {
    case 'test':
      return {
        ...baseConfig,
        database: process.env['DB_TEST_DATABASE'] || 'auth_service_test',
        synchronize: true, // OK for tests
        logging: false,
        dropSchema: true, // Clean slate for each test run
      };

    case 'development':
      return {
        ...baseConfig,
        synchronize: process.env['DB_SYNC'] === 'true', // Only if explicitly enabled
        logging: ['query', 'error', 'warn', 'info'],
      };

    case 'production':
      return {
        ...baseConfig,
        logging: ['error'],
        ssl: {
          rejectUnauthorized: true, // Always validate SSL in production
        },
        extra: {
          ...baseConfig.extra,
          // Production-optimized connection pool
          max: parseInt(process.env['DB_POOL_MAX'] || '20', 10),
          min: parseInt(process.env['DB_POOL_MIN'] || '5', 10),
        },
      };

    default:
      return baseConfig;
  }
};

/**
 * TypeORM CLI Configuration
 * 
 * Used by TypeORM CLI for migration generation and running.
 * Should be exported as default for CLI usage.
 */
export default {
  type: 'postgres',
  host: process.env['DB_HOST'] || 'localhost',
  port: parseInt(process.env['DB_PORT'] || '5432', 10),
  username: process.env['DB_USERNAME'] || 'postgres',
  password: process.env['DB_PASSWORD'] || 'postgres',
  database: process.env['DB_DATABASE'] || 'auth_service',
  entities: ['libs/auth/infrastructure/src/database/entities/*.ts'],
  migrations: ['libs/auth/infrastructure/src/database/migrations/*.ts'],
  cli: {
    entitiesDir: 'libs/auth/infrastructure/src/database/entities',
    migrationsDir: 'libs/auth/infrastructure/src/database/migrations',
  },
  logging: ['query', 'error'],
  synchronize: false,
};