import { registerAs } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { DataSource, DataSourceOptions } from 'typeorm';

// Import all ORM entities
import { UserOrmEntity } from './entities/user.orm-entity';
import { TokenOrmEntity } from './entities/token.orm-entity';
import { AuthSessionOrmEntity } from './entities/auth-session.orm-entity';

/**
 * Database configuration factory
 */
export const databaseConfig = registerAs('database', (): TypeOrmModuleOptions => {
  const baseConfig: TypeOrmModuleOptions = {
    type: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME || 'auth_service',
    password: process.env.DB_PASSWORD || 'password',
    database: process.env.DB_NAME || 'auth_service_db',
    
    // Entity registration
    entities: [UserOrmEntity, TokenOrmEntity, AuthSessionOrmEntity],
    
    // Migration configuration
    migrations: ['dist/infrastructure/database/migrations/*.js'],
    migrationsTableName: 'typeorm_migrations',
    migrationsRun: process.env.NODE_ENV === 'production',
    
    // Connection pool configuration
    extra: {
      max: parseInt(process.env.DB_POOL_MAX || '20', 10),
      min: parseInt(process.env.DB_POOL_MIN || '5', 10),
      acquire: parseInt(process.env.DB_POOL_ACQUIRE_TIMEOUT || '30000', 10),
      idle: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || '10000', 10),
      evict: parseInt(process.env.DB_POOL_EVICT_TIMEOUT || '60000', 10),
      handleDisconnects: true,
    },
    
    // Performance and logging
    logging: process.env.NODE_ENV === 'development' ? ['query', 'error'] : ['error'],
    logger: 'advanced-console',
    maxQueryExecutionTime: 1000, // Log slow queries
    
    // Connection options
    connectTimeoutMS: 10000,
    acquireTimeoutMillis: 10000,
    timeout: 10000,
    
    // Development/Test specific settings
    synchronize: process.env.NODE_ENV === 'test', // Only for testing
    dropSchema: process.env.NODE_ENV === 'test',
    
    // SSL configuration for production
    ssl: process.env.NODE_ENV === 'production' ? {
      rejectUnauthorized: false,
    } : false,
    
    // Timezone settings
    timezone: 'UTC',
    
    // Additional options
    cache: {
      duration: 30000, // 30 seconds cache
      type: 'database',
      tableName: 'typeorm_cache',
    },
  };

  return baseConfig;
});

/**
 * TypeORM CLI configuration
 * Used for generating migrations
 */
export const typeOrmCliConfig: DataSourceOptions = {
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USERNAME || 'auth_service',
  password: process.env.DB_PASSWORD || 'password',
  database: process.env.DB_NAME || 'auth_service_db',
  
  entities: ['src/infrastructure/database/entities/*.orm-entity.ts'],
  migrations: ['src/infrastructure/database/migrations/*.ts'],
  migrationsTableName: 'typeorm_migrations',
  
  synchronize: false,
  logging: false,
};

/**
 * Data source for TypeORM CLI
 */
export const AppDataSource = new DataSource(typeOrmCliConfig);