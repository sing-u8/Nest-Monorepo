import { DataSource } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { config } from 'dotenv';

// Load environment variables for CLI usage
config();

// Import all ORM entities
import { UserOrmEntity } from './entities/user.orm-entity';
import { TokenOrmEntity } from './entities/token.orm-entity';
import { AuthSessionOrmEntity } from './entities/auth-session.orm-entity';

/**
 * TypeORM CLI Data Source Configuration
 * 
 * This configuration is used by TypeORM CLI for:
 * - Generating migrations
 * - Running migrations
 * - Database schema operations
 */
export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USERNAME || 'auth_service',
  password: process.env.DB_PASSWORD || 'password',
  database: process.env.DB_NAME || 'auth_service_db',
  
  // Entity and migration paths for CLI
  entities: [
    UserOrmEntity,
    TokenOrmEntity,
    AuthSessionOrmEntity,
  ],
  
  // Migration configuration
  migrations: ['src/infrastructure/database/migrations/*.ts'],
  migrationsTableName: 'typeorm_migrations',
  
  // CLI specific settings
  synchronize: false, // Never use synchronize in production
  logging: process.env.NODE_ENV === 'development' ? ['query', 'error'] : ['error'],
  logger: 'advanced-console',
  
  // SSL configuration for production
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false,
  } : false,
  
  // Connection timeout
  connectTimeoutMS: 10000,
  
  // Timezone
  timezone: 'UTC',
});

/**
 * Initialize the data source for CLI operations
 * This is used by TypeORM CLI commands
 */
export default AppDataSource;