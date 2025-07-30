import { DataSource } from 'typeorm';
import { config } from 'dotenv';
import { join } from 'path';

// Load environment variables
config();

/**
 * TypeORM CLI Configuration
 * 
 * This file is used by TypeORM CLI for migrations, schema generation,
 * and other database operations. It uses the same configuration as
 * the application but with file paths suitable for CLI operations.
 */
export default new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USERNAME || 'auth_service',
  password: process.env.DB_PASSWORD || 'password',
  database: process.env.DB_NAME || 'auth_service_db',
  
  // Entity paths for CLI (compiled JavaScript files)
  entities: [
    join(__dirname, 'dist', 'infrastructure', 'database', 'entities', '*.orm-entity.js'),
  ],
  
  // Migration paths for CLI
  migrations: [
    join(__dirname, 'src', 'infrastructure', 'database', 'migrations', '*.ts'),
  ],
  
  // Migration table name
  migrationsTableName: 'typeorm_migrations',
  
  // CLI specific settings
  synchronize: false, // Always false for production safety
  logging: process.env.NODE_ENV === 'development' ? ['query', 'error'] : ['error'],
  logger: 'advanced-console',
  
  // SSL configuration
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false,
  } : false,
  
  // Connection settings
  connectTimeoutMS: 10000,
  timezone: 'UTC',
  
  // CLI output directory
  cli: {
    migrationsDir: 'src/infrastructure/database/migrations',
    entitiesDir: 'src/infrastructure/database/entities',
  },
});