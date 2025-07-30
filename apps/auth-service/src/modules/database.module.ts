import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TerminusModule } from '@nestjs/terminus';

// Database Configuration
import { databaseConfig } from '../infrastructure/database/database.config';

// ORM Entities
import { UserOrmEntity } from '../infrastructure/database/entities/user.orm-entity';
import { TokenOrmEntity } from '../infrastructure/database/entities/token.orm-entity';
import { AuthSessionOrmEntity } from '../infrastructure/database/entities/auth-session.orm-entity';

// Health Check
import { DatabaseHealthIndicator } from '../infrastructure/database/database.health';

/**
 * Database Module
 * 
 * Configures TypeORM with PostgreSQL and provides database-related services
 * including health checks and repository access.
 */
@Module({
  imports: [
    ConfigModule.forFeature(databaseConfig),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        const dbConfig = configService.get('database');
        return {
          type: 'postgres',
          host: dbConfig.host,
          port: dbConfig.port,
          username: dbConfig.username,
          password: dbConfig.password,
          database: dbConfig.database,
          
          // Entity registration
          entities: [UserOrmEntity, TokenOrmEntity, AuthSessionOrmEntity],
          
          // Migration configuration
          migrations: ['dist/infrastructure/database/migrations/*.js'],
          migrationsTableName: 'typeorm_migrations',
          migrationsRun: process.env.NODE_ENV === 'production',
          
          // Connection pool configuration
          extra: {
            max: dbConfig.pool.max,
            min: dbConfig.pool.min,
            acquire: dbConfig.pool.acquire,
            idle: dbConfig.pool.idle,
          },
          
          // Performance and logging
          logging: process.env.NODE_ENV === 'development' ? ['query', 'error'] : ['error'],
          logger: 'advanced-console',
          maxQueryExecutionTime: 1000,
          
          // Connection options
          connectTimeoutMS: 10000,
          acquireTimeoutMillis: 10000,
          timeout: 10000,
          
          // Development/Test specific settings
          synchronize: process.env.NODE_ENV === 'test',
          dropSchema: process.env.NODE_ENV === 'test',
          
          // SSL configuration for production
          ssl: process.env.NODE_ENV === 'production' ? {
            rejectUnauthorized: false,
          } : false,
          
          // Timezone settings
          timezone: 'UTC',
          
          // Cache configuration
          cache: {
            duration: 30000,
            type: 'database',
            tableName: 'typeorm_cache',
          },
        };
      },
      inject: [ConfigService],
    }),
    
    // Feature repositories for dependency injection
    TypeOrmModule.forFeature([
      UserOrmEntity,
      TokenOrmEntity,
      AuthSessionOrmEntity,
    ]),
    
    // Health check module
    TerminusModule,
  ],
  providers: [
    DatabaseHealthIndicator,
  ],
  exports: [
    TypeOrmModule,
    DatabaseHealthIndicator,
  ],
})
export class DatabaseModule {}