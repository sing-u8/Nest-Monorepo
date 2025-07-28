import { Module, Global } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { getDatabaseConfig } from '../config/database.config';
import { UserEntity } from './entities/user.entity';
import { TokenEntity } from './entities/token.entity';
import { AuthSessionEntity } from './entities/auth-session.entity';
import { DatabaseHealthService } from './health/database-health.service';
import { DatabaseHealthController } from './health/database-health.controller';

/**
 * Database Module
 * 
 * Configures TypeORM connection with proper connection pooling,
 * health checks, and environment-specific settings.
 * Global module that can be imported anywhere in the application.
 */
@Global()
@Module({
  imports: [
    ConfigModule,
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        // Get database configuration with environment variables
        const dbConfig = getDatabaseConfig();
        
        // Override with ConfigService values if available
        return {
          ...dbConfig,
          host: configService.get<string>('DB_HOST', dbConfig.host as string),
          port: configService.get<number>('DB_PORT', dbConfig.port as number),
          username: configService.get<string>('DB_USERNAME', dbConfig.username as string),
          password: configService.get<string>('DB_PASSWORD', dbConfig.password as string),
          database: configService.get<string>('DB_DATABASE', dbConfig.database as string),
          
          // Connection pool configuration
          extra: {
            ...dbConfig.extra,
            max: configService.get<number>('DB_POOL_MAX', 20),
            min: configService.get<number>('DB_POOL_MIN', 5),
            acquire: configService.get<number>('DB_POOL_ACQUIRE_TIMEOUT', 30000),
            idle: configService.get<number>('DB_POOL_IDLE_TIMEOUT', 10000),
            evict: configService.get<number>('DB_POOL_EVICT_TIMEOUT', 60000),
            
            // Additional PostgreSQL-specific settings
            application_name: 'auth-service',
            statement_timeout: configService.get<number>('DB_STATEMENT_TIMEOUT', 30000),
            query_timeout: configService.get<number>('DB_QUERY_TIMEOUT', 10000),
            connectionTimeoutMillis: configService.get<number>('DB_CONNECTION_TIMEOUT', 5000),
            
            // Connection retry settings
            retries: configService.get<number>('DB_RETRY_ATTEMPTS', 3),
            retryDelay: configService.get<number>('DB_RETRY_DELAY', 3000),
          },
          
          // SSL configuration
          ssl: configService.get<boolean>('DB_SSL', false) ? {
            rejectUnauthorized: configService.get<boolean>('DB_SSL_REJECT_UNAUTHORIZED', true),
            ca: configService.get<string>('DB_SSL_CA'),
            cert: configService.get<string>('DB_SSL_CERT'),
            key: configService.get<string>('DB_SSL_KEY'),
          } : false,
          
          // Enhanced logging configuration
          logging: configService.get<string>('NODE_ENV') === 'development' 
            ? ['query', 'error', 'warn', 'info', 'log', 'migration'] 
            : ['error', 'warn'],
          
          // Migration configuration
          migrationsRun: configService.get<boolean>('DB_RUN_MIGRATIONS', false),
          migrationsTransactionMode: 'each',
          
          // Performance optimizations
          maxQueryExecutionTime: configService.get<number>('DB_SLOW_QUERY_THRESHOLD', 1000),
          
          // Connection monitoring
          dropSchema: configService.get<boolean>('DB_DROP_SCHEMA', false),
          synchronize: configService.get<boolean>('DB_SYNCHRONIZE', false),
          
          // Cache configuration
          cache: configService.get<boolean>('DB_ENABLE_CACHE', false) ? {
            type: 'redis',
            options: {
              host: configService.get<string>('REDIS_HOST', 'localhost'),
              port: configService.get<number>('REDIS_PORT', 6379),
              password: configService.get<string>('REDIS_PASSWORD'),
              db: configService.get<number>('REDIS_DB', 0),
            },
            duration: configService.get<number>('DB_CACHE_DURATION', 30000),
          } : false,
        };
      },
      inject: [ConfigService],
    }),
    
    // Register entities for injection
    TypeOrmModule.forFeature([
      UserEntity,
      TokenEntity,
      AuthSessionEntity,
    ]),
  ],
  controllers: [
    DatabaseHealthController,
  ],
  providers: [
    DatabaseHealthService,
  ],
  exports: [
    TypeOrmModule,
    DatabaseHealthService,
  ],
})
export class DatabaseModule {
  constructor(private readonly databaseHealthService: DatabaseHealthService) {
    // Initialize health monitoring on module load
    this.initializeHealthMonitoring();
  }

  private async initializeHealthMonitoring(): Promise<void> {
    try {
      await this.databaseHealthService.checkHealth();
      console.log('✅ Database connection established successfully');
    } catch (error) {
      console.error('❌ Database connection failed:', error.message);
      
      // In production, you might want to implement retry logic here
      if (process.env['NODE_ENV'] === 'production') {
        // Could implement exponential backoff retry logic
        setTimeout(() => this.initializeHealthMonitoring(), 5000);
      }
    }
  }
}