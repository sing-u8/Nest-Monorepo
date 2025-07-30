import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';

// Configuration
import { databaseConfig } from './database.config';

// ORM Entities
import { UserOrmEntity } from './entities/user.orm-entity';
import { TokenOrmEntity } from './entities/token.orm-entity';
import { AuthSessionOrmEntity } from './entities/auth-session.orm-entity';

// Repository Implementations
import { UserRepositoryImpl } from '../repositories/user.repository.impl';
import { TokenRepositoryImpl } from '../repositories/token.repository.impl';
import { AuthSessionRepositoryImpl } from '../repositories/auth-session.repository.impl';

// Repository Ports
import { UserRepository } from '../../domain/ports/user.repository';
import { TokenRepository } from '../../domain/ports/token.repository';
import { AuthSessionRepository } from '../../domain/ports/auth-session.repository';

// Health Check
import { DatabaseHealthIndicator } from './database.health';

@Module({
  imports: [
    // TypeORM configuration
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        return configService.get('database');
      },
    }),
    
    // Feature repositories
    TypeOrmModule.forFeature([
      UserOrmEntity,
      TokenOrmEntity,
      AuthSessionOrmEntity,
    ]),
  ],
  providers: [
    // Repository implementations
    {
      provide: UserRepository,
      useClass: UserRepositoryImpl,
    },
    {
      provide: TokenRepository,
      useClass: TokenRepositoryImpl,
    },
    {
      provide: AuthSessionRepository,
      useClass: AuthSessionRepositoryImpl,
    },
    
    // Health check
    DatabaseHealthIndicator,
  ],
  exports: [
    // Export repository abstractions
    UserRepository,
    TokenRepository,
    AuthSessionRepository,
    
    // Export TypeORM repositories for advanced use cases
    TypeOrmModule,
    
    // Export health indicator
    DatabaseHealthIndicator,
  ],
})
export class DatabaseModule {}