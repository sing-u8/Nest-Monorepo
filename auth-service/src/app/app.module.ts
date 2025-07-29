import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from '@auth/infrastructure';
import { appConfig } from '@auth/infrastructure';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { HealthModule } from './health/health.module';

/**
 * Main Application Module
 * 
 * Root module that imports and configures all feature modules.
 * Follows NestJS module composition patterns for clean architecture.
 */
@Module({
  imports: [
    // Global configuration module
    ConfigModule.forRoot({
      isGlobal: true,
      load: [appConfig],
      envFilePath: [
        '.env.local',
        '.env',
        `.env.${process.env.NODE_ENV}`,
      ],
      expandVariables: true,
      validationSchema: null, // Validation is handled by AppConfig class
    }),

    // Authentication module (includes all auth features)
    AuthModule,

    // Health check module
    HealthModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
