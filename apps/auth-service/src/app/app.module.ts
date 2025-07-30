import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD, APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { TerminusModule } from '@nestjs/terminus';

// Configuration
import { 
  configurations, 
  configValidationSchema 
} from '../config/configuration';

// Application modules
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from '../modules/auth.module';
import { DatabaseModule } from '../modules/database.module';

// Security module
import { SecurityModule } from '../infrastructure/security/security.module';

// Monitoring module
import { MonitoringModule } from '../infrastructure/monitoring/monitoring.module';

// Guards
import { RateLimitGuard } from '../infrastructure/security/rate-limit.guard';

// Health check controller
import { HealthController } from './health.controller';

/**
 * Application Root Module
 * 
 * Main module that orchestrates all application modules with proper
 * configuration, security, and dependency injection setup.
 */
@Module({
  imports: [
    // Global configuration with validation
    ConfigModule.forRoot({
      isGlobal: true,
      load: configurations,
      validationSchema: configValidationSchema,
      validationOptions: {
        allowUnknown: true,
        abortEarly: false,
      },
      envFilePath: [
        '.env.local',
        '.env.development',
        '.env.production',
        '.env',
      ],
      expandVariables: true,
    }),

    // Database module
    DatabaseModule,

    // Security module (includes rate limiting)
    SecurityModule,

    // Health checks
    TerminusModule.forRoot({
      errorLogStyle: 'pretty',
      gracefulShutdownTimeoutMs: 5000,
    }),

    // Authentication module (main business logic)
    AuthModule,

    // Monitoring module (health checks, metrics, alerting)
    MonitoringModule,
  ],
  controllers: [
    AppController,
    HealthController,
  ],
  providers: [
    AppService,
    
    // Global guards
    {
      provide: APP_GUARD,
      useClass: RateLimitGuard,
    },
  ],
})
export class AppModule {}
