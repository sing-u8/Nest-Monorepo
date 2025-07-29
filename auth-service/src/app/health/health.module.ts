import { Module } from '@nestjs/common';
import { TerminusModule } from '@nestjs/terminus';
import { HttpModule } from '@nestjs/axios';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';

/**
 * Health Check Module
 * 
 * Provides comprehensive health checking capabilities including:
 * - Database connectivity
 * - External service dependencies
 * - Memory and disk usage
 * - Application metrics
 */
@Module({
  imports: [
    TerminusModule,
    HttpModule,
  ],
  controllers: [HealthController],
  providers: [HealthService],
  exports: [HealthService],
})
export class HealthModule {}