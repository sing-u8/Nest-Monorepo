import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { HttpModule } from '@nestjs/axios';
import { TerminusModule } from '@nestjs/terminus';

// Health indicators
import { DatabaseHealthIndicator } from '../database/database.health';
import { ExternalServicesHealthIndicator } from '../health/external-services.health';

// Monitoring services
import { MetricsService } from './metrics.service';
import { PerformanceService } from './performance.service';
import { LoggingService } from './logging.service';
import { AlertingService } from './alerting.service';

/**
 * Monitoring Module
 * 
 * Provides comprehensive monitoring capabilities including
 * health checks, metrics collection, performance monitoring,
 * and structured logging.
 */
@Module({
  imports: [
    ConfigModule,
    HttpModule,
    TerminusModule,
  ],
  providers: [
    // Health indicators
    DatabaseHealthIndicator,
    ExternalServicesHealthIndicator,
    
    // Monitoring services
    MetricsService,
    PerformanceService,
    LoggingService,
    AlertingService,
  ],
  exports: [
    // Export health indicators for use in health controller
    DatabaseHealthIndicator,
    ExternalServicesHealthIndicator,
    
    // Export monitoring services for use throughout the application
    MetricsService,
    PerformanceService,
    LoggingService,
    AlertingService,
  ],
})
export class MonitoringModule {}