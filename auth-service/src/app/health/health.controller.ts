import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import {
  HealthCheckService,
  HealthCheck,
  TypeOrmHealthIndicator,
  MemoryHealthIndicator,
  DiskHealthIndicator,
} from '@nestjs/terminus';
import { HealthService } from './health.service';

/**
 * Health Check Controller
 * 
 * Provides endpoints for monitoring application health and status.
 * Used by load balancers, monitoring systems, and deployment tools.
 */
@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator,
    private memory: MemoryHealthIndicator,
    private disk: DiskHealthIndicator,
    private healthService: HealthService,
  ) {}

  /**
   * Basic health check endpoint
   * Returns simple status for quick health verification
   */
  @Get()
  @ApiOperation({ 
    summary: 'Basic health check',
    description: 'Quick health status check for load balancers and basic monitoring'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Application is healthy',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'ok' },
        info: {
          type: 'object',
          properties: {
            database: { type: 'object' },
            memory_heap: { type: 'object' },
            memory_rss: { type: 'object' },
          }
        },
        error: { type: 'object' },
        details: {
          type: 'object',
          properties: {
            database: { type: 'object' },
            memory_heap: { type: 'object' },
            memory_rss: { type: 'object' },
          }
        }
      }
    }
  })
  @ApiResponse({ 
    status: 503, 
    description: 'Application is unhealthy',
  })
  @HealthCheck()
  check() {
    return this.health.check([
      // Database connectivity check
      () => this.db.pingCheck('database'),
      
      // Memory usage checks
      () => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024), // 150MB
      () => this.memory.checkRSS('memory_rss', 300 * 1024 * 1024),   // 300MB
    ]);
  }

  /**
   * Detailed health check endpoint
   * Returns comprehensive health information for detailed monitoring
   */
  @Get('detailed')
  @ApiOperation({ 
    summary: 'Detailed health check',
    description: 'Comprehensive health check with detailed system information'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Detailed health information',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'ok' },
        info: { type: 'object' },
        error: { type: 'object' },
        details: { type: 'object' },
      }
    }
  })
  @HealthCheck()
  checkDetailed() {
    return this.health.check([
      // Database connectivity
      () => this.db.pingCheck('database'),
      
      // Memory checks with different thresholds
      () => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024), // 150MB
      () => this.memory.checkRSS('memory_rss', 300 * 1024 * 1024),   // 300MB
      
      // Disk space check (if available)
      () => this.disk.checkStorage('storage', { path: '/', thresholdPercent: 0.9 }),
      
      // Custom application-specific checks
      () => this.healthService.checkJWTConfiguration(),
      () => this.healthService.checkOAuthConfiguration(),
      () => this.healthService.checkRequiredEnvironmentVariables(),
    ]);
  }

  /**
   * Readiness probe endpoint
   * Indicates if the application is ready to serve traffic
   */
  @Get('ready')
  @ApiOperation({ 
    summary: 'Readiness probe',
    description: 'Kubernetes-style readiness probe to check if app is ready to serve traffic'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Application is ready to serve traffic',
  })
  @ApiResponse({ 
    status: 503, 
    description: 'Application is not ready to serve traffic',
  })
  @HealthCheck()
  checkReadiness() {
    return this.health.check([
      // Essential services that must be available for the app to be ready
      () => this.db.pingCheck('database'),
      () => this.healthService.checkJWTConfiguration(),
      () => this.healthService.checkRequiredEnvironmentVariables(),
    ]);
  }

  /**
   * Liveness probe endpoint
   * Indicates if the application is alive and should not be restarted
   */
  @Get('live')
  @ApiOperation({ 
    summary: 'Liveness probe',
    description: 'Kubernetes-style liveness probe to check if app is alive and functioning'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Application is alive and functioning',
  })
  @ApiResponse({ 
    status: 503, 
    description: 'Application should be restarted',
  })
  @HealthCheck()
  checkLiveness() {
    return this.health.check([
      // Basic checks to ensure the application process is functioning
      () => this.memory.checkHeap('memory_heap', 500 * 1024 * 1024), // 500MB - higher threshold
      () => this.memory.checkRSS('memory_rss', 1024 * 1024 * 1024),  // 1GB - higher threshold
      () => this.healthService.checkApplicationUptime(),
    ]);
  }

  /**
   * External services health check
   * Checks connectivity to external dependencies
   */
  @Get('external')
  @ApiOperation({ 
    summary: 'External services health check',
    description: 'Check connectivity and availability of external service dependencies'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'External services health information',
  })
  @HealthCheck()
  checkExternalServices() {
    return this.health.check([
      () => this.healthService.checkExternalServiceDependencies(),
      () => this.healthService.checkRedisConnectivity(),
    ]);
  }

  /**
   * Security configuration health check
   * Validates security settings and configuration
   */
  @Get('security')
  @ApiOperation({ 
    summary: 'Security configuration health check',
    description: 'Validate security configuration and settings'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Security configuration is healthy',
  })
  @ApiResponse({ 
    status: 503, 
    description: 'Security configuration has issues',
  })
  @HealthCheck()
  checkSecurity() {
    return this.health.check([
      () => this.healthService.checkSecurityConfiguration(),
      () => this.healthService.checkJWTConfiguration(),
    ]);
  }

  /**
   * Comprehensive health check
   * Runs all available health checks for complete system status
   */
  @Get('comprehensive')
  @ApiOperation({ 
    summary: 'Comprehensive health check',
    description: 'Complete system health check including all components and dependencies'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Complete system health information',
  })
  @HealthCheck()
  checkComprehensive() {
    return this.health.check([
      // Core system checks
      () => this.db.pingCheck('database'),
      () => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024),
      () => this.memory.checkRSS('memory_rss', 300 * 1024 * 1024),
      () => this.disk.checkStorage('storage', { path: '/', thresholdPercent: 0.9 }),
      
      // Application-specific checks
      () => this.healthService.checkApplicationUptime(),
      () => this.healthService.checkJWTConfiguration(),
      () => this.healthService.checkOAuthConfiguration(),
      () => this.healthService.checkRequiredEnvironmentVariables(),
      () => this.healthService.checkSecurityConfiguration(),
      
      // External dependencies (non-critical)
      () => this.healthService.checkExternalServiceDependencies(),
      () => this.healthService.checkRedisConnectivity(),
    ]);
  }

  /**
   * Simple status endpoint
   * Returns basic status for external monitoring tools
   */
  @Get('status')
  @ApiOperation({ 
    summary: 'Simple status check',
    description: 'Simple status endpoint for external monitoring systems'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Application status',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'healthy' },
        timestamp: { type: 'string', example: '2023-12-01T10:00:00Z' },
        uptime: { type: 'number', example: 12345 },
        memory: { type: 'object' },
        system: { type: 'object' },
      }
    }
  })
  getStatus() {
    return this.healthService.getHealthStatus();
  }

  /**
   * Application info endpoint
   * Returns static information about the application
   */
  @Get('info')
  @ApiOperation({ 
    summary: 'Application information',
    description: 'Static information about the application version, environment, etc.'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Application information',
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', example: 'Auth Service' },
        version: { type: 'string', example: '1.0.0' },
        environment: { type: 'string', example: 'development' },
        uptime: { type: 'number', example: 12345 },
        timestamp: { type: 'string', example: '2023-12-01T10:00:00Z' },
        nodeVersion: { type: 'string', example: 'v18.17.0' },
        platform: { type: 'string', example: 'linux' },
      }
    }
  })
  getInfo() {
    return this.healthService.getApplicationInfo();
  }
}