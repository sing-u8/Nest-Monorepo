import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { 
  HealthCheckService, 
  HealthCheck, 
  HealthCheckResult,
  MemoryHealthIndicator,
  DiskHealthIndicator,
} from '@nestjs/terminus';
import { DatabaseHealthIndicator } from '../infrastructure/database/database.health';
import { ExternalServicesHealthIndicator } from '../infrastructure/health/external-services.health';
import { MetricsService } from '../infrastructure/monitoring/metrics.service';
import { PerformanceService } from '../infrastructure/monitoring/performance.service';

/**
 * Health Check Controller
 * 
 * Provides comprehensive health check endpoints for monitoring
 * application status, database connectivity, and system resources.
 */
@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(
    private readonly health: HealthCheckService,
    private readonly databaseHealthIndicator: DatabaseHealthIndicator,
    private readonly memoryHealthIndicator: MemoryHealthIndicator,
    private readonly diskHealthIndicator: DiskHealthIndicator,
    private readonly externalServicesHealthIndicator: ExternalServicesHealthIndicator,
    private readonly metricsService: MetricsService,
    private readonly performanceService: PerformanceService,
  ) {}

  /**
   * Overall health check
   * 
   * Performs comprehensive health check including database,
   * memory usage, and disk space validation.
   */
  @Get()
  @ApiOperation({ 
    summary: 'Get application health status',
    description: 'Returns comprehensive health check results including database connectivity, memory usage, and disk space'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Health check passed',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'ok' },
        info: { type: 'object' },
        error: { type: 'object' },
        details: { type: 'object' }
      }
    }
  })
  @ApiResponse({ 
    status: 503, 
    description: 'Health check failed - service unavailable' 
  })
  @HealthCheck()
  async check(): Promise<HealthCheckResult> {
    return this.health.check([
      // Database connectivity check
      () => this.databaseHealthIndicator.isHealthy('database'),
      
      // Memory usage check (heap should not exceed 150MB)
      () => this.memoryHealthIndicator.checkHeap('memory_heap', 150 * 1024 * 1024),
      
      // Memory RSS check (should not exceed 300MB)
      () => this.memoryHealthIndicator.checkRSS('memory_rss', 300 * 1024 * 1024),
      
      // Disk space check (should have at least 250MB free)
      () => this.diskHealthIndicator.checkStorage('storage', {
        path: '/',
        thresholdPercent: 0.9, // 90% threshold
      }),
    ]);
  }

  /**
   * Database-specific health check
   * 
   * Performs detailed database health check with connection
   * metrics and performance indicators.
   */
  @Get('database')
  @ApiOperation({ 
    summary: 'Get database health status',
    description: 'Returns detailed database health information including connection status, response time, and pool information'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Database health check passed' 
  })
  @ApiResponse({ 
    status: 503, 
    description: 'Database health check failed' 
  })
  @HealthCheck()
  async checkDatabase(): Promise<HealthCheckResult> {
    return this.health.check([
      () => this.databaseHealthIndicator.isHealthy('database', 5000), // 5 second timeout
    ]);
  }

  /**
   * Memory usage health check
   * 
   * Checks application memory consumption and provides
   * detailed memory usage statistics.
   */
  @Get('memory')
  @ApiOperation({ 
    summary: 'Get memory usage status',
    description: 'Returns memory usage statistics including heap and RSS memory consumption'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Memory health check passed' 
  })
  @ApiResponse({ 
    status: 503, 
    description: 'Memory usage exceeds threshold' 
  })
  @HealthCheck()
  async checkMemory(): Promise<HealthCheckResult> {
    return this.health.check([
      () => this.memoryHealthIndicator.checkHeap('memory_heap', 200 * 1024 * 1024),
      () => this.memoryHealthIndicator.checkRSS('memory_rss', 400 * 1024 * 1024),
    ]);
  }

  /**
   * Disk space health check
   * 
   * Monitors available disk space to prevent storage-related
   * application failures.
   */
  @Get('disk')
  @ApiOperation({ 
    summary: 'Get disk space status',
    description: 'Returns disk space usage and availability information'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Disk space health check passed' 
  })
  @ApiResponse({ 
    status: 503, 
    description: 'Disk space below threshold' 
  })
  @HealthCheck()
  async checkDisk(): Promise<HealthCheckResult> {
    return this.health.check([
      () => this.diskHealthIndicator.checkStorage('storage', {
        path: '/',
        thresholdPercent: 0.9,
      }),
    ]);
  }

  /**
   * Quick liveness check
   * 
   * Simple endpoint to verify that the application is running
   * and responsive. Used by orchestrators for basic health monitoring.
   */
  @Get('live')
  @ApiOperation({ 
    summary: 'Liveness probe',
    description: 'Simple endpoint to verify application is running and responsive'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Application is alive',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'ok' },
        timestamp: { type: 'string', example: '2023-01-01T00:00:00.000Z' },
        uptime: { type: 'number', example: 123.456 }
      }
    }
  })
  async liveness(): Promise<any> {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      node: process.version,
      memory: {
        used: Math.round((process.memoryUsage().heapUsed / 1024 / 1024) * 100) / 100,
        total: Math.round((process.memoryUsage().heapTotal / 1024 / 1024) * 100) / 100,
      },
    };
  }

  /**
   * Readiness check
   * 
   * Verifies that the application is ready to serve traffic
   * by checking critical dependencies and services.
   */
  @Get('ready')
  @ApiOperation({ 
    summary: 'Readiness probe',
    description: 'Verifies application is ready to serve traffic by checking critical dependencies'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Application is ready' 
  })
  @ApiResponse({ 
    status: 503, 
    description: 'Application is not ready' 
  })
  @HealthCheck()
  async readiness(): Promise<HealthCheckResult> {
    return this.health.check([
      // Check database connectivity (critical for serving requests)
      () => this.databaseHealthIndicator.isHealthy('database', 3000),
      
      // Quick database connection test
      () => this.databaseHealthIndicator.quickCheck().then(isHealthy => ({
        database_quick: {
          status: isHealthy ? 'up' : 'down',
        },
      })),
    ]);
  }

  /**
   * External services health check
   * 
   * Checks the health of external dependencies including
   * OAuth providers and third-party services.
   */
  @Get('external')
  @ApiOperation({ 
    summary: 'Get external services health status',
    description: 'Returns health status for external dependencies including OAuth providers'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'External services health check passed' 
  })
  @ApiResponse({ 
    status: 503, 
    description: 'External services health check failed' 
  })
  @HealthCheck()
  async checkExternal(): Promise<HealthCheckResult> {
    return this.health.check([
      () => this.externalServicesHealthIndicator.checkAllExternalServices('external_services'),
    ]);
  }

  /**
   * OAuth services health check
   * 
   * Specifically checks OAuth provider availability
   * including Google and Apple authentication services.
   */
  @Get('oauth')
  @ApiOperation({ 
    summary: 'Get OAuth services health status',
    description: 'Returns health status specifically for OAuth authentication providers'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'OAuth services health check passed' 
  })
  @ApiResponse({ 
    status: 503, 
    description: 'OAuth services health check failed' 
  })
  @HealthCheck()
  async checkOAuth(): Promise<HealthCheckResult> {
    return this.health.check([
      () => this.externalServicesHealthIndicator.checkAllOAuthServices('oauth_services'),
    ]);
  }

  /**
   * Network connectivity health check
   * 
   * Tests basic network connectivity to external endpoints
   * to ensure the service can reach external dependencies.
   */
  @Get('network')
  @ApiOperation({ 
    summary: 'Get network connectivity status',
    description: 'Tests network connectivity to external endpoints'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Network connectivity check passed' 
  })
  @ApiResponse({ 
    status: 503, 
    description: 'Network connectivity check failed' 
  })
  @HealthCheck()
  async checkNetwork(): Promise<HealthCheckResult> {
    return this.health.check([
      () => this.externalServicesHealthIndicator.checkNetworkConnectivity('network_connectivity'),
    ]);
  }

  /**
   * Application metrics endpoint
   * 
   * Returns application performance and usage metrics
   * for monitoring and alerting systems.
   */
  @Get('metrics')
  @ApiOperation({ 
    summary: 'Get application metrics',
    description: 'Returns comprehensive application metrics including authentication events, performance data, and system statistics'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Application metrics retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        timestamp: { type: 'string' },
        uptime: { type: 'number' },
        authentication: { type: 'object' },
        oauth: { type: 'object' },
        security: { type: 'object' },
        system: { type: 'object' },
        performance: { type: 'object' }
      }
    }
  })
  async getMetrics(): Promise<any> {
    return this.metricsService.getMetricsSummary();
  }

  /**
   * Application metrics in Prometheus format
   * 
   * Returns metrics in Prometheus exposition format
   * for integration with Prometheus monitoring.
   */
  @Get('metrics/prometheus')
  @ApiOperation({ 
    summary: 'Get metrics in Prometheus format',
    description: 'Returns application metrics in Prometheus exposition format'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Prometheus metrics retrieved successfully',
    schema: {
      type: 'string',
      example: '# HELP auth_requests_total Total authentication requests\n# TYPE auth_requests_total counter\nauth_requests_total 42\n'
    }
  })
  async getPrometheusMetrics(): Promise<string> {
    return this.metricsService.getPrometheusMetrics();
  }

  /**
   * Performance monitoring data
   * 
   * Returns detailed performance monitoring information
   * including operation statistics and system health.
   */
  @Get('performance')
  @ApiOperation({ 
    summary: 'Get performance monitoring data',
    description: 'Returns comprehensive performance monitoring data including operation statistics and system health assessment'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Performance data retrieved successfully' 
  })
  async getPerformance(): Promise<any> {
    return this.performanceService.getPerformanceSummary();
  }

  /**
   * Slow operations report
   * 
   * Returns a report of the slowest operations
   * for performance optimization insights.
   */
  @Get('performance/slow')
  @ApiOperation({ 
    summary: 'Get slow operations report',
    description: 'Returns a report of the slowest operations for performance analysis'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Slow operations report retrieved successfully' 
  })
  async getSlowOperations(): Promise<any> {
    return {
      timestamp: new Date().toISOString(),
      slowOperations: this.performanceService.getSlowOperationsReport(20),
    };
  }

  /**
   * Comprehensive system status
   * 
   * Returns a comprehensive system status report
   * combining health checks, metrics, and performance data.
   */
  @Get('status')
  @ApiOperation({ 
    summary: 'Get comprehensive system status',
    description: 'Returns comprehensive system status including health checks, metrics, and performance data'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'System status retrieved successfully' 
  })
  async getSystemStatus(): Promise<any> {
    const [
      healthCheck,
      metrics,
      performance,
      databaseInfo
    ] = await Promise.allSettled([
      this.check().catch(err => ({ status: 'error', error: err.message })),
      this.metricsService.getMetricsSummary(),
      this.performanceService.getPerformanceSummary(),
      this.databaseHealthIndicator.getDatabaseInfo(),
    ]);

    return {
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      uptime: process.uptime(),
      health: healthCheck.status === 'fulfilled' ? healthCheck.value : healthCheck.reason,
      metrics: metrics.status === 'fulfilled' ? metrics.value : { error: metrics.reason },
      performance: performance.status === 'fulfilled' ? performance.value : { error: performance.reason },
      database: databaseInfo.status === 'fulfilled' ? databaseInfo.value : { error: databaseInfo.reason },
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        architecture: process.arch,
        memoryUsage: process.memoryUsage(),
        cpuUsage: process.cpuUsage(),
      },
    };
  }
}