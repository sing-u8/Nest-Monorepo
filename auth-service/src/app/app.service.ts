import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '@auth/infrastructure';

/**
 * Application Service
 * 
 * Provides core application information and status functionality.
 * Serves as the main service for application-level operations.
 */
@Injectable()
export class AppService {
  private readonly startTime = Date.now();

  constructor(private configService: ConfigService) {}

  /**
   * Get API information
   * Returns basic information about the API service
   */
  getApiInfo() {
    const config = this.configService.get<AppConfig>('app');
    const isProduction = config?.NODE_ENV === 'production';

    return {
      name: config?.APP_NAME || 'Auth Service API',
      version: config?.APP_VERSION || '1.0.0',
      description: config?.APP_DESCRIPTION || 'NestJS Authentication Service with Clean Architecture',
      environment: config?.NODE_ENV || 'development',
      documentation: isProduction ? null : '/docs',
      health: '/health',
      endpoints: {
        authentication: `/${config?.API_PREFIX || 'api/v1'}/auth`,
        profile: `/${config?.API_PREFIX || 'api/v1'}/profile`,
        oauth: `/${config?.API_PREFIX || 'api/v1'}/auth/social`,
        health: '/health',
        ...(isProduction ? {} : { docs: '/docs' }),
      },
      features: {
        authentication: true,
        socialLogin: true,
        profileManagement: true,
        jwtTokens: true,
        rateLimiting: config?.SECURITY_ENABLE_RATE_LIMITING || false,
        mTLS: config?.SECURITY_ENABLE_MTLS || false,
        monitoring: config?.MONITORING_ENABLE_HEALTH_CHECK || false,
      },
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Get current API status
   * Returns the current status and uptime of the API service
   */
  getStatus() {
    const config = this.configService.get<AppConfig>('app');
    const uptime = Date.now() - this.startTime;
    const memoryUsage = process.memoryUsage();

    return {
      status: 'online',
      uptime: Math.floor(uptime / 1000),
      uptimeMs: uptime,
      timestamp: new Date().toISOString(),
      version: config?.APP_VERSION || '1.0.0',
      environment: config?.NODE_ENV || 'development',
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        architecture: process.arch,
        pid: process.pid,
      },
      memory: {
        heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024), // MB
        heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024), // MB
        rss: Math.round(memoryUsage.rss / 1024 / 1024), // MB
        external: Math.round(memoryUsage.external / 1024 / 1024), // MB
      },
      server: {
        port: config?.PORT || 3000,
        apiPrefix: config?.API_PREFIX || 'api/v1',
        cors: config?.API_ENABLE_CORS || false,
      },
    };
  }
}
