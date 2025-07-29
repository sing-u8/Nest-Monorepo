import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HealthIndicatorResult, HealthIndicator } from '@nestjs/terminus';
import { AppConfig } from '@auth/infrastructure';

/**
 * Health Service
 * 
 * Provides custom health check indicators for application-specific checks.
 * Extends the Terminus health check system with business logic validations.
 */
@Injectable()
export class HealthService extends HealthIndicator {
  private readonly logger = new Logger(HealthService.name);
  private readonly startTime = Date.now();

  constructor(private configService: ConfigService) {
    super();
  }

  /**
   * Check JWT configuration health
   * Validates that JWT configuration is properly set and accessible
   */
  async checkJWTConfiguration(): Promise<HealthIndicatorResult> {
    const key = 'jwt_config';
    
    try {
      const config = this.configService.get<AppConfig>('app');
      
      if (!config) {
        throw new Error('Application configuration not available');
      }

      if (!config.JWT_SECRET || config.JWT_SECRET.length < 32) {
        throw new Error('JWT secret is missing or too short');
      }

      if (!config.JWT_REFRESH_SECRET || config.JWT_REFRESH_SECRET.length < 32) {
        throw new Error('JWT refresh secret is missing or too short');
      }

      const result = this.getStatus(key, true, {
        jwtSecretLength: config.JWT_SECRET.length,
        refreshSecretLength: config.JWT_REFRESH_SECRET.length,
        issuer: config.JWT_ISSUER,
        audience: config.JWT_AUDIENCE,
        accessTokenExpiration: config.JWT_ACCESS_TOKEN_EXPIRATION,
        refreshTokenExpiration: config.JWT_REFRESH_TOKEN_EXPIRATION,
      });

      this.logger.debug('JWT configuration health check passed');
      return result;

    } catch (error) {
      const result = this.getStatus(key, false, {
        error: error.message,
      });

      this.logger.warn(`JWT configuration health check failed: ${error.message}`);
      throw new Error(`JWT configuration is unhealthy: ${error.message}`);
    }
  }

  /**
   * Check OAuth configuration health
   * Validates OAuth provider configurations
   */
  async checkOAuthConfiguration(): Promise<HealthIndicatorResult> {
    const key = 'oauth_config';
    
    try {
      const config = this.configService.get<AppConfig>('app');
      
      if (!config) {
        throw new Error('Application configuration not available');
      }

      const oauthStatus = {
        google: {
          configured: !!(config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET),
          hasClientId: !!config.GOOGLE_CLIENT_ID,
          hasClientSecret: !!config.GOOGLE_CLIENT_SECRET,
          hasCallbackUrl: !!config.GOOGLE_CALLBACK_URL,
        },
        apple: {
          configured: !!(config.APPLE_CLIENT_ID && config.APPLE_TEAM_ID && config.APPLE_KEY_ID && config.APPLE_PRIVATE_KEY),
          hasClientId: !!config.APPLE_CLIENT_ID,
          hasTeamId: !!config.APPLE_TEAM_ID,
          hasKeyId: !!config.APPLE_KEY_ID,
          hasPrivateKey: !!config.APPLE_PRIVATE_KEY,
          hasCallbackUrl: !!config.APPLE_CALLBACK_URL,
        },
      };

      const result = this.getStatus(key, true, oauthStatus);

      this.logger.debug('OAuth configuration health check passed');
      return result;

    } catch (error) {
      const result = this.getStatus(key, false, {
        error: error.message,
      });

      this.logger.warn(`OAuth configuration health check failed: ${error.message}`);
      return result; // OAuth is optional, so don't throw
    }
  }

  /**
   * Check required environment variables
   * Validates that all critical environment variables are set
   */
  async checkRequiredEnvironmentVariables(): Promise<HealthIndicatorResult> {
    const key = 'environment_variables';
    
    try {
      const config = this.configService.get<AppConfig>('app');
      
      if (!config) {
        throw new Error('Application configuration not available');
      }

      const requiredVars = [
        'NODE_ENV',
        'JWT_SECRET',
        'JWT_REFRESH_SECRET',
        'DATABASE_USERNAME',
        'DATABASE_PASSWORD',
        'DATABASE_NAME',
      ];

      const missingVars: string[] = [];
      const presentVars: string[] = [];

      for (const varName of requiredVars) {
        const value = config[varName as keyof AppConfig];
        if (!value || (typeof value === 'string' && value.trim().length === 0)) {
          missingVars.push(varName);
        } else {
          presentVars.push(varName);
        }
      }

      if (missingVars.length > 0) {
        throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
      }

      const result = this.getStatus(key, true, {
        totalRequired: requiredVars.length,
        present: presentVars.length,
        missing: missingVars.length,
        presentVars,
        environment: config.NODE_ENV,
      });

      this.logger.debug('Environment variables health check passed');
      return result;

    } catch (error) {
      const result = this.getStatus(key, false, {
        error: error.message,
      });

      this.logger.error(`Environment variables health check failed: ${error.message}`);
      throw new Error(`Required environment variables check failed: ${error.message}`);
    }
  }

  /**
   * Check application uptime
   * Validates that the application has been running for a reasonable time
   */
  async checkApplicationUptime(): Promise<HealthIndicatorResult> {
    const key = 'application_uptime';
    
    try {
      const uptime = Date.now() - this.startTime;
      const uptimeSeconds = Math.floor(uptime / 1000);
      
      // Consider unhealthy if uptime is less than 10 seconds (might indicate rapid restarts)
      const isHealthy = uptimeSeconds >= 10;

      if (!isHealthy) {
        throw new Error(`Application uptime too low: ${uptimeSeconds} seconds`);
      }

      const result = this.getStatus(key, isHealthy, {
        uptimeMs: uptime,
        uptimeSeconds,
        startTime: new Date(this.startTime).toISOString(),
        currentTime: new Date().toISOString(),
      });

      this.logger.debug(`Application uptime health check passed: ${uptimeSeconds}s`);
      return result;

    } catch (error) {
      const result = this.getStatus(key, false, {
        error: error.message,
        uptimeMs: Date.now() - this.startTime,
      });

      this.logger.warn(`Application uptime health check failed: ${error.message}`);
      throw new Error(`Application uptime check failed: ${error.message}`);
    }
  }

  /**
   * Get application information
   * Returns static information about the application
   */
  getApplicationInfo() {
    const config = this.configService.get<AppConfig>('app');
    const uptime = Date.now() - this.startTime;

    return {
      name: config?.APP_NAME || 'Auth Service',
      version: config?.APP_VERSION || '1.0.0',
      description: config?.APP_DESCRIPTION || 'NestJS Authentication Service',
      environment: config?.NODE_ENV || 'development',
      uptime: Math.floor(uptime / 1000),
      uptimeMs: uptime,
      startTime: new Date(this.startTime).toISOString(),
      timestamp: new Date().toISOString(),
      nodeVersion: process.version,
      platform: process.platform,
      architecture: process.arch,
      pid: process.pid,
      memoryUsage: process.memoryUsage(),
      cpuUsage: process.cpuUsage(),
      versions: process.versions,
      env: {
        nodeEnv: process.env.NODE_ENV,
        port: config?.PORT,
        apiPrefix: config?.API_PREFIX,
      },
      database: {
        type: config?.DATABASE_TYPE,
        host: config?.DATABASE_HOST,
        port: config?.DATABASE_PORT,
        name: config?.DATABASE_NAME,
        // Don't expose sensitive information
      },
      security: {
        corsEnabled: config?.API_ENABLE_CORS,
        helmetEnabled: config?.SECURITY_ENABLE_HELMET,
        rateLimitingEnabled: config?.SECURITY_ENABLE_RATE_LIMITING,
        mtlsEnabled: config?.SECURITY_ENABLE_MTLS,
      },
      monitoring: {
        healthCheckEnabled: config?.MONITORING_ENABLE_HEALTH_CHECK,
        metricsEnabled: config?.MONITORING_ENABLE_METRICS,
        healthCheckPath: config?.MONITORING_HEALTH_CHECK_PATH,
        metricsPath: config?.MONITORING_METRICS_PATH,
      },
    };
  }

  /**
   * Get health check status for external monitoring systems
   * Returns a simple status object for integration with external tools
   */
  getHealthStatus() {
    const uptime = Date.now() - this.startTime;
    const memoryUsage = process.memoryUsage();
    
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: Math.floor(uptime / 1000),
      memory: {
        heapUsed: memoryUsage.heapUsed,
        heapTotal: memoryUsage.heapTotal,
        rss: memoryUsage.rss,
        external: memoryUsage.external,
        arrayBuffers: memoryUsage.arrayBuffers,
      },
      system: {
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version,
        pid: process.pid,
      },
    };
  }
}