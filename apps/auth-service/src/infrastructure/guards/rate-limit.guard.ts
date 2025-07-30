import { Injectable, ExecutionContext, Logger } from '@nestjs/common';
import { ThrottlerGuard, ThrottlerException } from '@nestjs/throttler';
import { ThrottlerRequest } from '@nestjs/throttler/dist/interfaces';
import { ConfigService } from '@nestjs/config';

/**
 * Enhanced Rate Limiting Guard
 * 
 * Provides advanced rate limiting capabilities including:
 * - Progressive delays for repeated failures
 * - IP-based and user-based rate limiting
 * - Different limits for different endpoint types
 * - Audit logging for security monitoring
 */
@Injectable()
export class RateLimitGuard extends ThrottlerGuard {
  private readonly logger = new Logger(RateLimitGuard.name);
  private readonly failureCache = new Map<string, FailureRecord>();
  private readonly cleanupInterval: NodeJS.Timeout;

  constructor(private readonly configService: ConfigService) {
    super();
    
    // Clean up expired failure records every 5 minutes
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredFailures();
    }, 5 * 60 * 1000);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<ThrottlerRequest>();
    const clientId = this.getClientIdentifier(request);
    
    try {
      // Check if client is temporarily blocked due to repeated failures
      if (this.isTemporarilyBlocked(clientId)) {
        this.logger.warn(`Rate limit blocked - temporarily blocked client: ${clientId}`);
        throw new ThrottlerException('Too many failed attempts. Please try again later.');
      }

      // Apply progressive delay if there are recent failures
      await this.applyProgressiveDelay(clientId);

      // Execute standard throttling check
      const canActivate = await super.canActivate(context);
      
      if (canActivate) {
        // Reset failure count on successful request
        this.resetFailures(clientId);
        this.logger.debug(`Rate limit passed for client: ${clientId}`);
      }
      
      return canActivate;
    } catch (error) {
      // Track failures for progressive penalties
      this.trackFailure(clientId, request);
      
      this.logger.warn(`Rate limit exceeded - Client: ${clientId}, IP: ${this.getClientIp(request)}, User-Agent: ${request.headers['user-agent']}`);
      throw error;
    }
  }

  /**
   * Get client identifier for rate limiting
   * Uses combination of IP address and user ID (if authenticated)
   */
  protected getClientIdentifier(request: any): string {
    const ip = this.getClientIp(request);
    const userId = request.user?.userId;
    
    // Use user ID if authenticated, otherwise fall back to IP
    return userId ? `user:${userId}` : `ip:${ip}`;
  }

  /**
   * Extract client IP address with proxy support
   */
  protected getClientIp(request: any): string {
    return (
      request.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      request.headers['x-real-ip'] ||
      request.connection?.remoteAddress ||
      request.socket?.remoteAddress ||
      'Unknown'
    );
  }

  /**
   * Check if client is temporarily blocked due to repeated failures
   */
  private isTemporarilyBlocked(clientId: string): boolean {
    const failure = this.failureCache.get(clientId);
    if (!failure) return false;

    const blockDuration = this.calculateBlockDuration(failure.count);
    const blockUntil = failure.lastFailure.getTime() + blockDuration;
    
    return Date.now() < blockUntil;
  }

  /**
   * Apply progressive delay based on failure history
   */
  private async applyProgressiveDelay(clientId: string): Promise<void> {
    const failure = this.failureCache.get(clientId);
    if (!failure || failure.count === 0) return;

    const delay = this.calculateProgressiveDelay(failure.count);
    if (delay > 0) {
      this.logger.debug(`Applying progressive delay of ${delay}ms for client: ${clientId}`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  /**
   * Track failure for progressive penalty calculation
   */
  private trackFailure(clientId: string, request: any): void {
    const existing = this.failureCache.get(clientId);
    const now = new Date();
    
    const failure: FailureRecord = {
      count: existing ? existing.count + 1 : 1,
      firstFailure: existing?.firstFailure || now,
      lastFailure: now,
      ip: this.getClientIp(request),
      userAgent: request.headers['user-agent'] || 'Unknown',
      endpoint: `${request.method} ${request.url}`,
    };

    this.failureCache.set(clientId, failure);

    // Log security event for monitoring
    this.logger.warn(`Rate limit failure tracked - Client: ${clientId}, Count: ${failure.count}, Endpoint: ${failure.endpoint}`);
    
    // Log critical security alert for high failure counts
    if (failure.count >= 10) {
      this.logger.error(`SECURITY ALERT: High rate limit failure count - Client: ${clientId}, Count: ${failure.count}, IP: ${failure.ip}`);
    }
  }

  /**
   * Reset failure count for successful requests
   */
  private resetFailures(clientId: string): void {
    if (this.failureCache.has(clientId)) {
      this.failureCache.delete(clientId);
      this.logger.debug(`Reset failure count for client: ${clientId}`);
    }
  }

  /**
   * Calculate progressive delay in milliseconds
   * Exponential backoff with jitter
   */
  private calculateProgressiveDelay(failureCount: number): number {
    if (failureCount <= 1) return 0;
    
    // Base delay increases exponentially: 1s, 2s, 4s, 8s, etc.
    const baseDelay = Math.min(1000 * Math.pow(2, failureCount - 2), 30000); // Max 30 seconds
    
    // Add jitter (±25%)
    const jitter = 0.25;
    const jitterAmount = baseDelay * jitter * (Math.random() * 2 - 1);
    
    return Math.max(0, baseDelay + jitterAmount);
  }

  /**
   * Calculate block duration in milliseconds
   * Longer blocks for repeated failures
   */
  private calculateBlockDuration(failureCount: number): number {
    if (failureCount < 5) return 0; // No blocking for fewer than 5 failures
    
    // Progressive blocking: 1min, 5min, 15min, 30min, 1hour
    const durations = [60000, 300000, 900000, 1800000, 3600000];
    const index = Math.min(failureCount - 5, durations.length - 1);
    
    return durations[index];
  }

  /**
   * Clean up expired failure records
   */
  private cleanupExpiredFailures(): void {
    const now = Date.now();
    const expiry = 24 * 60 * 60 * 1000; // 24 hours
    
    let cleaned = 0;
    for (const [clientId, failure] of this.failureCache.entries()) {
      if (now - failure.lastFailure.getTime() > expiry) {
        this.failureCache.delete(clientId);
        cleaned++;
      }
    }
    
    if (cleaned > 0) {
      this.logger.debug(`Cleaned up ${cleaned} expired failure records`);
    }
  }

  /**
   * Get current failure statistics (for monitoring)
   */
  getFailureStatistics(): FailureStatistics {
    const stats: FailureStatistics = {
      totalClients: this.failureCache.size,
      blockedClients: 0,
      highFailureClients: 0,
      averageFailures: 0,
    };

    let totalFailures = 0;
    for (const failure of this.failureCache.values()) {
      totalFailures += failure.count;
      
      if (this.isTemporarilyBlocked(`temp:${failure.ip}`)) {
        stats.blockedClients++;
      }
      
      if (failure.count >= 10) {
        stats.highFailureClients++;
      }
    }

    stats.averageFailures = stats.totalClients > 0 ? 
      Math.round(totalFailures / stats.totalClients * 100) / 100 : 0;

    return stats;
  }

  /**
   * Cleanup when service is destroyed
   */
  onModuleDestroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }
}

/**
 * Failure record for tracking client violations
 */
interface FailureRecord {
  count: number;
  firstFailure: Date;
  lastFailure: Date;
  ip: string;
  userAgent: string;
  endpoint: string;
}

/**
 * Failure statistics for monitoring
 */
interface FailureStatistics {
  totalClients: number;
  blockedClients: number;
  highFailureClients: number;
  averageFailures: number;
}