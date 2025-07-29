import { Injectable, NestMiddleware, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { RateLimitingConfig } from '../config/rate-limiting.config';

export interface RateLimiterOptions {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Maximum number of requests in the window
  message: string; // Error message when limit is exceeded
  standardHeaders: boolean; // Include standard rate limit headers
  legacyHeaders: boolean; // Include legacy X-RateLimit headers
  skipSuccessfulRequests: boolean; // Don't count successful requests
  skipFailedRequests: boolean; // Don't count failed requests
}

interface RateLimitRecord {
  count: number;
  resetTime: number;
  firstRequest: number;
}

interface ProgressiveDelayRecord {
  attempts: number;
  lastAttempt: number;
  nextAllowedTime: number;
}

interface IPBlockRecord {
  failures: number;
  blockedUntil: number;
  lastFailure: number;
}

interface UserRateLimitRecord {
  attempts: number;
  windowStart: number;
  penaltyUntil: number;
}

/**
 * Advanced Rate Limiting Middleware
 * 
 * Provides multiple layers of rate limiting:
 * 1. Basic IP-based rate limiting
 * 2. Progressive delays for failed attempts
 * 3. IP blocking after repeated failures
 * 4. User-based rate limiting
 */
@Injectable()
export class RateLimitingMiddleware implements NestMiddleware {
  private readonly logger = new Logger(RateLimitingMiddleware.name);
  
  // In-memory storage for rate limiting (in production, use Redis)
  private readonly rateLimitStore = new Map<string, RateLimitRecord>();
  private readonly progressiveDelayStore = new Map<string, ProgressiveDelayRecord>();
  private readonly ipBlockStore = new Map<string, IPBlockRecord>();
  private readonly userRateLimitStore = new Map<string, UserRateLimitRecord>();
  
  constructor(
    private readonly config: RateLimitingConfig,
    private readonly options?: RateLimiterOptions
  ) {
    // Cleanup expired records every 5 minutes
    setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  use(req: Request, res: Response, next: NextFunction): void {
    const clientIP = this.getClientIP(req);
    const userId = this.getUserId(req);
    const endpoint = this.getEndpoint(req);
    
    try {
      // 1. Check IP blocking first
      if (this.config.ipBlocking.enabled && this.isIPBlocked(clientIP)) {
        this.handleBlockedIP(clientIP, res);
        return;
      }

      // 2. Check progressive delays
      if (this.config.progressive.enabled && this.hasProgressiveDelay(clientIP)) {
        this.handleProgressiveDelay(clientIP, res);
        return;
      }

      // 3. Check user-based rate limiting
      if (this.config.userBased.enabled && userId && this.isUserRateLimited(userId)) {
        this.handleUserRateLimit(userId, res);
        return;
      }

      // 4. Check endpoint-specific rate limiting
      const endpointOptions = this.getEndpointOptions(endpoint);
      if (endpointOptions && this.isRateLimited(clientIP, endpointOptions)) {
        this.handleRateLimit(clientIP, endpointOptions, res);
        return;
      }

      // 5. Check global rate limiting
      if (this.isRateLimited(clientIP, this.config.global)) {
        this.handleRateLimit(clientIP, this.config.global, res);
        return;
      }

      // Record the request
      this.recordRequest(clientIP, endpoint);
      
      // Continue to next middleware
      next();
      
    } catch (error) {
      this.logger.error('Rate limiting error:', error);
      next(); // Continue on error to avoid blocking legitimate requests
    }
  }

  /**
   * Extract client IP address from request
   */
  private getClientIP(req: Request): string {
    return (
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      (req.headers['x-real-ip'] as string) ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      '0.0.0.0'
    );
  }

  /**
   * Extract user ID from JWT token if available
   */
  private getUserId(req: Request): string | null {
    try {
      const user = (req as any).user;
      return user?.id || user?.sub || null;
    } catch {
      return null;
    }
  }

  /**
   * Get endpoint identifier from request
   */
  private getEndpoint(req: Request): string {
    const method = req.method.toLowerCase();
    const path = req.route?.path || req.path;
    return `${method}:${path}`;
  }

  /**
   * Get rate limiting options for specific endpoint
   */
  private getEndpointOptions(endpoint: string): RateLimiterOptions | null {
    if (endpoint.includes('/auth/login')) {
      return this.config.auth.login;
    }
    if (endpoint.includes('/auth/register')) {
      return this.config.auth.register;
    }
    if (endpoint.includes('/auth/refresh')) {
      return this.config.auth.refresh;
    }
    if (endpoint.includes('/auth/google') || endpoint.includes('/auth/apple')) {
      return this.config.auth.socialAuth;
    }
    return null;
  }

  /**
   * Check if IP is currently blocked
   */
  private isIPBlocked(ip: string): boolean {
    // Check whitelist
    if (this.config.ipBlocking.whitelist.includes(ip)) {
      return false;
    }

    const record = this.ipBlockStore.get(ip);
    if (!record) {
      return false;
    }

    const now = Date.now();
    if (now > record.blockedUntil) {
      this.ipBlockStore.delete(ip);
      return false;
    }

    return true;
  }

  /**
   * Check if request should be delayed due to progressive delays
   */
  private hasProgressiveDelay(ip: string): boolean {
    const record = this.progressiveDelayStore.get(ip);
    if (!record) {
      return false;
    }

    const now = Date.now();
    
    // Reset if enough time has passed
    if (now - record.lastAttempt > this.config.progressive.resetTime * 1000) {
      this.progressiveDelayStore.delete(ip);
      return false;
    }

    return now < record.nextAllowedTime;
  }

  /**
   * Check if user is rate limited
   */
  private isUserRateLimited(userId: string): boolean {
    const record = this.userRateLimitStore.get(userId);
    if (!record) {
      return false;
    }

    const now = Date.now();
    
    // Check if penalty period is over
    if (now > record.penaltyUntil) {
      this.userRateLimitStore.delete(userId);
      return false;
    }

    return true;
  }

  /**
   * Check if IP is rate limited for given options
   */
  private isRateLimited(ip: string, options: RateLimiterOptions): boolean {
    const key = `${ip}:${options.windowMs}:${options.maxRequests}`;
    const record = this.rateLimitStore.get(key);
    const now = Date.now();

    if (!record) {
      return false;
    }

    // Reset window if expired
    if (now > record.resetTime) {
      this.rateLimitStore.delete(key);
      return false;
    }

    return record.count >= options.maxRequests;
  }

  /**
   * Record a request for rate limiting
   */
  private recordRequest(ip: string, endpoint: string): void {
    const endpointOptions = this.getEndpointOptions(endpoint);
    
    // Record for endpoint-specific limiting
    if (endpointOptions) {
      this.updateRateLimitRecord(ip, endpointOptions);
    }
    
    // Record for global limiting
    this.updateRateLimitRecord(ip, this.config.global);
  }

  /**
   * Update rate limit record for IP and options
   */
  private updateRateLimitRecord(ip: string, options: RateLimiterOptions): void {
    const key = `${ip}:${options.windowMs}:${options.maxRequests}`;
    const now = Date.now();
    const record = this.rateLimitStore.get(key);

    if (!record || now > record.resetTime) {
      this.rateLimitStore.set(key, {
        count: 1,
        resetTime: now + options.windowMs,
        firstRequest: now,
      });
    } else {
      record.count++;
      this.rateLimitStore.set(key, record);
    }
  }

  /**
   * Handle blocked IP response
   */
  private handleBlockedIP(ip: string, res: Response): void {
    const record = this.ipBlockStore.get(ip)!;
    const remainingTime = Math.ceil((record.blockedUntil - Date.now()) / 1000);
    
    this.logger.warn(`Blocked IP attempt: ${ip}, remaining: ${remainingTime}s`);
    
    res.status(HttpStatus.TOO_MANY_REQUESTS);
    res.set({
      'Retry-After': remainingTime.toString(),
      'X-Blocked-Until': new Date(record.blockedUntil).toISOString(),
    });
    res.json({
      error: 'IP_BLOCKED',
      message: 'Your IP has been temporarily blocked due to suspicious activity',
      retryAfter: remainingTime,
    });
  }

  /**
   * Handle progressive delay response
   */
  private handleProgressiveDelay(ip: string, res: Response): void {
    const record = this.progressiveDelayStore.get(ip)!;
    const remainingTime = Math.ceil((record.nextAllowedTime - Date.now()) / 1000);
    
    this.logger.warn(`Progressive delay for IP: ${ip}, attempts: ${record.attempts}, delay: ${remainingTime}s`);
    
    res.status(HttpStatus.TOO_MANY_REQUESTS);
    res.set({
      'Retry-After': remainingTime.toString(),
      'X-Progressive-Delay': 'true',
      'X-Attempt-Count': record.attempts.toString(),
    });
    res.json({
      error: 'PROGRESSIVE_DELAY',
      message: 'Please wait before attempting again',
      retryAfter: remainingTime,
      attemptCount: record.attempts,
    });
  }

  /**
   * Handle user rate limit response
   */
  private handleUserRateLimit(userId: string, res: Response): void {
    const record = this.userRateLimitStore.get(userId)!;
    const remainingTime = Math.ceil((record.penaltyUntil - Date.now()) / 1000);
    
    this.logger.warn(`User rate limited: ${userId}, attempts: ${record.attempts}, penalty: ${remainingTime}s`);
    
    res.status(HttpStatus.TOO_MANY_REQUESTS);
    res.set({
      'Retry-After': remainingTime.toString(),
      'X-User-Rate-Limited': 'true',
    });
    res.json({
      error: 'USER_RATE_LIMITED',
      message: 'Too many attempts from your account',
      retryAfter: remainingTime,
    });
  }

  /**
   * Handle standard rate limit response
   */
  private handleRateLimit(ip: string, options: RateLimiterOptions, res: Response): void {
    const key = `${ip}:${options.windowMs}:${options.maxRequests}`;
    const record = this.rateLimitStore.get(key)!;
    const remainingTime = Math.ceil((record.resetTime - Date.now()) / 1000);
    
    this.logger.warn(`Rate limit exceeded for IP: ${ip}, limit: ${options.maxRequests}, window: ${options.windowMs}ms`);
    
    res.status(HttpStatus.TOO_MANY_REQUESTS);
    
    if (options.standardHeaders) {
      res.set({
        'RateLimit-Limit': options.maxRequests.toString(),
        'RateLimit-Remaining': '0',
        'RateLimit-Reset': new Date(record.resetTime).toISOString(),
        'Retry-After': remainingTime.toString(),
      });
    }
    
    if (options.legacyHeaders) {
      res.set({
        'X-RateLimit-Limit': options.maxRequests.toString(),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': new Date(record.resetTime).toISOString(),
      });
    }
    
    res.json({
      error: 'RATE_LIMIT_EXCEEDED',
      message: options.message,
      retryAfter: remainingTime,
    });
  }

  /**
   * Record authentication failure for progressive delays and IP blocking
   */
  recordAuthFailure(ip: string, userId?: string): void {
    // Record progressive delay
    if (this.config.progressive.enabled) {
      this.recordProgressiveDelay(ip);
    }

    // Record IP failure for blocking
    if (this.config.ipBlocking.enabled) {
      this.recordIPFailure(ip);
    }

    // Record user failure
    if (this.config.userBased.enabled && userId) {
      this.recordUserFailure(userId);
    }
  }

  /**
   * Record progressive delay for IP
   */
  private recordProgressiveDelay(ip: string): void {
    const record = this.progressiveDelayStore.get(ip) || {
      attempts: 0,
      lastAttempt: 0,
      nextAllowedTime: 0,
    };

    const now = Date.now();
    
    // Reset if enough time has passed
    if (now - record.lastAttempt > this.config.progressive.resetTime * 1000) {
      record.attempts = 0;
    }

    record.attempts++;
    record.lastAttempt = now;

    if (record.attempts <= this.config.progressive.maxAttempts) {
      // Calculate exponential delay
      const delay = Math.min(
        this.config.progressive.baseDelay * Math.pow(2, record.attempts - 1),
        this.config.progressive.maxDelay
      );
      record.nextAllowedTime = now + delay;
    }

    this.progressiveDelayStore.set(ip, record);
    
    this.logger.debug(`Progressive delay recorded for IP: ${ip}, attempts: ${record.attempts}`);
  }

  /**
   * Record IP failure for blocking
   */
  private recordIPFailure(ip: string): void {
    // Don't block whitelisted IPs
    if (this.config.ipBlocking.whitelist.includes(ip)) {
      return;
    }

    const record = this.ipBlockStore.get(ip) || {
      failures: 0,
      blockedUntil: 0,
      lastFailure: 0,
    };

    const now = Date.now();
    record.failures++;
    record.lastFailure = now;

    if (record.failures >= this.config.ipBlocking.maxFailures) {
      record.blockedUntil = now + (this.config.ipBlocking.blockDuration * 1000);
      this.logger.warn(`IP blocked: ${ip}, failures: ${record.failures}, duration: ${this.config.ipBlocking.blockDuration}s`);
    }

    this.ipBlockStore.set(ip, record);
  }

  /**
   * Record user failure for rate limiting
   */
  private recordUserFailure(userId: string): void {
    const record = this.userRateLimitStore.get(userId) || {
      attempts: 0,
      windowStart: 0,
      penaltyUntil: 0,
    };

    const now = Date.now();
    
    // Reset window if expired
    if (now - record.windowStart > this.config.userBased.windowSize * 1000) {
      record.attempts = 0;
      record.windowStart = now;
    }

    record.attempts++;

    if (record.attempts >= this.config.userBased.maxAttempts) {
      record.penaltyUntil = now + (this.config.userBased.penaltyDuration * 1000);
      this.logger.warn(`User rate limited: ${userId}, attempts: ${record.attempts}, penalty: ${this.config.userBased.penaltyDuration}s`);
    }

    this.userRateLimitStore.set(userId, record);
  }

  /**
   * Clean up expired records
   */
  private cleanup(): void {
    const now = Date.now();
    let cleaned = 0;

    // Clean rate limit records
    for (const [key, record] of this.rateLimitStore) {
      if (now > record.resetTime) {
        this.rateLimitStore.delete(key);
        cleaned++;
      }
    }

    // Clean progressive delay records
    for (const [ip, record] of this.progressiveDelayStore) {
      if (now - record.lastAttempt > this.config.progressive.resetTime * 1000) {
        this.progressiveDelayStore.delete(ip);
        cleaned++;
      }
    }

    // Clean IP block records
    for (const [ip, record] of this.ipBlockStore) {
      if (now > record.blockedUntil) {
        this.ipBlockStore.delete(ip);
        cleaned++;
      }
    }

    // Clean user rate limit records
    for (const [userId, record] of this.userRateLimitStore) {
      if (now > record.penaltyUntil) {
        this.userRateLimitStore.delete(userId);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      this.logger.debug(`Cleaned up ${cleaned} expired rate limiting records`);
    }
  }

  /**
   * Get current rate limit status for IP
   */
  getRateLimitStatus(ip: string, options: RateLimiterOptions): {
    limit: number;
    remaining: number;
    resetTime: number;
    isLimited: boolean;
  } {
    const key = `${ip}:${options.windowMs}:${options.maxRequests}`;
    const record = this.rateLimitStore.get(key);
    const now = Date.now();

    if (!record || now > record.resetTime) {
      return {
        limit: options.maxRequests,
        remaining: options.maxRequests,
        resetTime: now + options.windowMs,
        isLimited: false,
      };
    }

    return {
      limit: options.maxRequests,
      remaining: Math.max(0, options.maxRequests - record.count),
      resetTime: record.resetTime,
      isLimited: record.count >= options.maxRequests,
    };
  }
}