import { CanActivate, ExecutionContext, Injectable, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request, Response } from 'express';
import { RateLimitingMiddleware, RateLimiterOptions } from '../middleware/rate-limiting.middleware';
import { getRateLimitingConfig } from '../config/rate-limiting.config';
import { RATE_LIMIT_KEY } from '../decorators/rate-limit.decorator';

/**
 * Rate Limit Guard
 * 
 * Applies rate limiting to specific endpoints using decorators
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly logger = new Logger(RateLimitGuard.name);
  private readonly rateLimitingMiddleware: RateLimitingMiddleware;

  constructor(private readonly reflector: Reflector) {
    const config = getRateLimitingConfig();
    this.rateLimitingMiddleware = new RateLimitingMiddleware(config);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    
    // Get rate limit options from decorator
    const rateLimitOptions = this.reflector.get<Partial<RateLimiterOptions>>(
      RATE_LIMIT_KEY,
      context.getHandler(),
    );

    if (!rateLimitOptions) {
      return true; // No rate limiting configured
    }

    try {
      // Extract client information
      const clientIP = this.getClientIP(request);
      const userId = this.getUserId(request);
      
      // Build complete options with defaults
      const options: RateLimiterOptions = {
        windowMs: 15 * 60 * 1000, // 15 minutes default
        maxRequests: 100, // 100 requests default
        message: 'Too many requests, please try again later.',
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        skipFailedRequests: false,
        ...rateLimitOptions,
      };

      // Check rate limit
      const status = this.rateLimitingMiddleware.getRateLimitStatus(clientIP, options);
      
      if (status.isLimited) {
        this.handleRateLimit(clientIP, userId, options, status, response);
        return false;
      }

      // Set rate limit headers for successful requests
      this.setRateLimitHeaders(response, options, status);
      
      return true;
      
    } catch (error) {
      this.logger.error('Rate limit guard error:', error);
      return true; // Allow request on error to avoid blocking legitimate users
    }
  }

  /**
   * Extract client IP address from request
   */
  private getClientIP(request: Request): string {
    return (
      (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      (request.headers['x-real-ip'] as string) ||
      request.connection.remoteAddress ||
      request.socket.remoteAddress ||
      '0.0.0.0'
    );
  }

  /**
   * Extract user ID from request if available
   */
  private getUserId(request: Request): string | null {
    try {
      const user = (request as any).user;
      return user?.id || user?.sub || null;
    } catch {
      return null;
    }
  }

  /**
   * Handle rate limit exceeded scenario
   */
  private handleRateLimit(
    clientIP: string,
    userId: string | null,
    options: RateLimiterOptions,
    status: any,
    response: Response
  ): void {
    const remainingTime = Math.ceil((status.resetTime - Date.now()) / 1000);
    
    this.logger.warn(`Rate limit exceeded`, {
      clientIP,
      userId,
      limit: options.maxRequests,
      windowMs: options.windowMs,
      remaining: status.remaining,
      resetTime: new Date(status.resetTime).toISOString(),
    });

    // Set headers
    this.setRateLimitHeaders(response, options, status);
    response.set('Retry-After', remainingTime.toString());

    // Throw HTTP exception
    throw new HttpException(
      {
        error: 'RATE_LIMIT_EXCEEDED',
        message: options.message,
        statusCode: HttpStatus.TOO_MANY_REQUESTS,
        retryAfter: remainingTime,
        details: {
          limit: status.limit,
          remaining: status.remaining,
          resetTime: new Date(status.resetTime).toISOString(),
        },
      },
      HttpStatus.TOO_MANY_REQUESTS,
    );
  }

  /**
   * Set rate limit headers in response
   */
  private setRateLimitHeaders(
    response: Response,
    options: RateLimiterOptions,
    status: any
  ): void {
    if (options.standardHeaders) {
      response.set({
        'RateLimit-Limit': status.limit.toString(),
        'RateLimit-Remaining': status.remaining.toString(),
        'RateLimit-Reset': new Date(status.resetTime).toISOString(),
      });
    }

    if (options.legacyHeaders) {
      response.set({
        'X-RateLimit-Limit': status.limit.toString(),
        'X-RateLimit-Remaining': status.remaining.toString(),
        'X-RateLimit-Reset': new Date(status.resetTime).toISOString(),
      });
    }
  }
}