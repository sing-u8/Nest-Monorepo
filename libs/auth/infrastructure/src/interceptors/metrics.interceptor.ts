import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { MetricsService } from '../services/metrics.service';

/**
 * Metrics Interceptor
 * 
 * Automatically collects performance metrics for all HTTP requests
 * and tracks authentication events.
 */
@Injectable()
export class MetricsInterceptor implements NestInterceptor {
  private readonly logger = new Logger(MetricsInterceptor.name);
  
  constructor(private metricsService: MetricsService) {}
  
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    
    const startTime = Date.now();
    const method = request.method;
    const url = request.url;
    const endpoint = this.normalizeEndpoint(url);
    
    // Start system metrics collection
    this.metricsService.recordSystemMetrics();
    
    return next.handle().pipe(
      tap((data) => {
        const duration = Date.now() - startTime;
        const statusCode = response.statusCode;
        
        // Record API performance
        this.metricsService.recordApiPerformance(
          endpoint,
          method,
          statusCode,
          duration,
          {
            userAgent: request.headers['user-agent'],
            ip: request.ip,
            userId: request.user?.id,
          },
        );
        
        // Track authentication events based on endpoint and response
        this.trackAuthenticationMetrics(endpoint, method, statusCode, data);
        
        // Log slow requests
        if (duration > 1000) {
          this.logger.warn(`Slow request detected: ${method} ${endpoint} took ${duration}ms`);
        }
      }),
      catchError((error) => {
        const duration = Date.now() - startTime;
        const statusCode = error.status || 500;
        
        // Record failed API performance
        this.metricsService.recordApiPerformance(
          endpoint,
          method,
          statusCode,
          duration,
          {
            error: error.message,
            userAgent: request.headers['user-agent'],
            ip: request.ip,
            userId: request.user?.id,
          },
        );
        
        // Track authentication failures
        this.trackAuthenticationFailure(endpoint, method, error);
        
        throw error;
      }),
    );
  }
  
  private normalizeEndpoint(url: string): string {
    // Remove query parameters
    const baseUrl = url.split('?')[0];
    
    // Replace dynamic path parameters with placeholders
    return baseUrl
      .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:id') // UUIDs
      .replace(/\/\d+/g, '/:id') // Numeric IDs
      .replace(/\/auth\/google\/callback.*/, '/auth/google/callback') // OAuth callbacks
      .replace(/\/auth\/apple\/callback.*/, '/auth/apple/callback');
  }
  
  private trackAuthenticationMetrics(
    endpoint: string,
    method: string,
    statusCode: number,
    data: any,
  ): void {
    // Skip non-successful responses
    if (statusCode >= 300) return;
    
    switch (endpoint) {
      case '/auth/register':
        if (method === 'POST') {
          this.metricsService.recordAuthSuccess('register', undefined, {
            email: data?.user?.email,
          });
        }
        break;
        
      case '/auth/login':
        if (method === 'POST') {
          this.metricsService.recordAuthSuccess('login', undefined, {
            email: data?.user?.email,
          });
        }
        break;
        
      case '/auth/refresh':
        if (method === 'POST') {
          this.metricsService.recordAuthSuccess('refresh');
        }
        break;
        
      case '/auth/google/callback':
        if (method === 'GET') {
          this.metricsService.recordAuthSuccess('oauth', 'google', {
            email: data?.user?.email,
          });
        }
        break;
        
      case '/auth/apple/callback':
        if (method === 'POST') {
          this.metricsService.recordAuthSuccess('oauth', 'apple', {
            email: data?.user?.email,
          });
        }
        break;
        
      case '/auth/logout':
        if (method === 'POST') {
          this.metricsService.increment('auth.logout');
        }
        break;
    }
  }
  
  private trackAuthenticationFailure(
    endpoint: string,
    method: string,
    error: any,
  ): void {
    const reason = this.extractFailureReason(error);
    
    switch (endpoint) {
      case '/auth/register':
        if (method === 'POST') {
          this.metricsService.recordAuthFailure('register', reason);
        }
        break;
        
      case '/auth/login':
        if (method === 'POST') {
          this.metricsService.recordAuthFailure('login', reason);
          
          // Track potential brute force
          if (reason === 'invalid_credentials') {
            this.checkBruteForce(error);
          }
        }
        break;
        
      case '/auth/refresh':
        if (method === 'POST') {
          this.metricsService.recordAuthFailure('refresh', reason);
          
          // Track suspicious token activity
          if (reason === 'invalid_token') {
            this.metricsService.recordSecurityEvent('invalid_token', {
              endpoint,
              error: error.message,
            });
          }
        }
        break;
        
      case '/auth/google/callback':
        if (method === 'GET') {
          this.metricsService.recordAuthFailure('oauth', reason, 'google');
        }
        break;
        
      case '/auth/apple/callback':
        if (method === 'POST') {
          this.metricsService.recordAuthFailure('oauth', reason, 'apple');
        }
        break;
    }
  }
  
  private extractFailureReason(error: any): string {
    if (error.status === 401) {
      return 'invalid_credentials';
    }
    
    if (error.status === 403) {
      return 'forbidden';
    }
    
    if (error.status === 429) {
      this.metricsService.recordSecurityEvent('rate_limit');
      return 'rate_limit';
    }
    
    if (error.status === 400) {
      if (error.message?.includes('email')) {
        return 'invalid_email';
      }
      if (error.message?.includes('password')) {
        return 'invalid_password';
      }
      if (error.message?.includes('validation')) {
        return 'validation_error';
      }
      return 'bad_request';
    }
    
    if (error.status === 409) {
      return 'duplicate_user';
    }
    
    if (error.message?.includes('token')) {
      return 'invalid_token';
    }
    
    if (error.message?.includes('expired')) {
      return 'expired';
    }
    
    return 'unknown';
  }
  
  private checkBruteForce(error: any): void {
    // This is a simplified check - in production, you'd want more sophisticated detection
    const metadata = error.response?.metadata;
    
    if (metadata?.failedAttempts > 5) {
      this.metricsService.recordSecurityEvent('brute_force', {
        ip: metadata.ip,
        attempts: metadata.failedAttempts,
      });
    }
  }
}