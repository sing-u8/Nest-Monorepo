import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '@auth/infrastructure';

/**
 * Logging Interceptor
 * 
 * Logs all HTTP requests and responses with performance metrics.
 * Provides structured logging for monitoring and debugging.
 */
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  constructor(private configService: ConfigService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const config = this.configService.get<AppConfig>('app');
    
    // Skip logging in test environment
    if (config?.NODE_ENV === 'test') {
      return next.handle();
    }

    const startTime = Date.now();
    const ctx = context.switchToHttp();
    const request = ctx.getRequest<Request>();
    const response = ctx.getResponse<Response>();

    // Generate request ID if not present
    const requestId = request.get('X-Request-ID') || this.generateRequestId();
    
    // Add request ID to response headers
    response.set('X-Request-ID', requestId);

    // Extract request information
    const requestInfo = this.extractRequestInfo(request, requestId);

    // Log incoming request
    this.logRequest(requestInfo);

    return next.handle().pipe(
      tap(() => {
        // Log successful response
        const duration = Date.now() - startTime;
        this.logResponse(requestInfo, response.statusCode, duration, 'success');
      }),
      catchError((error) => {
        // Log error response
        const duration = Date.now() - startTime;
        const statusCode = error.status || 500;
        this.logResponse(requestInfo, statusCode, duration, 'error', error);
        throw error;
      })
    );
  }

  /**
   * Extract request information for logging
   */
  private extractRequestInfo(request: Request, requestId: string) {
    return {
      requestId,
      method: request.method,
      url: request.url,
      path: request.path,
      query: request.query,
      userAgent: request.get('User-Agent'),
      ip: request.ip,
      contentLength: request.get('Content-Length'),
      contentType: request.get('Content-Type'),
      authorization: request.get('Authorization') ? 'Bearer ***' : undefined,
      userId: (request as any).user?.id || 'anonymous',
      sessionId: (request as any).session?.id,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Log incoming request
   */
  private logRequest(requestInfo: any): void {
    const { method, path, requestId, userId, ip, userAgent } = requestInfo;
    
    this.logger.log(`→ ${method} ${path}`, {
      type: 'request',
      requestId,
      method,
      path,
      userId,
      ip,
      userAgent,
      timestamp: requestInfo.timestamp,
    });
  }

  /**
   * Log response with performance metrics
   */
  private logResponse(
    requestInfo: any,
    statusCode: number,
    duration: number,
    type: 'success' | 'error',
    error?: any
  ): void {
    const { method, path, requestId, userId } = requestInfo;
    
    const logLevel = this.getLogLevel(statusCode);
    const statusEmoji = this.getStatusEmoji(statusCode);
    
    const logMessage = `← ${statusEmoji} ${method} ${path} ${statusCode} ${duration}ms`;
    
    const logContext = {
      type: 'response',
      requestId,
      method,
      path,
      statusCode,
      duration,
      userId,
      responseType: type,
      ...(error && { error: error.message }),
    };

    switch (logLevel) {
      case 'error':
        this.logger.error(logMessage, logContext);
        break;
      case 'warn':
        this.logger.warn(logMessage, logContext);
        break;
      case 'log':
      default:
        this.logger.log(logMessage, logContext);
        break;
    }

    // Log slow requests
    if (duration > 1000) {
      this.logger.warn(`Slow request detected: ${method} ${path} took ${duration}ms`, {
        type: 'performance',
        requestId,
        method,
        path,
        duration,
        userId,
      });
    }
  }

  /**
   * Determine log level based on status code
   */
  private getLogLevel(statusCode: number): 'error' | 'warn' | 'log' {
    if (statusCode >= 500) {
      return 'error';
    } else if (statusCode >= 400) {
      return 'warn';
    } else {
      return 'log';
    }
  }

  /**
   * Get emoji for status code
   */
  private getStatusEmoji(statusCode: number): string {
    if (statusCode >= 200 && statusCode < 300) {
      return '✅';
    } else if (statusCode >= 300 && statusCode < 400) {
      return '🔄';
    } else if (statusCode >= 400 && statusCode < 500) {
      return '⚠️';
    } else {
      return '❌';
    }
  }

  /**
   * Generate unique request ID
   */
  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}