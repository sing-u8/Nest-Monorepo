import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '@auth/infrastructure';

/**
 * Global Exception Filter
 * 
 * Catches all exceptions across the application and formats them consistently.
 * Provides proper error responses with appropriate logging and error tracking.
 */
@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  constructor(private configService: ConfigService) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const config = this.configService.get<AppConfig>('app');

    // Determine HTTP status code
    const status = exception instanceof HttpException
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    // Extract error message and details
    const errorResponse = this.getErrorResponse(exception, status);
    
    // Generate error ID for tracking
    const errorId = this.generateErrorId();
    
    // Create standardized error response
    const errorResponseBody = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      method: request.method,
      errorId,
      message: errorResponse.message,
      error: errorResponse.error,
      ...(config?.NODE_ENV !== 'production' && {
        details: errorResponse.details,
        stack: errorResponse.stack,
      }),
    };

    // Log the error with appropriate level
    this.logError(exception, request, errorId, status);

    // Send the response
    response.status(status).json(errorResponseBody);
  }

  /**
   * Extract error response from exception
   */
  private getErrorResponse(exception: unknown, status: number) {
    if (exception instanceof HttpException) {
      const response = exception.getResponse();
      
      if (typeof response === 'string') {
        return {
          message: response,
          error: exception.name,
          details: null,
          stack: exception.stack,
        };
      }
      
      if (typeof response === 'object' && response !== null) {
        return {
          message: (response as any).message || exception.message,
          error: (response as any).error || exception.name,
          details: response,
          stack: exception.stack,
        };
      }
    }

    if (exception instanceof Error) {
      return {
        message: exception.message,
        error: exception.name,
        details: null,
        stack: exception.stack,
      };
    }

    return {
      message: 'Internal server error',
      error: 'UnknownError',
      details: exception,
      stack: null,
    };
  }

  /**
   * Log error with appropriate level and context
   */
  private logError(
    exception: unknown,
    request: Request,
    errorId: string,
    status: number
  ): void {
    const logContext = {
      errorId,
      method: request.method,
      url: request.url,
      userAgent: request.get('User-Agent'),
      ip: request.ip,
      userId: (request as any).user?.id || 'anonymous',
      requestId: request.get('X-Request-ID'),
    };

    const logMessage = `${status} Error: ${this.getErrorMessage(exception)}`;

    if (status >= 500) {
      this.logger.error(logMessage, {
        ...logContext,
        stack: exception instanceof Error ? exception.stack : undefined,
        exception,
      });
    } else if (status >= 400) {
      this.logger.warn(logMessage, logContext);
    } else {
      this.logger.log(logMessage, logContext);
    }
  }

  /**
   * Get error message from exception
   */
  private getErrorMessage(exception: unknown): string {
    if (exception instanceof Error) {
      return exception.message;
    }
    
    if (typeof exception === 'string') {
      return exception;
    }
    
    return 'Unknown error occurred';
  }

  /**
   * Generate unique error ID for tracking
   */
  private generateErrorId(): string {
    return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}