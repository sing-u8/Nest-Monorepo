import { Injectable, HttpStatus } from '@nestjs/common';
import { Request } from 'express';

// DTOs
import { ErrorResponseDto, ValidationErrorDto } from '../controllers/dtos/common.dto';

export interface ErrorContext {
  correlationId?: string;
  userId?: string;
  sessionId?: string;
  requestId?: string;
  userAgent?: string;
  ipAddress?: string;
  [key: string]: any;
}

@Injectable()
export class ErrorPresenter {
  /**
   * Present generic error response
   */
  presentError(
    error: Error,
    statusCode: number,
    path: string,
    context?: ErrorContext,
    timestamp: Date = new Date(),
  ): ErrorResponseDto {
    const errorCode = this.mapErrorToCode(error);
    const shouldIncludeDetails = this.shouldIncludeErrorDetails(error, statusCode);

    return {
      statusCode,
      message: this.sanitizeErrorMessage(error.message, statusCode),
      error: errorCode,
      timestamp: timestamp.toISOString(),
      path,
      ...(shouldIncludeDetails && context && { details: this.sanitizeContext(context) }),
    };
  }

  /**
   * Present validation error response
   */
  presentValidationError(
    validationErrors: ValidationErrorDto[],
    path: string,
    timestamp: Date = new Date(),
  ): ErrorResponseDto {
    return {
      statusCode: HttpStatus.UNPROCESSABLE_ENTITY,
      message: 'Validation failed',
      error: 'VALIDATION_ERROR',
      timestamp: timestamp.toISOString(),
      path,
      validationErrors: validationErrors.map(error => ({
        field: error.field,
        message: this.sanitizeErrorMessage(error.message),
        ...(error.constraint && { constraint: error.constraint }),
        ...(error.value !== undefined && { value: this.sanitizeValue(error.value) }),
      })),
    };
  }

  /**
   * Present authentication error
   */
  presentAuthenticationError(
    message: string = 'Authentication failed',
    path: string,
    context?: ErrorContext,
    timestamp: Date = new Date(),
  ): ErrorResponseDto {
    return {
      statusCode: HttpStatus.UNAUTHORIZED,
      message,
      error: 'AUTHENTICATION_FAILED',
      timestamp: timestamp.toISOString(),
      path,
      ...(context && { details: this.sanitizeContext(context) }),
    };
  }

  /**
   * Present authorization error
   */
  presentAuthorizationError(
    message: string = 'Access denied',
    path: string,
    requiredPermission?: string,
    timestamp: Date = new Date(),
  ): ErrorResponseDto {
    return {
      statusCode: HttpStatus.FORBIDDEN,
      message,
      error: 'ACCESS_DENIED',
      timestamp: timestamp.toISOString(),
      path,
      ...(requiredPermission && { 
        details: { requiredPermission } 
      }),
    };
  }

  /**
   * Present rate limit error
   */
  presentRateLimitError(
    path: string,
    limit: number,
    windowMs: number,
    retryAfter?: number,
    timestamp: Date = new Date(),
  ): ErrorResponseDto {
    return {
      statusCode: HttpStatus.TOO_MANY_REQUESTS,
      message: `Too many requests. Limit: ${limit} requests per ${windowMs / 1000} seconds`,
      error: 'RATE_LIMIT_EXCEEDED',
      timestamp: timestamp.toISOString(),
      path,
      details: {
        limit,
        windowMs,
        ...(retryAfter && { retryAfter }),
      },
    };
  }

  /**
   * Present not found error
   */
  presentNotFoundError(
    resource: string,
    path: string,
    timestamp: Date = new Date(),
  ): ErrorResponseDto {
    return {
      statusCode: HttpStatus.NOT_FOUND,
      message: `${resource} not found`,
      error: 'NOT_FOUND',
      timestamp: timestamp.toISOString(),
      path,
    };
  }

  /**
   * Present conflict error (e.g., duplicate resources)
   */
  presentConflictError(
    message: string,
    path: string,
    conflictingField?: string,
    timestamp: Date = new Date(),
  ): ErrorResponseDto {
    return {
      statusCode: HttpStatus.CONFLICT,
      message,
      error: 'CONFLICT',
      timestamp: timestamp.toISOString(),
      path,
      ...(conflictingField && { 
        details: { conflictingField } 
      }),
    };
  }

  /**
   * Present internal server error
   */
  presentInternalServerError(
    path: string,
    correlationId?: string,
    timestamp: Date = new Date(),
  ): ErrorResponseDto {
    return {
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
      message: 'Internal server error',
      error: 'INTERNAL_SERVER_ERROR',
      timestamp: timestamp.toISOString(),
      path,
      ...(correlationId && { 
        details: { correlationId } 
      }),
    };
  }

  /**
   * Present bad request error
   */
  presentBadRequestError(
    message: string,
    path: string,
    details?: Record<string, any>,
    timestamp: Date = new Date(),
  ): ErrorResponseDto {
    return {
      statusCode: HttpStatus.BAD_REQUEST,
      message,
      error: 'BAD_REQUEST',
      timestamp: timestamp.toISOString(),
      path,
      ...(details && { details: this.sanitizeContext(details) }),
    };
  }

  /**
   * Present service unavailable error
   */
  presentServiceUnavailableError(
    service: string,
    path: string,
    retryAfter?: number,
    timestamp: Date = new Date(),
  ): ErrorResponseDto {
    return {
      statusCode: HttpStatus.SERVICE_UNAVAILABLE,
      message: `${service} service is currently unavailable`,
      error: 'SERVICE_UNAVAILABLE',
      timestamp: timestamp.toISOString(),
      path,
      ...(retryAfter && { 
        details: { retryAfter } 
      }),
    };
  }

  /**
   * Extract error context from request
   */
  extractErrorContext(request: Request): ErrorContext {
    return {
      correlationId: request.headers['x-correlation-id'] as string,
      requestId: request.headers['x-request-id'] as string,
      userAgent: request.headers['user-agent'],
      ipAddress: this.extractIpAddress(request),
      userId: (request as any).user?.userId,
      sessionId: (request as any).user?.sessionId,
    };
  }

  /**
   * Map domain errors to HTTP status codes
   */
  mapErrorToStatusCode(error: Error): number {
    const errorName = error.constructor.name;
    
    const statusCodeMap: Record<string, number> = {
      // Authentication & Authorization
      'InvalidCredentialsError': HttpStatus.UNAUTHORIZED,
      'UserNotActiveError': HttpStatus.FORBIDDEN,
      'InvalidRefreshTokenError': HttpStatus.UNAUTHORIZED,
      'TokenExpiredError': HttpStatus.UNAUTHORIZED,
      'UnauthorizedError': HttpStatus.UNAUTHORIZED,
      'ForbiddenError': HttpStatus.FORBIDDEN,
      
      // User Management
      'UserAlreadyExistsError': HttpStatus.CONFLICT,
      'UserNotFoundError': HttpStatus.NOT_FOUND,
      'InvalidEmailError': HttpStatus.BAD_REQUEST,
      'InvalidPasswordError': HttpStatus.BAD_REQUEST,
      'InvalidNameError': HttpStatus.BAD_REQUEST,
      
      // OAuth
      'UnsupportedProviderError': HttpStatus.BAD_REQUEST,
      'OAuthAuthorizationError': HttpStatus.BAD_REQUEST,
      'OAuthUserInfoError': HttpStatus.BAD_REQUEST,
      'GoogleOAuthError': HttpStatus.BAD_REQUEST,
      'AppleOAuthError': HttpStatus.BAD_REQUEST,
      
      // Profile
      'NoChangesError': HttpStatus.BAD_REQUEST,
      'InvalidProfilePictureUrlError': HttpStatus.BAD_REQUEST,
      
      // Session
      'InvalidSessionError': HttpStatus.UNAUTHORIZED,
      'SessionExpiredError': HttpStatus.UNAUTHORIZED,
      
      // Validation
      'ValidationError': HttpStatus.UNPROCESSABLE_ENTITY,
      
      // Generic
      'NotFoundError': HttpStatus.NOT_FOUND,
      'ConflictError': HttpStatus.CONFLICT,
    };

    return statusCodeMap[errorName] || HttpStatus.INTERNAL_SERVER_ERROR;
  }

  /**
   * Map domain errors to API error codes
   */
  private mapErrorToCode(error: Error): string {
    const errorName = error.constructor.name;
    
    const errorCodeMap: Record<string, string> = {
      // User Registration Errors
      'UserAlreadyExistsError': 'USER_ALREADY_EXISTS',
      'InvalidEmailError': 'INVALID_EMAIL',
      'InvalidPasswordError': 'INVALID_PASSWORD',
      'InvalidNameError': 'INVALID_NAME',
      
      // Authentication Errors
      'InvalidCredentialsError': 'INVALID_CREDENTIALS',
      'UserNotFoundError': 'USER_NOT_FOUND',
      'UserNotActiveError': 'USER_NOT_ACTIVE',
      
      // Token Errors
      'InvalidRefreshTokenError': 'INVALID_REFRESH_TOKEN',
      'TokenExpiredError': 'TOKEN_EXPIRED',
      'InvalidTokenError': 'INVALID_TOKEN',
      
      // Social Login Errors
      'UnsupportedProviderError': 'UNSUPPORTED_PROVIDER',
      'OAuthAuthorizationError': 'OAUTH_AUTHORIZATION_ERROR',
      'OAuthUserInfoError': 'OAUTH_USER_INFO_ERROR',
      'GoogleOAuthError': 'GOOGLE_OAUTH_ERROR',
      'GoogleTokenExchangeError': 'GOOGLE_TOKEN_EXCHANGE_ERROR',
      'GoogleUserInfoError': 'GOOGLE_USER_INFO_ERROR',
      'AppleOAuthError': 'APPLE_OAUTH_ERROR',
      'AppleTokenVerificationError': 'APPLE_TOKEN_VERIFICATION_ERROR',
      'AppleUserInfoExtractionError': 'APPLE_USER_INFO_EXTRACTION_ERROR',
      
      // Profile Errors
      'NoChangesError': 'NO_CHANGES_DETECTED',
      'InvalidProfilePictureUrlError': 'INVALID_PROFILE_PICTURE_URL',
      
      // Session Errors
      'InvalidSessionError': 'INVALID_SESSION',
      'SessionExpiredError': 'SESSION_EXPIRED',
      
      // Generic Errors
      'ValidationError': 'VALIDATION_ERROR',
      'NotFoundError': 'NOT_FOUND',
      'UnauthorizedError': 'UNAUTHORIZED',
      'ForbiddenError': 'FORBIDDEN',
      'ConflictError': 'CONFLICT',
    };

    return errorCodeMap[errorName] || 'INTERNAL_SERVER_ERROR';
  }

  /**
   * Sanitize error message for client consumption
   */
  private sanitizeErrorMessage(message: string, statusCode?: number): string {
    // For internal server errors, don't expose internal details
    if (statusCode === HttpStatus.INTERNAL_SERVER_ERROR) {
      return 'An internal error occurred. Please try again later.';
    }

    // Remove sensitive information patterns
    const sensitivePatterns = [
      /password/gi,
      /secret/gi,
      /key/gi,
      /token/gi,
      /connection string/gi,
      /database/gi,
    ];

    let sanitized = message;
    sensitivePatterns.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
    });

    return sanitized;
  }

  /**
   * Sanitize error context to remove sensitive information
   */
  private sanitizeContext(context: ErrorContext): Record<string, any> {
    const sanitized = { ...context };
    
    // Remove sensitive fields
    const sensitiveFields = ['password', 'secret', 'key', 'token'];
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });

    // Truncate user agent to prevent log pollution
    if (sanitized.userAgent && sanitized.userAgent.length > 200) {
      sanitized.userAgent = sanitized.userAgent.substring(0, 200) + '...';
    }

    return sanitized;
  }

  /**
   * Sanitize validation error values
   */
  private sanitizeValue(value: any): any {
    if (typeof value === 'string') {
      // Don't expose passwords or other sensitive data
      if (value.length > 50) {
        return `[${typeof value}:${value.length}chars]`;
      }
    }
    
    return value;
  }

  /**
   * Determine if error details should be included in response
   */
  private shouldIncludeErrorDetails(error: Error, statusCode: number): boolean {
    // Don't include details for internal server errors in production
    if (statusCode === HttpStatus.INTERNAL_SERVER_ERROR) {
      return process.env.NODE_ENV !== 'production';
    }

    // Include details for client errors
    return statusCode >= 400 && statusCode < 500;
  }

  /**
   * Extract client IP address
   */
  private extractIpAddress(request: Request): string {
    const forwarded = request.headers['x-forwarded-for'] as string;
    const realIp = request.headers['x-real-ip'] as string;
    
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
    
    if (realIp) {
      return realIp;
    }
    
    return request.connection.remoteAddress || 
           request.socket.remoteAddress || 
           'Unknown';
  }
}