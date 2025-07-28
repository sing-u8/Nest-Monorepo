import { Injectable } from '@nestjs/common';
import { ErrorResponse } from '@auth/shared';

/**
 * Error Presenter
 * 
 * Provides consistent error formatting across the authentication system.
 * This presenter standardizes error responses and provides helpful
 * error messages and suggestions for common error scenarios.
 * 
 * All error responses follow a consistent format:
 * - success: false
 * - error: string (error code)
 * - message: string (user-friendly message)
 * - details?: any (additional error information)
 */
@Injectable()
export class ErrorPresenter {

  // HTTP Error Presenters

  presentBadRequest(message: string, details?: any): ErrorResponse {
    return {
      success: false,
      error: 'BAD_REQUEST',
      message: message || 'The request is invalid',
      details: {
        ...details,
        statusCode: 400,
        suggestion: 'Please check your request data and try again',
      },
    };
  }

  presentUnauthorized(message?: string, details?: any): ErrorResponse {
    return {
      success: false,
      error: 'UNAUTHORIZED',
      message: message || 'Authentication required',
      details: {
        ...details,
        statusCode: 401,
        suggestion: 'Please log in to access this resource',
      },
    };
  }

  presentForbidden(message?: string, details?: any): ErrorResponse {
    return {
      success: false,
      error: 'FORBIDDEN',
      message: message || 'Access denied',
      details: {
        ...details,
        statusCode: 403,
        suggestion: 'You do not have permission to access this resource',
      },
    };
  }

  presentNotFound(resource: string, identifier?: string): ErrorResponse {
    return {
      success: false,
      error: 'NOT_FOUND',
      message: `${resource} not found`,
      details: {
        resource,
        identifier,
        statusCode: 404,
        suggestion: `Please check the ${resource.toLowerCase()} identifier and try again`,
      },
    };
  }

  presentConflict(message: string, details?: any): ErrorResponse {
    return {
      success: false,
      error: 'CONFLICT',
      message: message || 'Resource conflict',
      details: {
        ...details,
        statusCode: 409,
        suggestion: 'The resource already exists or conflicts with existing data',
      },
    };
  }

  presentUnprocessableEntity(message: string, details?: any): ErrorResponse {
    return {
      success: false,
      error: 'UNPROCESSABLE_ENTITY',
      message: message || 'The request contains invalid data',
      details: {
        ...details,
        statusCode: 422,
        suggestion: 'Please correct the validation errors and try again',
      },
    };
  }

  presentTooManyRequests(retryAfter?: number): ErrorResponse {
    return {
      success: false,
      error: 'TOO_MANY_REQUESTS',
      message: 'Too many requests. Please try again later.',
      details: {
        statusCode: 429,
        retryAfter,
        retryAfterFormatted: retryAfter ? this.formatRetryAfter(retryAfter) : undefined,
        suggestion: 'Please wait before making another request',
      },
    };
  }

  presentInternalServerError(message?: string, details?: any): ErrorResponse {
    return {
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: message || 'An unexpected error occurred',
      details: {
        ...details,
        statusCode: 500,
        suggestion: 'Please try again later. If the problem persists, contact support.',
      },
    };
  }

  presentServiceUnavailable(message?: string, details?: any): ErrorResponse {
    return {
      success: false,
      error: 'SERVICE_UNAVAILABLE',
      message: message || 'Service temporarily unavailable',
      details: {
        ...details,
        statusCode: 503,
        suggestion: 'The service is temporarily down. Please try again later.',
      },
    };
  }

  // Validation Error Presenters

  presentValidationErrors(errors: Record<string, string[]>): ErrorResponse {
    const formattedErrors = Object.entries(errors).map(([field, messages]) => ({
      field,
      messages,
    }));

    return {
      success: false,
      error: 'VALIDATION_ERROR',
      message: 'Data validation failed',
      details: {
        errors: formattedErrors,
        totalErrors: formattedErrors.length,
        suggestion: 'Please correct the validation errors and try again',
      },
    };
  }

  presentFieldValidationError(field: string, message: string, value?: any): ErrorResponse {
    return {
      success: false,
      error: 'FIELD_VALIDATION_ERROR',
      message: `Validation failed for field: ${field}`,
      details: {
        field,
        message,
        value,
        suggestion: 'Please correct the field value and try again',
      },
    };
  }

  presentMissingRequiredField(field: string): ErrorResponse {
    return {
      success: false,
      error: 'MISSING_REQUIRED_FIELD',
      message: `Required field is missing: ${field}`,
      details: {
        field,
        suggestion: `Please provide a value for the ${field} field`,
      },
    };
  }

  // Business Logic Error Presenters

  presentBusinessRuleViolation(rule: string, message: string, details?: any): ErrorResponse {
    return {
      success: false,
      error: 'BUSINESS_RULE_VIOLATION',
      message: message || `Business rule violation: ${rule}`,
      details: {
        rule,
        ...details,
        suggestion: 'Please review the requirements and try again',
      },
    };
  }

  presentResourceLimitExceeded(resource: string, limit: number, current: number): ErrorResponse {
    return {
      success: false,
      error: 'RESOURCE_LIMIT_EXCEEDED',
      message: `${resource} limit exceeded`,
      details: {
        resource,
        limit,
        current,
        suggestion: `Please reduce ${resource.toLowerCase()} usage or upgrade your plan`,
      },
    };
  }

  presentOperationNotAllowed(operation: string, reason?: string): ErrorResponse {
    return {
      success: false,
      error: 'OPERATION_NOT_ALLOWED',
      message: `Operation not allowed: ${operation}`,
      details: {
        operation,
        reason,
        suggestion: 'Please check the operation requirements and try again',
      },
    };
  }

  // External Service Error Presenters

  presentExternalServiceError(service: string, error: string): ErrorResponse {
    return {
      success: false,
      error: 'EXTERNAL_SERVICE_ERROR',
      message: `External service error: ${service}`,
      details: {
        service,
        error,
        suggestion: 'The external service is experiencing issues. Please try again later.',
      },
    };
  }

  presentServiceTimeout(service: string, timeout: number): ErrorResponse {
    return {
      success: false,
      error: 'SERVICE_TIMEOUT',
      message: `Service timeout: ${service}`,
      details: {
        service,
        timeout,
        suggestion: 'The service took too long to respond. Please try again.',
      },
    };
  }

  // Database Error Presenters

  presentDatabaseError(operation: string, error?: string): ErrorResponse {
    return {
      success: false,
      error: 'DATABASE_ERROR',
      message: `Database operation failed: ${operation}`,
      details: {
        operation,
        error,
        suggestion: 'Please try again. If the problem persists, contact support.',
      },
    };
  }

  presentDatabaseConnectionError(): ErrorResponse {
    return {
      success: false,
      error: 'DATABASE_CONNECTION_ERROR',
      message: 'Unable to connect to the database',
      details: {
        suggestion: 'The service is temporarily unavailable. Please try again later.',
      },
    };
  }

  // Security Error Presenters

  presentSecurityViolation(violation: string, details?: any): ErrorResponse {
    return {
      success: false,
      error: 'SECURITY_VIOLATION',
      message: 'Security violation detected',
      details: {
        violation,
        ...details,
        suggestion: 'Please ensure you are using the service properly',
      },
    };
  }

  presentSuspiciousActivity(activity: string, details?: any): ErrorResponse {
    return {
      success: false,
      error: 'SUSPICIOUS_ACTIVITY',
      message: 'Suspicious activity detected',
      details: {
        activity,
        ...details,
        suggestion: 'Your account may be temporarily restricted for security reasons',
      },
    };
  }

  // Generic Error Presenter

  presentGenericError(code: string, message: string, details?: any): ErrorResponse {
    return {
      success: false,
      error: code,
      message,
      details: {
        ...details,
        suggestion: 'Please try again or contact support if the problem persists',
      },
    };
  }

  // Helper Methods

  private formatRetryAfter(seconds: number): string {
    if (seconds < 60) {
      return `${seconds} seconds`;
    } else if (seconds < 3600) {
      const minutes = Math.ceil(seconds / 60);
      return `${minutes} minute${minutes > 1 ? 's' : ''}`;
    } else {
      const hours = Math.ceil(seconds / 3600);
      return `${hours} hour${hours > 1 ? 's' : ''}`;
    }
  }

  // Format file size for error messages
  formatFileSize(bytes: number): string {
    if (bytes < 1024) {
      return `${bytes} bytes`;
    } else if (bytes < 1024 * 1024) {
      return `${Math.round(bytes / 1024)} KB`;
    } else {
      return `${Math.round(bytes / (1024 * 1024))} MB`;
    }
  }

  // Format duration for error messages
  formatDuration(milliseconds: number): string {
    if (milliseconds < 1000) {
      return `${milliseconds}ms`;
    } else if (milliseconds < 60000) {
      return `${Math.round(milliseconds / 1000)}s`;
    } else {
      return `${Math.round(milliseconds / 60000)}m`;
    }
  }
}