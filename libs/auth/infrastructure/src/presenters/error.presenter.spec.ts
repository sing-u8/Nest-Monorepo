import { Test, TestingModule } from '@nestjs/testing';
import { ErrorPresenter } from './error.presenter';
import { ErrorResponse } from '@auth/shared';

describe('ErrorPresenter', () => {
  let presenter: ErrorPresenter;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ErrorPresenter],
    }).compile();

    presenter = module.get<ErrorPresenter>(ErrorPresenter);
  });

  describe('HTTP Error Presenters', () => {
    describe('presentBadRequest', () => {
      it('should present bad request error with details', () => {
        const result = presenter.presentBadRequest('Invalid JSON format', { field: 'body' });

        expect(result).toEqual({
          success: false,
          error: 'BAD_REQUEST',
          message: 'Invalid JSON format',
          details: {
            field: 'body',
            statusCode: 400,
            suggestion: 'Please check your request data and try again',
          },
        });
      });

      it('should present bad request error without details', () => {
        const result = presenter.presentBadRequest('Invalid request');

        expect(result).toEqual({
          success: false,
          error: 'BAD_REQUEST',
          message: 'Invalid request',
          details: {
            statusCode: 400,
            suggestion: 'Please check your request data and try again',
          },
        });
      });

      it('should use default message if not provided', () => {
        const result = presenter.presentBadRequest('');

        expect(result.message).toBe('The request is invalid');
      });
    });

    describe('presentUnauthorized', () => {
      it('should present unauthorized error with custom message', () => {
        const result = presenter.presentUnauthorized('Token expired', { tokenId: 'token-123' });

        expect(result).toEqual({
          success: false,
          error: 'UNAUTHORIZED',
          message: 'Token expired',
          details: {
            tokenId: 'token-123',
            statusCode: 401,
            suggestion: 'Please log in to access this resource',
          },
        });
      });

      it('should present unauthorized error with default message', () => {
        const result = presenter.presentUnauthorized();

        expect(result).toEqual({
          success: false,
          error: 'UNAUTHORIZED',
          message: 'Authentication required',
          details: {
            statusCode: 401,
            suggestion: 'Please log in to access this resource',
          },
        });
      });
    });

    describe('presentForbidden', () => {
      it('should present forbidden error', () => {
        const result = presenter.presentForbidden('Insufficient permissions');

        expect(result).toEqual({
          success: false,
          error: 'FORBIDDEN',
          message: 'Insufficient permissions',
          details: {
            statusCode: 403,
            suggestion: 'You do not have permission to access this resource',
          },
        });
      });

      it('should use default message if not provided', () => {
        const result = presenter.presentForbidden();

        expect(result.message).toBe('Access denied');
      });
    });

    describe('presentNotFound', () => {
      it('should present not found error with identifier', () => {
        const result = presenter.presentNotFound('User', 'user-123');

        expect(result).toEqual({
          success: false,
          error: 'NOT_FOUND',
          message: 'User not found',
          details: {
            resource: 'User',
            identifier: 'user-123',
            statusCode: 404,
            suggestion: 'Please check the user identifier and try again',
          },
        });
      });

      it('should present not found error without identifier', () => {
        const result = presenter.presentNotFound('Session');

        expect(result).toEqual({
          success: false,
          error: 'NOT_FOUND',
          message: 'Session not found',
          details: {
            resource: 'Session',
            identifier: undefined,
            statusCode: 404,
            suggestion: 'Please check the session identifier and try again',
          },
        });
      });
    });

    describe('presentConflict', () => {
      it('should present conflict error', () => {
        const result = presenter.presentConflict('Email already exists', { email: 'user@example.com' });

        expect(result).toEqual({
          success: false,
          error: 'CONFLICT',
          message: 'Email already exists',
          details: {
            email: 'user@example.com',
            statusCode: 409,
            suggestion: 'The resource already exists or conflicts with existing data',
          },
        });
      });

      it('should use default message if not provided', () => {
        const result = presenter.presentConflict('');

        expect(result.message).toBe('Resource conflict');
      });
    });

    describe('presentTooManyRequests', () => {
      it('should present too many requests error with retry after', () => {
        const result = presenter.presentTooManyRequests(120);

        expect(result).toEqual({
          success: false,
          error: 'TOO_MANY_REQUESTS',
          message: 'Too many requests. Please try again later.',
          details: {
            statusCode: 429,
            retryAfter: 120,
            retryAfterFormatted: '2 minutes',
            suggestion: 'Please wait before making another request',
          },
        });
      });

      it('should present too many requests error without retry after', () => {
        const result = presenter.presentTooManyRequests();

        expect(result).toEqual({
          success: false,
          error: 'TOO_MANY_REQUESTS',
          message: 'Too many requests. Please try again later.',
          details: {
            statusCode: 429,
            retryAfter: undefined,
            retryAfterFormatted: undefined,
            suggestion: 'Please wait before making another request',
          },
        });
      });
    });

    describe('presentInternalServerError', () => {
      it('should present internal server error with custom message', () => {
        const result = presenter.presentInternalServerError('Database connection failed', { service: 'database' });

        expect(result).toEqual({
          success: false,
          error: 'INTERNAL_SERVER_ERROR',
          message: 'Database connection failed',
          details: {
            service: 'database',
            statusCode: 500,
            suggestion: 'Please try again later. If the problem persists, contact support.',
          },
        });
      });

      it('should use default message if not provided', () => {
        const result = presenter.presentInternalServerError();

        expect(result.message).toBe('An unexpected error occurred');
      });
    });

    describe('presentServiceUnavailable', () => {
      it('should present service unavailable error', () => {
        const result = presenter.presentServiceUnavailable('Maintenance mode');

        expect(result).toEqual({
          success: false,
          error: 'SERVICE_UNAVAILABLE',
          message: 'Maintenance mode',
          details: {
            statusCode: 503,
            suggestion: 'The service is temporarily down. Please try again later.',
          },
        });
      });
    });
  });

  describe('Validation Error Presenters', () => {
    describe('presentValidationErrors', () => {
      it('should present validation errors', () => {
        const errors = {
          email: ['Invalid email format', 'Email is required'],
          password: ['Password is too weak'],
          name: ['Name must be at least 2 characters'],
        };

        const result = presenter.presentValidationErrors(errors);

        expect(result).toEqual({
          success: false,
          error: 'VALIDATION_ERROR',
          message: 'Data validation failed',
          details: {
            errors: [
              { field: 'email', messages: ['Invalid email format', 'Email is required'] },
              { field: 'password', messages: ['Password is too weak'] },
              { field: 'name', messages: ['Name must be at least 2 characters'] },
            ],
            totalErrors: 3,
            suggestion: 'Please correct the validation errors and try again',
          },
        });
      });
    });

    describe('presentFieldValidationError', () => {
      it('should present field validation error with value', () => {
        const result = presenter.presentFieldValidationError('email', 'Invalid email format', 'invalid-email');

        expect(result).toEqual({
          success: false,
          error: 'FIELD_VALIDATION_ERROR',
          message: 'Validation failed for field: email',
          details: {
            field: 'email',
            message: 'Invalid email format',
            value: 'invalid-email',
            suggestion: 'Please correct the field value and try again',
          },
        });
      });

      it('should present field validation error without value', () => {
        const result = presenter.presentFieldValidationError('password', 'Password is required');

        expect(result).toEqual({
          success: false,
          error: 'FIELD_VALIDATION_ERROR',
          message: 'Validation failed for field: password',
          details: {
            field: 'password',
            message: 'Password is required',
            value: undefined,
            suggestion: 'Please correct the field value and try again',
          },
        });
      });
    });

    describe('presentMissingRequiredField', () => {
      it('should present missing required field error', () => {
        const result = presenter.presentMissingRequiredField('email');

        expect(result).toEqual({
          success: false,
          error: 'MISSING_REQUIRED_FIELD',
          message: 'Required field is missing: email',
          details: {
            field: 'email',
            suggestion: 'Please provide a value for the email field',
          },
        });
      });
    });
  });

  describe('Business Logic Error Presenters', () => {
    describe('presentBusinessRuleViolation', () => {
      it('should present business rule violation with custom message', () => {
        const result = presenter.presentBusinessRuleViolation(
          'MAX_SESSIONS_EXCEEDED',
          'Maximum number of concurrent sessions exceeded',
          { maxSessions: 5, currentSessions: 6 }
        );

        expect(result).toEqual({
          success: false,
          error: 'BUSINESS_RULE_VIOLATION',
          message: 'Maximum number of concurrent sessions exceeded',
          details: {
            rule: 'MAX_SESSIONS_EXCEEDED',
            maxSessions: 5,
            currentSessions: 6,
            suggestion: 'Please review the requirements and try again',
          },
        });
      });

      it('should use default message if not provided', () => {
        const result = presenter.presentBusinessRuleViolation('INVALID_OPERATION', '');

        expect(result.message).toBe('Business rule violation: INVALID_OPERATION');
      });
    });

    describe('presentResourceLimitExceeded', () => {
      it('should present resource limit exceeded error', () => {
        const result = presenter.presentResourceLimitExceeded('API requests', 1000, 1500);

        expect(result).toEqual({
          success: false,
          error: 'RESOURCE_LIMIT_EXCEEDED',
          message: 'API requests limit exceeded',
          details: {
            resource: 'API requests',
            limit: 1000,
            current: 1500,
            suggestion: 'Please reduce api requests usage or upgrade your plan',
          },
        });
      });
    });

    describe('presentOperationNotAllowed', () => {
      it('should present operation not allowed with reason', () => {
        const result = presenter.presentOperationNotAllowed('delete account', 'Account has pending transactions');

        expect(result).toEqual({
          success: false,
          error: 'OPERATION_NOT_ALLOWED',
          message: 'Operation not allowed: delete account',
          details: {
            operation: 'delete account',
            reason: 'Account has pending transactions',
            suggestion: 'Please check the operation requirements and try again',
          },
        });
      });

      it('should present operation not allowed without reason', () => {
        const result = presenter.presentOperationNotAllowed('bulk update');

        expect(result).toEqual({
          success: false,
          error: 'OPERATION_NOT_ALLOWED',
          message: 'Operation not allowed: bulk update',
          details: {
            operation: 'bulk update',
            reason: undefined,
            suggestion: 'Please check the operation requirements and try again',
          },
        });
      });
    });
  });

  describe('External Service Error Presenters', () => {
    describe('presentExternalServiceError', () => {
      it('should present external service error', () => {
        const result = presenter.presentExternalServiceError('Google OAuth', 'Token validation failed');

        expect(result).toEqual({
          success: false,
          error: 'EXTERNAL_SERVICE_ERROR',
          message: 'External service error: Google OAuth',
          details: {
            service: 'Google OAuth',
            error: 'Token validation failed',
            suggestion: 'The external service is experiencing issues. Please try again later.',
          },
        });
      });
    });

    describe('presentServiceTimeout', () => {
      it('should present service timeout error', () => {
        const result = presenter.presentServiceTimeout('Payment API', 5000);

        expect(result).toEqual({
          success: false,
          error: 'SERVICE_TIMEOUT',
          message: 'Service timeout: Payment API',
          details: {
            service: 'Payment API',
            timeout: 5000,
            suggestion: 'The service took too long to respond. Please try again.',
          },
        });
      });
    });
  });

  describe('Database Error Presenters', () => {
    describe('presentDatabaseError', () => {
      it('should present database error with error message', () => {
        const result = presenter.presentDatabaseError('INSERT', 'Duplicate key violation');

        expect(result).toEqual({
          success: false,
          error: 'DATABASE_ERROR',
          message: 'Database operation failed: INSERT',
          details: {
            operation: 'INSERT',
            error: 'Duplicate key violation',
            suggestion: 'Please try again. If the problem persists, contact support.',
          },
        });
      });

      it('should present database error without error message', () => {
        const result = presenter.presentDatabaseError('SELECT');

        expect(result).toEqual({
          success: false,
          error: 'DATABASE_ERROR',
          message: 'Database operation failed: SELECT',
          details: {
            operation: 'SELECT',
            error: undefined,
            suggestion: 'Please try again. If the problem persists, contact support.',
          },
        });
      });
    });

    describe('presentDatabaseConnectionError', () => {
      it('should present database connection error', () => {
        const result = presenter.presentDatabaseConnectionError();

        expect(result).toEqual({
          success: false,
          error: 'DATABASE_CONNECTION_ERROR',
          message: 'Unable to connect to the database',
          details: {
            suggestion: 'The service is temporarily unavailable. Please try again later.',
          },
        });
      });
    });
  });

  describe('Security Error Presenters', () => {
    describe('presentSecurityViolation', () => {
      it('should present security violation', () => {
        const result = presenter.presentSecurityViolation('SQL_INJECTION_ATTEMPT', { query: 'malicious query' });

        expect(result).toEqual({
          success: false,
          error: 'SECURITY_VIOLATION',
          message: 'Security violation detected',
          details: {
            violation: 'SQL_INJECTION_ATTEMPT',
            query: 'malicious query',
            suggestion: 'Please ensure you are using the service properly',
          },
        });
      });
    });

    describe('presentSuspiciousActivity', () => {
      it('should present suspicious activity', () => {
        const result = presenter.presentSuspiciousActivity('MULTIPLE_FAILED_LOGINS', { attempts: 10 });

        expect(result).toEqual({
          success: false,
          error: 'SUSPICIOUS_ACTIVITY',
          message: 'Suspicious activity detected',
          details: {
            activity: 'MULTIPLE_FAILED_LOGINS',
            attempts: 10,
            suggestion: 'Your account may be temporarily restricted for security reasons',
          },
        });
      });
    });
  });

  describe('Generic Error Presenter', () => {
    describe('presentGenericError', () => {
      it('should present generic error', () => {
        const result = presenter.presentGenericError('CUSTOM_ERROR', 'Something went wrong', { code: 1001 });

        expect(result).toEqual({
          success: false,
          error: 'CUSTOM_ERROR',
          message: 'Something went wrong',
          details: {
            code: 1001,
            suggestion: 'Please try again or contact support if the problem persists',
          },
        });
      });
    });
  });

  describe('Helper Methods', () => {
    describe('formatFileSize', () => {
      it('should format bytes', () => {
        expect(presenter.formatFileSize(500)).toBe('500 bytes');
      });

      it('should format kilobytes', () => {
        expect(presenter.formatFileSize(1536)).toBe('2 KB'); // 1.5KB rounded to 2KB
      });

      it('should format megabytes', () => {
        expect(presenter.formatFileSize(2097152)).toBe('2 MB'); // 2MB exactly
        expect(presenter.formatFileSize(1572864)).toBe('2 MB'); // 1.5MB rounded to 2MB
      });
    });

    describe('formatDuration', () => {
      it('should format milliseconds', () => {
        expect(presenter.formatDuration(500)).toBe('500ms');
      });

      it('should format seconds', () => {
        expect(presenter.formatDuration(1500)).toBe('2s'); // 1.5s rounded to 2s
      });

      it('should format minutes', () => {
        expect(presenter.formatDuration(90000)).toBe('2m'); // 1.5m rounded to 2m
      });
    });

    describe('formatRetryAfter', () => {
      it('should format seconds', () => {
        // Access private method through reflection
        const formatRetryAfter = (presenter as any).formatRetryAfter.bind(presenter);
        
        expect(formatRetryAfter(30)).toBe('30 seconds');
        expect(formatRetryAfter(1)).toBe('1 seconds'); // Note: doesn't handle singular
      });

      it('should format minutes', () => {
        const formatRetryAfter = (presenter as any).formatRetryAfter.bind(presenter);
        
        expect(formatRetryAfter(120)).toBe('2 minutes');
        expect(formatRetryAfter(60)).toBe('1 minute');
      });

      it('should format hours', () => {
        const formatRetryAfter = (presenter as any).formatRetryAfter.bind(presenter);
        
        expect(formatRetryAfter(7200)).toBe('2 hours');
        expect(formatRetryAfter(3600)).toBe('1 hour');
      });
    });
  });
});