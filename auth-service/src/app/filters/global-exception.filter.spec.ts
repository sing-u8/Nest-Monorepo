import { Test, TestingModule } from '@nestjs/testing';
import { ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { GlobalExceptionFilter } from './global-exception.filter';
import { AppConfig } from '@auth/infrastructure';

describe('GlobalExceptionFilter', () => {
  let filter: GlobalExceptionFilter;
  let configService: jest.Mocked<ConfigService>;
  let mockResponse: jest.Mocked<Response>;
  let mockRequest: jest.Mocked<Request>;
  let mockArgumentsHost: jest.Mocked<ArgumentsHost>;
  let loggerSpy: jest.SpyInstance;

  const mockAppConfig: Partial<AppConfig> = {
    NODE_ENV: 'test',
  };

  beforeEach(async () => {
    const mockConfigService = {
      get: jest.fn(),
    };

    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    } as any;

    mockRequest = {
      url: '/api/test',
      method: 'GET',
      ip: '127.0.0.1',
      get: jest.fn(),
      user: { id: 'user-123' },
    } as any;

    const mockHttpArgumentsHost = {
      getResponse: jest.fn().mockReturnValue(mockResponse),
      getRequest: jest.fn().mockReturnValue(mockRequest),
    };

    mockArgumentsHost = {
      switchToHttp: jest.fn().mockReturnValue(mockHttpArgumentsHost),
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        GlobalExceptionFilter,
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    filter = module.get<GlobalExceptionFilter>(GlobalExceptionFilter);
    configService = module.get(ConfigService);

    // Setup logger spy
    loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    jest.spyOn(Logger.prototype, 'warn').mockImplementation();
    jest.spyOn(Logger.prototype, 'log').mockImplementation();

    // Default config mock
    configService.get.mockReturnValue(mockAppConfig);
    
    // Default request mocks
    mockRequest.get.mockImplementation((header: string) => {
      switch (header) {
        case 'User-Agent':
          return 'test-agent';
        case 'X-Request-ID':
          return 'req-123';
        default:
          return undefined;
      }
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('HTTP Exception handling', () => {
    it('should handle HttpException with string message', () => {
      // Arrange
      const exception = new HttpException('Bad request', HttpStatus.BAD_REQUEST);

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.BAD_REQUEST);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: HttpStatus.BAD_REQUEST,
          message: 'Bad request',
          error: 'HttpException',
          timestamp: expect.any(String),
          path: '/api/test',
          method: 'GET',
          errorId: expect.stringMatching(/^err_\d+_[a-z0-9]+$/),
        })
      );
    });

    it('should handle HttpException with object response', () => {
      // Arrange
      const exceptionResponse = {
        message: 'Validation failed',
        error: 'ValidationError',
        details: ['field1 is required', 'field2 must be a string'],
      };
      const exception = new HttpException(exceptionResponse, HttpStatus.BAD_REQUEST);

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: HttpStatus.BAD_REQUEST,
          message: 'Validation failed',
          error: 'ValidationError',
          details: exceptionResponse,
        })
      );
    });

    it('should include stack trace in non-production environment', () => {
      // Arrange
      const exception = new HttpException('Test error', HttpStatus.BAD_REQUEST);
      configService.get.mockReturnValue({ NODE_ENV: 'development' });

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          stack: expect.any(String),
        })
      );
    });

    it('should exclude stack trace in production environment', () => {
      // Arrange
      const exception = new HttpException('Test error', HttpStatus.BAD_REQUEST);
      configService.get.mockReturnValue({ NODE_ENV: 'production' });

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      const callArgs = mockResponse.json.mock.calls[0][0];
      expect(callArgs).not.toHaveProperty('stack');
      expect(callArgs).not.toHaveProperty('details');
    });
  });

  describe('Generic Error handling', () => {
    it('should handle generic Error instances', () => {
      // Arrange
      const exception = new Error('Generic error message');

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.INTERNAL_SERVER_ERROR);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Generic error message',
          error: 'Error',
          stack: expect.any(String),
        })
      );
    });

    it('should handle custom Error subclasses', () => {
      // Arrange
      class CustomError extends Error {
        constructor(message: string) {
          super(message);
          this.name = 'CustomError';
        }
      }
      const exception = new CustomError('Custom error occurred');

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Custom error occurred',
          error: 'CustomError',
        })
      );
    });
  });

  describe('Unknown exception handling', () => {
    it('should handle string exceptions', () => {
      // Arrange
      const exception = 'String error message';

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Internal server error',
          error: 'UnknownError',
          details: 'String error message',
        })
      );
    });

    it('should handle null exceptions', () => {
      // Arrange
      const exception = null;

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Internal server error',
          error: 'UnknownError',
          details: null,
        })
      );
    });

    it('should handle object exceptions', () => {
      // Arrange
      const exception = { customProperty: 'value', code: 'CUSTOM_ERROR' };

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Internal server error',
          error: 'UnknownError',
          details: exception,
        })
      );
    });
  });

  describe('Logging behavior', () => {
    it('should log server errors (5xx) as error level', () => {
      // Arrange
      const exception = new Error('Server error');

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(Logger.prototype.error).toHaveBeenCalledWith(
        expect.stringContaining('500 Error: Server error'),
        expect.objectContaining({
          errorId: expect.any(String),
          method: 'GET',
          url: '/api/test',
          userAgent: 'test-agent',
          ip: '127.0.0.1',
          userId: 'user-123',
          requestId: 'req-123',
          stack: expect.any(String),
          exception,
        })
      );
    });

    it('should log client errors (4xx) as warning level', () => {
      // Arrange
      const exception = new HttpException('Bad request', HttpStatus.BAD_REQUEST);

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(Logger.prototype.warn).toHaveBeenCalledWith(
        expect.stringContaining('400 Error: Bad request'),
        expect.objectContaining({
          errorId: expect.any(String),
          method: 'GET',
          url: '/api/test',
          userAgent: 'test-agent',
          ip: '127.0.0.1',
          userId: 'user-123',
          requestId: 'req-123',
        })
      );
    });

    it('should log other status codes as info level', () => {
      // Arrange
      const exception = new HttpException('Redirect', HttpStatus.MOVED_PERMANENTLY);

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(Logger.prototype.log).toHaveBeenCalledWith(
        expect.stringContaining('301 Error: Redirect'),
        expect.any(Object)
      );
    });

    it('should handle anonymous users in logging', () => {
      // Arrange
      mockRequest.user = undefined;
      const exception = new Error('Test error');

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(Logger.prototype.error).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          userId: 'anonymous',
        })
      );
    });

    it('should handle missing headers in logging', () => {
      // Arrange
      mockRequest.get.mockReturnValue(undefined);
      const exception = new Error('Test error');

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(Logger.prototype.error).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          userAgent: undefined,
          requestId: undefined,
        })
      );
    });
  });

  describe('Error ID generation', () => {
    it('should generate unique error IDs', () => {
      // Arrange
      const exception1 = new Error('Error 1');
      const exception2 = new Error('Error 2');

      // Act
      filter.catch(exception1, mockArgumentsHost);
      filter.catch(exception2, mockArgumentsHost);

      // Assert
      const call1 = mockResponse.json.mock.calls[0][0];
      const call2 = mockResponse.json.mock.calls[1][0];
      
      expect(call1.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
      expect(call2.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
      expect(call1.errorId).not.toBe(call2.errorId);
    });

    it('should include error ID in response', () => {
      // Arrange
      const exception = new Error('Test error');

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          errorId: expect.stringMatching(/^err_\d+_[a-z0-9]+$/),
        })
      );
    });
  });

  describe('Response format', () => {
    it('should include all required fields in error response', () => {
      // Arrange
      const exception = new HttpException('Test error', HttpStatus.BAD_REQUEST);

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: expect.any(Number),
          timestamp: expect.any(String),
          path: expect.any(String),
          method: expect.any(String),
          errorId: expect.any(String),
          message: expect.any(String),
          error: expect.any(String),
        })
      );
    });

    it('should format timestamp as ISO string', () => {
      // Arrange
      const exception = new Error('Test error');
      const beforeTime = new Date().toISOString();

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      const callArgs = mockResponse.json.mock.calls[0][0];
      const timestamp = new Date(callArgs.timestamp);
      expect(timestamp.toISOString()).toBe(callArgs.timestamp);
      expect(callArgs.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    });

    it('should include request path and method', () => {
      // Arrange
      const exception = new Error('Test error');

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          path: '/api/test',
          method: 'GET',
        })
      );
    });
  });

  describe('Configuration handling', () => {
    it('should handle missing configuration gracefully', () => {
      // Arrange
      configService.get.mockReturnValue(null);
      const exception = new Error('Test error');

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Test error',
          // Should not include details or stack when config is null
        })
      );
    });

    it('should handle configuration service errors', () => {
      // Arrange
      configService.get.mockImplementation(() => {
        throw new Error('Config service error');
      });
      const exception = new Error('Test error');

      // Act & Assert
      expect(() => filter.catch(exception, mockArgumentsHost)).not.toThrow();
      expect(mockResponse.json).toHaveBeenCalled();
    });
  });

  describe('Edge cases', () => {
    it('should handle HttpException with undefined response', () => {
      // Arrange
      const exception = new HttpException(undefined as any, HttpStatus.BAD_REQUEST);

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.any(String),
          error: 'HttpException',
        })
      );
    });

    it('should handle Error with undefined message', () => {
      // Arrange
      const exception = new Error();
      exception.message = undefined as any;

      // Act
      filter.catch(exception, mockArgumentsHost);

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Error',
        })
      );
    });

    it('should handle circular reference in exception details', () => {
      // Arrange
      const circularObj: any = { prop: 'value' };
      circularObj.self = circularObj;
      const exception = circularObj;

      // Act & Assert
      expect(() => filter.catch(exception, mockArgumentsHost)).not.toThrow();
      expect(mockResponse.json).toHaveBeenCalled();
    });
  });
});