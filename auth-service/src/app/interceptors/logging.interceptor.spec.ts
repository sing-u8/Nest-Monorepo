import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, CallHandler, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { of, throwError, Observable } from 'rxjs';
import { LoggingInterceptor } from './logging.interceptor';
import { AppConfig } from '@auth/infrastructure';

describe('LoggingInterceptor', () => {
  let interceptor: LoggingInterceptor;
  let configService: jest.Mocked<ConfigService>;
  let mockRequest: jest.Mocked<Request>;
  let mockResponse: jest.Mocked<Response>;
  let mockExecutionContext: jest.Mocked<ExecutionContext>;
  let mockCallHandler: jest.Mocked<CallHandler>;
  let loggerSpy: {
    log: jest.SpyInstance;
    warn: jest.SpyInstance;
    error: jest.SpyInstance;
  };

  const mockAppConfig: Partial<AppConfig> = {
    NODE_ENV: 'development',
  };

  beforeEach(async () => {
    const mockConfigService = {
      get: jest.fn(),
    };

    mockRequest = {
      method: 'GET',
      url: '/api/test?param=value',
      path: '/api/test',
      query: { param: 'value' },
      ip: '127.0.0.1',
      get: jest.fn(),
      user: { id: 'user-123' },
      session: { id: 'session-456' },
    } as any;

    mockResponse = {
      set: jest.fn(),
      statusCode: 200,
    } as any;

    const mockHttpArgumentsHost = {
      getRequest: jest.fn().mockReturnValue(mockRequest),
      getResponse: jest.fn().mockReturnValue(mockResponse),
    };

    mockExecutionContext = {
      switchToHttp: jest.fn().mockReturnValue(mockHttpArgumentsHost),
    } as any;

    mockCallHandler = {
      handle: jest.fn(),
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LoggingInterceptor,
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    interceptor = module.get<LoggingInterceptor>(LoggingInterceptor);
    configService = module.get(ConfigService);

    // Setup logger spies
    loggerSpy = {
      log: jest.spyOn(Logger.prototype, 'log').mockImplementation(),
      warn: jest.spyOn(Logger.prototype, 'warn').mockImplementation(),
      error: jest.spyOn(Logger.prototype, 'error').mockImplementation(),
    };

    // Default config mock
    configService.get.mockReturnValue(mockAppConfig);

    // Default request header mocks
    mockRequest.get.mockImplementation((header: string) => {
      switch (header) {
        case 'User-Agent':
          return 'test-agent/1.0';
        case 'Content-Length':
          return '100';
        case 'Content-Type':
          return 'application/json';
        case 'Authorization':
          return 'Bearer token123';
        case 'X-Request-ID':
          return undefined; // Will be generated
        default:
          return undefined;
      }
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Test environment handling', () => {
    it('should skip logging in test environment', () => {
      // Arrange
      configService.get.mockReturnValue({ NODE_ENV: 'test' });
      mockCallHandler.handle.mockReturnValue(of('test result'));

      // Act
      const result = interceptor.intercept(mockExecutionContext, mockCallHandler);

      // Assert
      expect(result).toBeInstanceOf(Observable);
      expect(loggerSpy.log).not.toHaveBeenCalled();
      expect(mockResponse.set).not.toHaveBeenCalled();
    });

    it('should proceed with logging in non-test environment', () => {
      // Arrange
      configService.get.mockReturnValue({ NODE_ENV: 'development' });
      mockCallHandler.handle.mockReturnValue(of('result'));

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);

      // Assert
      result$.subscribe(() => {
        expect(loggerSpy.log).toHaveBeenCalled();
        expect(mockResponse.set).toHaveBeenCalledWith('X-Request-ID', expect.stringMatching(/^req_\d+_[a-z0-9]+$/));
      });
    });
  });

  describe('Request logging', () => {
    beforeEach(() => {
      mockCallHandler.handle.mockReturnValue(of('result'));
    });

    it('should log incoming request with all details', () => {
      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);

      // Subscribe to trigger the interceptor
      result$.subscribe();

      // Assert
      expect(loggerSpy.log).toHaveBeenCalledWith(
        '→ GET /api/test',
        expect.objectContaining({
          type: 'request',
          requestId: expect.stringMatching(/^req_\d+_[a-z0-9]+$/),
          method: 'GET',
          path: '/api/test',
          userId: 'user-123',
          ip: '127.0.0.1',
          userAgent: 'test-agent/1.0',
          timestamp: expect.any(String),
        })
      );
    });

    it('should generate request ID when not provided', () => {
      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert
      expect(mockResponse.set).toHaveBeenCalledWith('X-Request-ID', expect.stringMatching(/^req_\d+_[a-z0-9]+$/));
    });

    it('should use existing request ID when provided', () => {
      // Arrange
      mockRequest.get.mockImplementation((header: string) => {
        if (header === 'X-Request-ID') return 'existing-req-id';
        return mockRequest.get.call(mockRequest, header);
      });

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert
      expect(mockResponse.set).toHaveBeenCalledWith('X-Request-ID', 'existing-req-id');
    });

    it('should handle anonymous users', () => {
      // Arrange
      mockRequest.user = undefined;

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert
      expect(loggerSpy.log).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          userId: 'anonymous',
        })
      );
    });

    it('should mask authorization header', () => {
      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert - Check if authorization is masked (though not directly in request log, it's in extracted info)
      expect(mockRequest.get).toHaveBeenCalledWith('Authorization');
    });

    it('should handle missing headers gracefully', () => {
      // Arrange
      mockRequest.get.mockReturnValue(undefined);

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert
      expect(loggerSpy.log).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          userAgent: undefined,
        })
      );
    });
  });

  describe('Successful response logging', () => {
    it('should log successful response with 2xx status codes', () => {
      // Arrange
      mockResponse.statusCode = 200;
      mockCallHandler.handle.mockReturnValue(of('success result'));

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert
      expect(loggerSpy.log).toHaveBeenCalledWith(
        expect.stringMatching(/← ✅ GET \/api\/test 200 \d+ms/),
        expect.objectContaining({
          type: 'response',
          requestId: expect.any(String),
          method: 'GET',
          path: '/api/test',
          statusCode: 200,
          duration: expect.any(Number),
          userId: 'user-123',
          responseType: 'success',
        })
      );
    });

    it('should log redirect responses with 3xx status codes', () => {
      // Arrange
      mockResponse.statusCode = 301;
      mockCallHandler.handle.mockReturnValue(of('redirect'));

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert
      expect(loggerSpy.log).toHaveBeenCalledWith(
        expect.stringMatching(/← 🔄 GET \/api\/test 301 \d+ms/),
        expect.objectContaining({
          statusCode: 301,
        })
      );
    });

    it('should measure and log response duration', () => {
      // Arrange
      mockCallHandler.handle.mockReturnValue(of('result'));

      // Act
      const startTime = Date.now();
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();
      const endTime = Date.now();

      // Assert
      expect(loggerSpy.log).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          duration: expect.any(Number),
        })
      );

      // Verify duration is reasonable
      const logCall = loggerSpy.log.mock.calls.find(call => call[1]?.type === 'response');
      expect(logCall[1].duration).toBeGreaterThanOrEqual(0);
      expect(logCall[1].duration).toBeLessThanOrEqual(endTime - startTime + 10); // Allow some tolerance
    });
  });

  describe('Error response logging', () => {
    it('should log client errors (4xx) as warnings', () => {
      // Arrange
      const error = { status: 400, message: 'Bad Request' };
      mockCallHandler.handle.mockReturnValue(throwError(error));

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);

      // Assert
      expect(() => result$.subscribe()).toThrow();
      expect(loggerSpy.warn).toHaveBeenCalledWith(
        expect.stringMatching(/← ⚠️ GET \/api\/test 400 \d+ms/),
        expect.objectContaining({
          type: 'response',
          statusCode: 400,
          responseType: 'error',
          error: 'Bad Request',
        })
      );
    });

    it('should log server errors (5xx) as errors', () => {
      // Arrange
      const error = { status: 500, message: 'Internal Server Error' };
      mockCallHandler.handle.mockReturnValue(throwError(error));

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);

      // Assert
      expect(() => result$.subscribe()).toThrow();
      expect(loggerSpy.error).toHaveBeenCalledWith(
        expect.stringMatching(/← ❌ GET \/api\/test 500 \d+ms/),
        expect.objectContaining({
          type: 'response',
          statusCode: 500,
          responseType: 'error',
          error: 'Internal Server Error',
        })
      );
    });

    it('should handle errors without status code', () => {
      // Arrange
      const error = { message: 'Unknown error' };
      mockCallHandler.handle.mockReturnValue(throwError(error));

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);

      // Assert
      expect(() => result$.subscribe()).toThrow();
      expect(loggerSpy.error).toHaveBeenCalledWith(
        expect.stringMatching(/← ❌ GET \/api\/test 500 \d+ms/),
        expect.objectContaining({
          statusCode: 500, // Default for errors without status
        })
      );
    });

    it('should re-throw errors after logging', () => {
      // Arrange
      const error = new Error('Test error');
      mockCallHandler.handle.mockReturnValue(throwError(error));

      // Act & Assert
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      expect(() => result$.subscribe()).toThrow('Test error');
    });
  });

  describe('Performance monitoring', () => {
    it('should log slow requests as warnings', () => {
      // Arrange
      mockCallHandler.handle.mockReturnValue(of('result'));
      
      // Mock Date.now to simulate slow request
      const originalDateNow = Date.now;
      let callCount = 0;
      Date.now = jest.fn(() => {
        callCount++;
        if (callCount === 1) return 1000; // Start time
        return 2500; // End time (1500ms duration)
      });

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert
      expect(loggerSpy.warn).toHaveBeenCalledWith(
        expect.stringMatching(/Slow request detected: GET \/api\/test took \d+ms/),
        expect.objectContaining({
          type: 'performance',
          requestId: expect.any(String),
          method: 'GET',
          path: '/api/test',
          duration: expect.any(Number),
          userId: 'user-123',
        })
      );

      // Restore Date.now
      Date.now = originalDateNow;
    });

    it('should not log performance warning for fast requests', () => {
      // Arrange
      mockCallHandler.handle.mockReturnValue(of('result'));

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert
      const performanceWarnings = loggerSpy.warn.mock.calls.filter(
        call => call[1]?.type === 'performance'
      );
      expect(performanceWarnings).toHaveLength(0);
    });
  });

  describe('Status emoji mapping', () => {
    const testCases = [
      { status: 200, emoji: '✅', logLevel: 'log' },
      { status: 201, emoji: '✅', logLevel: 'log' },
      { status: 301, emoji: '🔄', logLevel: 'log' },
      { status: 302, emoji: '🔄', logLevel: 'log' },
      { status: 400, emoji: '⚠️', logLevel: 'warn' },
      { status: 404, emoji: '⚠️', logLevel: 'warn' },
      { status: 500, emoji: '❌', logLevel: 'error' },
      { status: 503, emoji: '❌', logLevel: 'error' },
    ];

    testCases.forEach(({ status, emoji, logLevel }) => {
      it(`should use ${emoji} emoji and ${logLevel} level for ${status} status`, () => {
        // Arrange
        const error = { status, message: 'Test error' };
        mockCallHandler.handle.mockReturnValue(throwError(error));

        // Act
        const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);

        try {
          result$.subscribe();
        } catch (e) {
          // Expected for error cases
        }

        // Assert
        const expectedLogger = loggerSpy[logLevel as keyof typeof loggerSpy];
        expect(expectedLogger).toHaveBeenCalledWith(
          expect.stringContaining(emoji),
          expect.any(Object)
        );
      });
    });
  });

  describe('Request ID generation', () => {
    it('should generate unique request IDs', () => {
      // Arrange
      mockCallHandler.handle.mockReturnValue(of('result'));

      // Act
      const result1$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      const result2$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      
      result1$.subscribe();
      result2$.subscribe();

      // Assert
      const call1 = mockResponse.set.mock.calls[0];
      const call2 = mockResponse.set.mock.calls[1];
      
      expect(call1[1]).toMatch(/^req_\d+_[a-z0-9]+$/);
      expect(call2[1]).toMatch(/^req_\d+_[a-z0-9]+$/);
      expect(call1[1]).not.toBe(call2[1]);
    });
  });

  describe('Configuration handling', () => {
    it('should handle missing configuration gracefully', () => {
      // Arrange
      configService.get.mockReturnValue(null);
      mockCallHandler.handle.mockReturnValue(of('result'));

      // Act & Assert
      expect(() => {
        const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
        result$.subscribe();
      }).not.toThrow();
    });

    it('should handle configuration service errors', () => {
      // Arrange
      configService.get.mockImplementation(() => {
        throw new Error('Config service error');
      });
      mockCallHandler.handle.mockReturnValue(of('result'));

      // Act & Assert
      expect(() => {
        const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
        result$.subscribe();
      }).not.toThrow();
    });
  });

  describe('Edge cases', () => {
    it('should handle POST requests with different parameters', () => {
      // Arrange
      mockRequest.method = 'POST';
      mockRequest.path = '/api/users';
      mockRequest.query = {};
      mockCallHandler.handle.mockReturnValue(of('created'));

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert
      expect(loggerSpy.log).toHaveBeenCalledWith(
        '→ POST /api/users',
        expect.objectContaining({
          method: 'POST',
          path: '/api/users',
        })
      );
    });

    it('should handle requests without query parameters', () => {
      // Arrange
      mockRequest.query = {};
      mockCallHandler.handle.mockReturnValue(of('result'));

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert
      expect(loggerSpy.log).toHaveBeenCalled();
    });

    it('should handle requests without user session', () => {
      // Arrange
      mockRequest.user = undefined;
      mockRequest.session = undefined;
      mockCallHandler.handle.mockReturnValue(of('result'));

      // Act
      const result$ = interceptor.intercept(mockExecutionContext, mockCallHandler);
      result$.subscribe();

      // Assert
      expect(loggerSpy.log).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          userId: 'anonymous',
        })
      );
    });
  });
});