import { Test, TestingModule } from '@nestjs/testing';
import { Request, Response, NextFunction } from 'express';
import { RateLimitingMiddleware } from '../rate-limiting.middleware';
import { getRateLimitingConfig } from '../../config/rate-limiting.config';

describe('RateLimitingMiddleware', () => {
  let middleware: RateLimitingMiddleware;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(async () => {
    const config = getRateLimitingConfig();
    middleware = new RateLimitingMiddleware(config);
    
    mockRequest = {
      headers: {},
      connection: { remoteAddress: '127.0.0.1' },
      route: { path: '/auth/login' },
      method: 'POST',
      path: '/auth/login',
    };
    
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    
    mockNext = jest.fn();
  });

  describe('Basic Rate Limiting', () => {
    it('should allow requests under the limit', () => {
      middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should extract IP address correctly', () => {
      mockRequest.headers = {
        'x-forwarded-for': '192.168.1.1, 10.0.0.1',
      };

      middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle missing IP address gracefully', () => {
      mockRequest.connection = {};
      mockRequest.socket = undefined;

      middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Progressive Delays', () => {
    beforeEach(() => {
      // Enable progressive delays for testing
      jest.spyOn(middleware as any, 'config', 'get').mockReturnValue({
        ...middleware['config'],
        progressive: {
          enabled: true,
          maxAttempts: 3,
          baseDelay: 100,
          maxDelay: 1000,
          resetTime: 1,
        },
      });
    });

    it('should record authentication failures', () => {
      const ip = '192.168.1.1';
      
      middleware.recordAuthFailure(ip);
      
      const record = middleware['progressiveDelayStore'].get(ip);
      expect(record).toBeDefined();
      expect(record?.attempts).toBe(1);
    });

    it('should increase delay with multiple failures', () => {
      const ip = '192.168.1.1';
      
      middleware.recordAuthFailure(ip);
      const firstRecord = middleware['progressiveDelayStore'].get(ip);
      
      middleware.recordAuthFailure(ip);
      const secondRecord = middleware['progressiveDelayStore'].get(ip);
      
      expect(secondRecord?.attempts).toBe(2);
      expect(secondRecord?.nextAllowedTime).toBeGreaterThan(firstRecord?.nextAllowedTime || 0);
    });
  });

  describe('IP Blocking', () => {
    beforeEach(() => {
      // Enable IP blocking for testing
      jest.spyOn(middleware as any, 'config', 'get').mockReturnValue({
        ...middleware['config'],
        ipBlocking: {
          enabled: true,
          maxFailures: 3,
          blockDuration: 1,
          whitelist: ['127.0.0.1'],
        },
      });
    });

    it('should not block whitelisted IPs', () => {
      const ip = '127.0.0.1';
      
      // Record multiple failures
      for (let i = 0; i < 5; i++) {
        middleware.recordAuthFailure(ip);
      }
      
      const record = middleware['ipBlockStore'].get(ip);
      expect(record).toBeUndefined();
    });

    it('should block IPs after max failures', () => {
      const ip = '192.168.1.1';
      
      // Record failures up to the limit
      for (let i = 0; i < 3; i++) {
        middleware.recordAuthFailure(ip);
      }
      
      const record = middleware['ipBlockStore'].get(ip);
      expect(record).toBeDefined();
      expect(record?.failures).toBe(3);
      expect(record?.blockedUntil).toBeGreaterThan(Date.now());
    });
  });

  describe('User-based Rate Limiting', () => {
    beforeEach(() => {
      // Enable user-based limiting for testing
      jest.spyOn(middleware as any, 'config', 'get').mockReturnValue({
        ...middleware['config'],
        userBased: {
          enabled: true,
          maxAttempts: 3,
          windowSize: 1,
          penaltyDuration: 1,
        },
      });
    });

    it('should record user failures', () => {
      const userId = 'user-123';
      
      middleware.recordAuthFailure('192.168.1.1', userId);
      
      const record = middleware['userRateLimitStore'].get(userId);
      expect(record).toBeDefined();
      expect(record?.attempts).toBe(1);
    });

    it('should apply penalty after max attempts', () => {
      const userId = 'user-123';
      
      // Record failures up to the limit
      for (let i = 0; i < 3; i++) {
        middleware.recordAuthFailure('192.168.1.1', userId);
      }
      
      const record = middleware['userRateLimitStore'].get(userId);
      expect(record).toBeDefined();
      expect(record?.attempts).toBe(3);
      expect(record?.penaltyUntil).toBeGreaterThan(Date.now());
    });
  });

  describe('Rate Limit Status', () => {
    it('should return correct rate limit status', () => {
      const ip = '192.168.1.1';
      const options = {
        windowMs: 60000,
        maxRequests: 5,
        message: 'Rate limited',
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        skipFailedRequests: false,
      };

      const status = middleware.getRateLimitStatus(ip, options);

      expect(status).toEqual({
        limit: 5,
        remaining: 5,
        resetTime: expect.any(Number),
        isLimited: false,
      });
    });

    it('should show decreased remaining count after requests', () => {
      const ip = '192.168.1.1';
      const options = {
        windowMs: 60000,
        maxRequests: 5,
        message: 'Rate limited',
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        skipFailedRequests: false,
      };

      // Record a request
      middleware['updateRateLimitRecord'](ip, options);
      
      const status = middleware.getRateLimitStatus(ip, options);

      expect(status.remaining).toBe(4);
      expect(status.isLimited).toBe(false);
    });
  });

  describe('Error Handling', () => {
    it('should continue on errors', () => {
      // Mock an error in the middleware
      mockRequest.headers = null as any;

      middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle cleanup errors gracefully', () => {
      // Force an error in cleanup
      middleware['rateLimitStore'].clear = jest.fn().mockImplementation(() => {
        throw new Error('Cleanup error');
      });

      expect(() => middleware['cleanup']()).not.toThrow();
    });
  });

  describe('Cleanup', () => {
    it('should clean up expired records', async () => {
      const ip = '192.168.1.1';
      
      // Add an expired record
      middleware['rateLimitStore'].set(`${ip}:1000:5`, {
        count: 1,
        resetTime: Date.now() - 1000, // Expired
        firstRequest: Date.now() - 2000,
      });

      expect(middleware['rateLimitStore'].size).toBe(1);
      
      middleware['cleanup']();
      
      expect(middleware['rateLimitStore'].size).toBe(0);
    });

    it('should not clean up active records', () => {
      const ip = '192.168.1.1';
      
      // Add an active record
      middleware['rateLimitStore'].set(`${ip}:60000:5`, {
        count: 1,
        resetTime: Date.now() + 60000, // Future
        firstRequest: Date.now(),
      });

      expect(middleware['rateLimitStore'].size).toBe(1);
      
      middleware['cleanup']();
      
      expect(middleware['rateLimitStore'].size).toBe(1);
    });
  });
});