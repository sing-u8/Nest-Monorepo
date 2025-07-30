import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtAuthGuard, IS_PUBLIC_KEY } from '../jwt-auth.guard';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;
  let reflector: jest.Mocked<Reflector>;

  const mockExecutionContext = {
    switchToHttp: jest.fn().mockReturnValue({
      getRequest: jest.fn().mockReturnValue({
        headers: {
          'user-agent': 'Test-Agent/1.0',
          'x-forwarded-for': '203.0.113.1, 198.51.100.1',
        },
        connection: {
          remoteAddress: '192.168.1.1',
        },
      }),
    }),
    getHandler: jest.fn(),
    getClass: jest.fn(),
  } as unknown as ExecutionContext;

  beforeEach(async () => {
    reflector = {
      getAllAndOverride: jest.fn(),
    } as unknown as jest.Mocked<Reflector>;

    guard = new JwtAuthGuard(reflector);
  });

  describe('canActivate', () => {
    it('should return true for public routes', async () => {
      // Arrange
      reflector.getAllAndOverride.mockReturnValue(true);

      // Act
      const result = await guard.canActivate(mockExecutionContext);

      // Assert
      expect(result).toBe(true);
      expect(reflector.getAllAndOverride).toHaveBeenCalledWith(IS_PUBLIC_KEY, [
        mockExecutionContext.getHandler(),
        mockExecutionContext.getClass(),
      ]);
    });

    it('should call parent canActivate for protected routes', async () => {
      // Arrange
      reflector.getAllAndOverride.mockReturnValue(false);
      const parentCanActivateSpy = jest
        .spyOn(Object.getPrototypeOf(Object.getPrototypeOf(guard)), 'canActivate')
        .mockReturnValue(true);

      // Act
      const result = await guard.canActivate(mockExecutionContext);

      // Assert
      expect(parentCanActivateSpy).toHaveBeenCalledWith(mockExecutionContext);
    });
  });

  describe('handleRequest', () => {
    it('should return user when authentication succeeds', () => {
      // Arrange
      const user = {
        userId: 'user_123',
        email: 'test@example.com',
        sessionId: 'session_123',
      };

      // Act
      const result = guard.handleRequest(null, user, null, mockExecutionContext);

      // Assert
      expect(result).toEqual(user);
    });

    it('should throw UnauthorizedException for expired token', () => {
      // Arrange
      const info = { name: 'TokenExpiredError' };

      // Act & Assert
      expect(() => 
        guard.handleRequest(null, null, info, mockExecutionContext)
      ).toThrow(new UnauthorizedException('Token has expired'));
    });

    it('should throw UnauthorizedException for invalid token', () => {
      // Arrange
      const info = { name: 'JsonWebTokenError' };

      // Act & Assert
      expect(() => 
        guard.handleRequest(null, null, info, mockExecutionContext)
      ).toThrow(new UnauthorizedException('Invalid token'));
    });

    it('should throw provided error when error exists', () => {
      // Arrange
      const error = new UnauthorizedException('Custom error');

      // Act & Assert
      expect(() => 
        guard.handleRequest(error, null, null, mockExecutionContext)
      ).toThrow(error);
    });

    it('should throw generic UnauthorizedException when no user and no specific error', () => {
      // Act & Assert
      expect(() => 
        guard.handleRequest(null, null, null, mockExecutionContext)
      ).toThrow(new UnauthorizedException('Authentication failed'));
    });

    it('should log failed authentication attempts', () => {
      // Arrange
      const loggerSpy = jest.spyOn(guard['logger'], 'warn').mockImplementation();
      const error = new UnauthorizedException('Test error');

      // Act
      try {
        guard.handleRequest(error, null, null, mockExecutionContext);
      } catch (e) {
        // Expected to throw
      }

      // Assert
      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining('Authentication failed - IP: 203.0.113.1'),
      );
    });

    it('should log successful authentication', () => {
      // Arrange
      const loggerSpy = jest.spyOn(guard['logger'], 'debug').mockImplementation();
      const user = {
        userId: 'user_123',
        sessionId: 'session_123',
      };

      // Act
      guard.handleRequest(null, user, null, mockExecutionContext);

      // Assert
      expect(loggerSpy).toHaveBeenCalledWith(
        'Authentication successful - User ID: user_123, Session: session_123',
      );
    });
  });

  describe('getClientIp', () => {
    it('should extract IP from x-forwarded-for header', () => {
      // Act
      const ip = guard['getClientIp'](mockExecutionContext.switchToHttp().getRequest());

      // Assert
      expect(ip).toBe('203.0.113.1');
    });

    it('should extract IP from x-real-ip header', () => {
      // Arrange
      const request = {
        headers: { 'x-real-ip': '198.51.100.1' },
        connection: { remoteAddress: '192.168.1.1' },
      };

      // Act
      const ip = guard['getClientIp'](request);

      // Assert
      expect(ip).toBe('198.51.100.1');
    });

    it('should fall back to connection.remoteAddress', () => {
      // Arrange
      const request = {
        headers: {},
        connection: { remoteAddress: '192.168.1.1' },
      };

      // Act
      const ip = guard['getClientIp'](request);

      // Assert
      expect(ip).toBe('192.168.1.1');
    });

    it('should fall back to socket.remoteAddress', () => {
      // Arrange
      const request = {
        headers: {},
        connection: {},
        socket: { remoteAddress: '10.0.0.1' },
      };

      // Act
      const ip = guard['getClientIp'](request);

      // Assert
      expect(ip).toBe('10.0.0.1');
    });

    it('should return Unknown when no IP available', () => {
      // Arrange
      const request = {
        headers: {},
        connection: {},
        socket: {},
      };

      // Act
      const ip = guard['getClientIp'](request);

      // Assert
      expect(ip).toBe('Unknown');
    });
  });
});