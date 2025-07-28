import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Request } from 'express';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;
  let jwtService: jest.Mocked<JwtService>;
  let mockExecutionContext: jest.Mocked<ExecutionContext>;
  let mockRequest: Partial<Request>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtAuthGuard,
        {
          provide: JwtService,
          useValue: {
            verifyAsync: jest.fn(),
          },
        },
      ],
    }).compile();

    guard = module.get<JwtAuthGuard>(JwtAuthGuard);
    jwtService = module.get(JwtService);

    // Setup mock request
    mockRequest = {
      headers: {},
    };

    // Setup mock execution context
    mockExecutionContext = {
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue(mockRequest),
      }),
    } as any;

    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('canActivate', () => {
    it('should return true for valid JWT token', async () => {
      const validPayload = {
        sub: 'user-123',
        email: 'user@example.com',
        iat: Math.floor(Date.now() / 1000) - 100,
        exp: Math.floor(Date.now() / 1000) + 900,
      };

      mockRequest.headers = {
        authorization: 'Bearer valid-jwt-token',
      };

      jwtService.verifyAsync.mockResolvedValue(validPayload);

      const result = await guard.canActivate(mockExecutionContext);

      expect(result).toBe(true);
      expect(jwtService.verifyAsync).toHaveBeenCalledWith('valid-jwt-token');
      expect((mockRequest as any).user).toEqual({
        sub: 'user-123',
        email: 'user@example.com',
        iat: validPayload.iat,
        exp: validPayload.exp,
      });
    });

    it('should include additional claims in user object', async () => {
      const validPayload = {
        sub: 'user-123',
        email: 'user@example.com',
        iat: Math.floor(Date.now() / 1000) - 100,
        exp: Math.floor(Date.now() / 1000) + 900,
        role: 'admin',
        permissions: ['read', 'write'],
      };

      mockRequest.headers = {
        authorization: 'Bearer valid-jwt-token',
      };

      jwtService.verifyAsync.mockResolvedValue(validPayload);

      const result = await guard.canActivate(mockExecutionContext);

      expect(result).toBe(true);
      expect((mockRequest as any).user).toEqual(expect.objectContaining({
        sub: 'user-123',
        email: 'user@example.com',
        role: 'admin',
        permissions: ['read', 'write'],
      }));
    });

    it('should throw UnauthorizedException when no authorization header', async () => {
      mockRequest.headers = {};

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Missing authentication token')
      );

      expect(jwtService.verifyAsync).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when authorization header is malformed', async () => {
      mockRequest.headers = {
        authorization: 'InvalidFormat token',
      };

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Missing authentication token')
      );

      expect(jwtService.verifyAsync).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when Bearer token is missing', async () => {
      mockRequest.headers = {
        authorization: 'Bearer ',
      };

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Missing authentication token')
      );

      expect(jwtService.verifyAsync).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException when token payload is missing sub', async () => {
      const invalidPayload = {
        email: 'user@example.com',
        iat: Math.floor(Date.now() / 1000) - 100,
        exp: Math.floor(Date.now() / 1000) + 900,
      };

      mockRequest.headers = {
        authorization: 'Bearer invalid-payload-token',
      };

      jwtService.verifyAsync.mockResolvedValue(invalidPayload);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Invalid token payload')
      );
    });

    it('should throw UnauthorizedException when token payload is missing email', async () => {
      const invalidPayload = {
        sub: 'user-123',
        iat: Math.floor(Date.now() / 1000) - 100,
        exp: Math.floor(Date.now() / 1000) + 900,
      };

      mockRequest.headers = {
        authorization: 'Bearer invalid-payload-token',
      };

      jwtService.verifyAsync.mockResolvedValue(invalidPayload);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Invalid token payload')
      );
    });

    it('should throw UnauthorizedException when token is expired', async () => {
      const expiredPayload = {
        sub: 'user-123',
        email: 'user@example.com',
        iat: Math.floor(Date.now() / 1000) - 1000,
        exp: Math.floor(Date.now() / 1000) - 100, // Expired 100 seconds ago
      };

      mockRequest.headers = {
        authorization: 'Bearer expired-token',
      };

      jwtService.verifyAsync.mockResolvedValue(expiredPayload);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Token has expired')
      );
    });

    it('should handle JsonWebTokenError', async () => {
      mockRequest.headers = {
        authorization: 'Bearer invalid-token',
      };

      const jwtError = new Error('invalid signature');
      jwtError.name = 'JsonWebTokenError';
      jwtService.verifyAsync.mockRejectedValue(jwtError);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Invalid authentication token')
      );
    });

    it('should handle TokenExpiredError', async () => {
      mockRequest.headers = {
        authorization: 'Bearer expired-token',
      };

      const jwtError = new Error('jwt expired');
      jwtError.name = 'TokenExpiredError';
      jwtService.verifyAsync.mockRejectedValue(jwtError);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Authentication token has expired')
      );
    });

    it('should handle NotBeforeError', async () => {
      mockRequest.headers = {
        authorization: 'Bearer future-token',
      };

      const jwtError = new Error('jwt not active');
      jwtError.name = 'NotBeforeError';
      jwtService.verifyAsync.mockRejectedValue(jwtError);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Authentication token not yet active')
      );
    });

    it('should handle unexpected errors', async () => {
      mockRequest.headers = {
        authorization: 'Bearer some-token',
      };

      const unexpectedError = new Error('Database connection failed');
      jwtService.verifyAsync.mockRejectedValue(unexpectedError);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Authentication failed')
      );
    });

    it('should re-throw UnauthorizedException without modification', async () => {
      mockRequest.headers = {
        authorization: 'Bearer some-token',
      };

      const authError = new UnauthorizedException('Custom auth error');
      jwtService.verifyAsync.mockRejectedValue(authError);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Custom auth error')
      );
    });
  });

  describe('extractTokenFromHeader', () => {
    it('should extract valid Bearer token', () => {
      const request = {
        headers: {
          authorization: 'Bearer valid-token-123',
        },
      } as Request;

      // Access private method through reflection
      const extractTokenFromHeader = (guard as any).extractTokenFromHeader.bind(guard);
      const token = extractTokenFromHeader(request);

      expect(token).toBe('valid-token-123');
    });

    it('should return undefined for missing authorization header', () => {
      const request = {
        headers: {},
      } as Request;

      const extractTokenFromHeader = (guard as any).extractTokenFromHeader.bind(guard);
      const token = extractTokenFromHeader(request);

      expect(token).toBeUndefined();
    });

    it('should return undefined for invalid authorization header format', () => {
      const request = {
        headers: {
          authorization: 'Basic dXNlcjpwYXNz',
        },
      } as Request;

      const extractTokenFromHeader = (guard as any).extractTokenFromHeader.bind(guard);
      const token = extractTokenFromHeader(request);

      expect(token).toBeUndefined();
    });

    it('should return undefined for Bearer without token', () => {
      const request = {
        headers: {
          authorization: 'Bearer',
        },
      } as Request;

      const extractTokenFromHeader = (guard as any).extractTokenFromHeader.bind(guard);
      const token = extractTokenFromHeader(request);

      expect(token).toBeUndefined();
    });

    it('should return undefined for Bearer with empty token', () => {
      const request = {
        headers: {
          authorization: 'Bearer ',
        },
      } as Request;

      const extractTokenFromHeader = (guard as any).extractTokenFromHeader.bind(guard);
      const token = extractTokenFromHeader(request);

      expect(token).toBeUndefined();
    });

    it('should handle complex Bearer tokens', () => {
      const complexToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ';
      const request = {
        headers: {
          authorization: `Bearer ${complexToken}`,
        },
      } as Request;

      const extractTokenFromHeader = (guard as any).extractTokenFromHeader.bind(guard);
      const token = extractTokenFromHeader(request);

      expect(token).toBe(complexToken);
    });
  });

  describe('Token validation edge cases', () => {
    it('should accept token without expiration claim', async () => {
      const payloadWithoutExp = {
        sub: 'user-123',
        email: 'user@example.com',
        iat: Math.floor(Date.now() / 1000) - 100,
      };

      mockRequest.headers = {
        authorization: 'Bearer token-without-exp',
      };

      jwtService.verifyAsync.mockResolvedValue(payloadWithoutExp);

      const result = await guard.canActivate(mockExecutionContext);

      expect(result).toBe(true);
      expect((mockRequest as any).user).toEqual(expect.objectContaining({
        sub: 'user-123',
        email: 'user@example.com',
      }));
    });

    it('should handle token with future expiration', async () => {
      const futureExpPayload = {
        sub: 'user-123',
        email: 'user@example.com',
        iat: Math.floor(Date.now() / 1000) - 100,
        exp: Math.floor(Date.now() / 1000) + 3600, // Expires in 1 hour
      };

      mockRequest.headers = {
        authorization: 'Bearer future-exp-token',
      };

      jwtService.verifyAsync.mockResolvedValue(futureExpPayload);

      const result = await guard.canActivate(mockExecutionContext);

      expect(result).toBe(true);
    });

    it('should handle empty payload gracefully', async () => {
      const emptyPayload = {};

      mockRequest.headers = {
        authorization: 'Bearer empty-payload-token',
      };

      jwtService.verifyAsync.mockResolvedValue(emptyPayload);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Invalid token payload')
      );
    });

    it('should handle null payload', async () => {
      mockRequest.headers = {
        authorization: 'Bearer null-payload-token',
      };

      jwtService.verifyAsync.mockResolvedValue(null);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Invalid token payload')
      );
    });
  });
});