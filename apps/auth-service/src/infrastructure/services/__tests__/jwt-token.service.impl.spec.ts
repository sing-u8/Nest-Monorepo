import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtTokenServiceImpl } from '../jwt-token.service.impl';
import { TokenType } from '@auth/shared/types/auth.types';

describe('JwtTokenServiceImpl', () => {
  let service: JwtTokenServiceImpl;
  let jwtService: jest.Mocked<JwtService>;
  let configService: jest.Mocked<ConfigService>;

  const mockPayload = {
    userId: 'user_123',
    email: 'test@example.com',
    type: TokenType.ACCESS,
    sessionId: 'session_123',
  };

  beforeEach(async () => {
    const mockJwtService = {
      signAsync: jest.fn(),
      verifyAsync: jest.fn(),
      decode: jest.fn(),
    };

    const mockConfigService = {
      get: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtTokenServiceImpl,
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    service = module.get<JwtTokenServiceImpl>(JwtTokenServiceImpl);
    jwtService = module.get(JwtService);
    configService = module.get(ConfigService);

    // Setup default config values
    configService.get.mockImplementation((key: string, defaultValue?: any) => {
      const configMap: { [key: string]: any } = {
        'auth.jwt.accessTokenSecret': 'access-secret',
        'auth.jwt.refreshTokenSecret': 'refresh-secret',
        'auth.jwt.accessTokenExpiresIn': '15m',
        'auth.jwt.refreshTokenExpiresIn': '7d',
      };
      return configMap[key] || defaultValue;
    });
  });

  describe('generateToken', () => {
    it('should generate access token with default expiration', async () => {
      // Arrange
      const expectedToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token';
      jwtService.signAsync.mockResolvedValue(expectedToken);

      // Act
      const token = await service.generateToken(mockPayload);

      // Assert
      expect(token).toBe(expectedToken);
      expect(jwtService.signAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: 'user_123',
          email: 'test@example.com',
          type: TokenType.ACCESS,
          sessionId: 'session_123',
        }),
        expect.objectContaining({
          expiresIn: '15m',
          secret: 'access-secret',
        })
      );
    });

    it('should generate refresh token with correct secret', async () => {
      // Arrange
      const refreshPayload = { ...mockPayload, type: TokenType.REFRESH };
      const expectedToken = 'refresh.token.value';
      jwtService.signAsync.mockResolvedValue(expectedToken);

      // Act
      const token = await service.generateToken(refreshPayload);

      // Assert
      expect(token).toBe(expectedToken);
      expect(jwtService.signAsync).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          secret: 'refresh-secret',
        })
      );
    });

    it('should use custom expiration when provided', async () => {
      // Arrange
      const customExpiration = '30m';
      const expectedToken = 'custom.token.value';
      jwtService.signAsync.mockResolvedValue(expectedToken);

      // Act
      const token = await service.generateToken(mockPayload, customExpiration);

      // Assert
      expect(jwtService.signAsync).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          expiresIn: customExpiration,
        })
      );
    });

    it('should throw error when JWT signing fails', async () => {
      // Arrange
      jwtService.signAsync.mockRejectedValue(new Error('JWT signing failed'));

      // Act & Assert
      await expect(service.generateToken(mockPayload)).rejects.toThrow('Failed to generate JWT token');
    });
  });

  describe('generateTokenPair', () => {
    it('should generate both access and refresh tokens', async () => {
      // Arrange
      jwtService.signAsync
        .mockResolvedValueOnce('access.token.value')
        .mockResolvedValueOnce('refresh.token.value');

      // Act
      const tokenPair = await service.generateTokenPair(mockPayload);

      // Assert
      expect(tokenPair.accessToken).toBeDefined();
      expect(tokenPair.refreshToken).toBeDefined();
      expect(tokenPair.accessToken.type).toBe(TokenType.ACCESS);
      expect(tokenPair.refreshToken.type).toBe(TokenType.REFRESH);
      expect(tokenPair.accessToken.getValue()).toBe('access.token.value');
      expect(tokenPair.refreshToken.getValue()).toBe('refresh.token.value');
    });

    it('should generate tokens with correct expiration times', async () => {
      // Arrange
      jwtService.signAsync
        .mockResolvedValueOnce('access.token.value')
        .mockResolvedValueOnce('refresh.token.value');

      const beforeGeneration = Date.now();

      // Act
      const tokenPair = await service.generateTokenPair(mockPayload);

      // Assert
      const accessExpiration = tokenPair.accessToken.getExpiresAt().getTime();
      const refreshExpiration = tokenPair.refreshToken.getExpiresAt().getTime();

      // Access token should expire in ~15 minutes
      expect(accessExpiration).toBeGreaterThan(beforeGeneration + 14 * 60 * 1000);
      expect(accessExpiration).toBeLessThan(beforeGeneration + 16 * 60 * 1000);

      // Refresh token should expire in ~7 days
      expect(refreshExpiration).toBeGreaterThan(beforeGeneration + 6 * 24 * 60 * 60 * 1000);
      expect(refreshExpiration).toBeLessThan(beforeGeneration + 8 * 24 * 60 * 60 * 1000);
    });

    it('should throw error when token generation fails', async () => {
      // Arrange
      jwtService.signAsync.mockRejectedValue(new Error('Token generation failed'));

      // Act & Assert
      await expect(service.generateTokenPair(mockPayload)).rejects.toThrow('Failed to generate token pair');
    });
  });

  describe('verifyToken', () => {
    it('should verify valid access token', async () => {
      // Arrange
      const token = 'valid.access.token';
      const decodedPayload = {
        sub: 'user_123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
        sessionId: 'session_123',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900, // 15 minutes
      };
      jwtService.verifyAsync.mockResolvedValue(decodedPayload);

      // Act
      const result = await service.verifyToken(token, TokenType.ACCESS);

      // Assert
      expect(result).toEqual(expect.objectContaining({
        userId: 'user_123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
        sessionId: 'session_123',
      }));
      expect(jwtService.verifyAsync).toHaveBeenCalledWith(token, { secret: 'access-secret' });
    });

    it('should verify valid refresh token', async () => {
      // Arrange
      const token = 'valid.refresh.token';
      const decodedPayload = {
        sub: 'user_123',
        email: 'test@example.com',
        type: TokenType.REFRESH,
        sessionId: 'session_123',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 604800, // 7 days
      };
      jwtService.verifyAsync.mockResolvedValue(decodedPayload);

      // Act
      const result = await service.verifyToken(token, TokenType.REFRESH);

      // Assert
      expect(result).toEqual(expect.objectContaining({
        userId: 'user_123',
        type: TokenType.REFRESH,
      }));
      expect(jwtService.verifyAsync).toHaveBeenCalledWith(token, { secret: 'refresh-secret' });
    });

    it('should return null for token with wrong type', async () => {
      // Arrange
      const token = 'access.token.with.wrong.type';
      const decodedPayload = {
        sub: 'user_123',
        email: 'test@example.com',
        type: TokenType.ACCESS, // Token is access type
        sessionId: 'session_123',
      };
      jwtService.verifyAsync.mockResolvedValue(decodedPayload);

      // Act - trying to verify as refresh token
      const result = await service.verifyToken(token, TokenType.REFRESH);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null for expired token', async () => {
      // Arrange
      const token = 'expired.token';
      jwtService.verifyAsync.mockRejectedValue(new Error('TokenExpiredError'));

      // Act
      const result = await service.verifyToken(token, TokenType.ACCESS);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null for invalid token signature', async () => {
      // Arrange
      const token = 'invalid.signature.token';
      jwtService.verifyAsync.mockRejectedValue(new Error('JsonWebTokenError'));

      // Act
      const result = await service.verifyToken(token, TokenType.ACCESS);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('decodeToken', () => {
    it('should decode token without verification', async () => {
      // Arrange
      const token = 'token.to.decode';
      const decodedPayload = {
        sub: 'user_123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
      };
      jwtService.decode.mockReturnValue(decodedPayload);

      // Act
      const result = await service.decodeToken(token);

      // Assert
      expect(result).toEqual(decodedPayload);
      expect(jwtService.decode).toHaveBeenCalledWith(token);
    });

    it('should throw error when decoding fails', async () => {
      // Arrange
      const token = 'invalid.token';
      jwtService.decode.mockImplementation(() => {
        throw new Error('Decode failed');
      });

      // Act & Assert
      await expect(service.decodeToken(token)).rejects.toThrow('Failed to decode token');
    });
  });

  describe('refreshTokens', () => {
    it('should generate new token pair from valid refresh token', async () => {
      // Arrange
      const refreshToken = 'valid.refresh.token';
      const decodedPayload = {
        sub: 'user_123',
        email: 'test@example.com',
        type: TokenType.REFRESH,
        sessionId: 'session_123',
      };
      
      jwtService.verifyAsync.mockResolvedValue(decodedPayload);
      jwtService.signAsync
        .mockResolvedValueOnce('new.access.token')
        .mockResolvedValueOnce('new.refresh.token');

      // Act
      const result = await service.refreshTokens(refreshToken);

      // Assert
      expect(result).not.toBeNull();
      expect(result!.accessToken.getValue()).toBe('new.access.token');
      expect(result!.refreshToken.getValue()).toBe('new.refresh.token');
    });

    it('should return null for invalid refresh token', async () => {
      // Arrange
      const refreshToken = 'invalid.refresh.token';
      jwtService.verifyAsync.mockRejectedValue(new Error('Invalid token'));

      // Act
      const result = await service.refreshTokens(refreshToken);

      // Assert
      expect(result).toBeNull();
    });

    it('should throw error when token generation fails during refresh', async () => {
      // Arrange
      const refreshToken = 'valid.refresh.token';
      const decodedPayload = {
        sub: 'user_123',
        email: 'test@example.com',
        type: TokenType.REFRESH,
        sessionId: 'session_123',
      };
      
      jwtService.verifyAsync.mockResolvedValue(decodedPayload);
      jwtService.signAsync.mockRejectedValue(new Error('Token generation failed'));

      // Act & Assert
      await expect(service.refreshTokens(refreshToken)).rejects.toThrow('Failed to refresh tokens');
    });
  });

  describe('getTokenExpiration', () => {
    it('should return expiration date from token', async () => {
      // Arrange
      const token = 'token.with.expiration';
      const exp = Math.floor(Date.now() / 1000) + 900; // 15 minutes from now
      jwtService.decode.mockReturnValue({ exp });

      // Act
      const expiration = service.getTokenExpiration(token);

      // Assert
      expect(expiration).toBeInstanceOf(Date);
      expect(expiration!.getTime()).toBe(exp * 1000);
    });

    it('should return null for token without expiration', async () => {
      // Arrange
      const token = 'token.without.expiration';
      jwtService.decode.mockReturnValue({ sub: 'user_123' }); // No exp field

      // Act
      const expiration = service.getTokenExpiration(token);

      // Assert
      expect(expiration).toBeNull();
    });

    it('should return null for invalid token', async () => {
      // Arrange
      const token = 'invalid.token';
      jwtService.decode.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      // Act
      const expiration = service.getTokenExpiration(token);

      // Assert
      expect(expiration).toBeNull();
    });
  });

  describe('isTokenExpired', () => {
    it('should return false for valid token', async () => {
      // Arrange
      const token = 'valid.token';
      const exp = Math.floor(Date.now() / 1000) + 900; // 15 minutes from now
      jwtService.decode.mockReturnValue({ exp });

      // Act
      const isExpired = service.isTokenExpired(token);

      // Assert
      expect(isExpired).toBe(false);
    });

    it('should return true for expired token', async () => {
      // Arrange
      const token = 'expired.token';
      const exp = Math.floor(Date.now() / 1000) - 900; // 15 minutes ago
      jwtService.decode.mockReturnValue({ exp });

      // Act
      const isExpired = service.isTokenExpired(token);

      // Assert
      expect(isExpired).toBe(true);
    });

    it('should return true for token without expiration', async () => {
      // Arrange
      const token = 'token.without.exp';
      jwtService.decode.mockReturnValue({ sub: 'user_123' });

      // Act
      const isExpired = service.isTokenExpired(token);

      // Assert
      expect(isExpired).toBe(true);
    });
  });

  describe('validateTokenFormat', () => {
    it('should return true for valid JWT format', async () => {
      // Arrange
      const validToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

      // Act
      const isValid = service.validateTokenFormat(validToken);

      // Assert
      expect(isValid).toBe(true);
    });

    it('should return false for invalid JWT format', async () => {
      // Arrange
      const invalidTokens = [
        'invalid.token', // Only 2 parts
        'invalid.token.format.extra', // 4 parts
        'invalid@token.format', // Invalid characters
        '', // Empty
        'not-base64.not-base64.not-base64', // Invalid base64
      ];

      // Act & Assert
      invalidTokens.forEach(token => {
        expect(service.validateTokenFormat(token)).toBe(false);
      });
    });

    it('should return false for non-string input', async () => {
      // Act & Assert
      expect(service.validateTokenFormat(null as any)).toBe(false);
      expect(service.validateTokenFormat(undefined as any)).toBe(false);
      expect(service.validateTokenFormat(123 as any)).toBe(false);
    });
  });

  describe('extractTokenPayload', () => {
    it('should extract payload from token', async () => {
      // Arrange
      const token = 'valid.token';
      const decodedPayload = {
        sub: 'user_123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
        sessionId: 'session_123',
        iat: 1234567890,
        exp: 1234567890 + 900,
      };
      jwtService.decode.mockReturnValue(decodedPayload);

      // Act
      const result = service.extractTokenPayload(token);

      // Assert
      expect(result).toEqual({
        userId: 'user_123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
        sessionId: 'session_123',
        iat: 1234567890,
        exp: 1234567890 + 900,
      });
    });

    it('should return null for invalid token', async () => {
      // Arrange
      const token = 'invalid.token';
      jwtService.decode.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      // Act
      const result = service.extractTokenPayload(token);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null when decode returns null', async () => {
      // Arrange
      const token = 'malformed.token';
      jwtService.decode.mockReturnValue(null);

      // Act
      const result = service.extractTokenPayload(token);

      // Assert
      expect(result).toBeNull();
    });
  });
});