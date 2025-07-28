import { Test, TestingModule } from '@nestjs/testing';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { JwtTokenService } from './jwt-token.service';
import { TokenType, JwtPayload } from '@auth/shared';

// Mock jsonwebtoken
jest.mock('jsonwebtoken');
const mockedJwt = jwt as jest.Mocked<typeof jwt>;

// Mock crypto
jest.mock('crypto');
const mockedCrypto = crypto as jest.Mocked<typeof crypto>;

describe('JwtTokenService', () => {
  let service: JwtTokenService;
  let mockPrivateKey: string;
  let mockPublicKey: string;

  beforeEach(async () => {
    mockPrivateKey = 'mock-private-key';
    mockPublicKey = 'mock-public-key';

    // Mock RSA key pair generation
    mockedCrypto.generateKeyPairSync.mockReturnValue({
      privateKey: mockPrivateKey,
      publicKey: mockPublicKey,
    } as any);

    const module: TestingModule = await Test.createTestingModule({
      providers: [JwtTokenService],
    }).compile();

    service = module.get<JwtTokenService>(JwtTokenService);
    
    // Reset all mocks
    jest.clearAllMocks();
  });

  describe('generateToken', () => {
    it('should generate JWT token with correct parameters', async () => {
      const payload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
      };
      const expiresIn = '15m';
      const mockToken = 'mock.jwt.token';

      mockedJwt.sign.mockReturnValue(mockToken);

      const result = await service.generateToken(payload, TokenType.ACCESS, expiresIn);

      expect(mockedJwt.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          ...payload,
          type: TokenType.ACCESS,
          iat: expect.any(Number),
        }),
        mockPrivateKey,
        expect.objectContaining({
          algorithm: 'RS256',
          expiresIn,
          issuer: 'auth-service',
          audience: 'auth-client',
          subject: payload.sub,
        })
      );
      expect(result).toBe(mockToken);
    });

    it('should throw error for invalid payload', async () => {
      const invalidPayload = null as any;

      await expect(service.generateToken(invalidPayload, TokenType.ACCESS, '15m'))
        .rejects.toThrow('Failed to generate JWT token');
    });

    it('should throw error for invalid expiration time', async () => {
      const payload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
      };

      await expect(service.generateToken(payload, TokenType.ACCESS, 'invalid'))
        .rejects.toThrow('Failed to generate JWT token');
    });

    it('should handle JWT signing errors', async () => {
      const payload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
      };

      mockedJwt.sign.mockImplementation(() => {
        throw new Error('JWT signing error');
      });

      await expect(service.generateToken(payload, TokenType.ACCESS, '15m'))
        .rejects.toThrow('Failed to generate JWT token');
    });
  });

  describe('generateAccessToken', () => {
    it('should generate access token', async () => {
      const userId = 'user123';
      const email = 'test@example.com';
      const mockToken = 'mock.access.token';

      mockedJwt.sign.mockReturnValue(mockToken);

      const result = await service.generateAccessToken(userId, email);

      expect(mockedJwt.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: userId,
          email,
          type: TokenType.ACCESS,
        }),
        mockPrivateKey,
        expect.objectContaining({
          expiresIn: '15m',
        })
      );
      expect(result).toBe(mockToken);
    });

    it('should generate access token with custom expiration', async () => {
      const userId = 'user123';
      const email = 'test@example.com';
      const expiresIn = '30m';
      const mockToken = 'mock.access.token';

      mockedJwt.sign.mockReturnValue(mockToken);

      await service.generateAccessToken(userId, email, expiresIn);

      expect(mockedJwt.sign).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({
          expiresIn,
        })
      );
    });

    it('should throw error for invalid user ID', async () => {
      await expect(service.generateAccessToken('', 'test@example.com'))
        .rejects.toThrow('Failed to generate access token');
    });

    it('should throw error for invalid email', async () => {
      await expect(service.generateAccessToken('user123', 'invalid-email'))
        .rejects.toThrow('Failed to generate access token');
    });
  });

  describe('generateRefreshToken', () => {
    it('should generate refresh token', async () => {
      const userId = 'user123';
      const email = 'test@example.com';
      const mockToken = 'mock.refresh.token';

      mockedJwt.sign.mockReturnValue(mockToken);

      const result = await service.generateRefreshToken(userId, email);

      expect(mockedJwt.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: userId,
          email,
          type: TokenType.REFRESH,
        }),
        mockPrivateKey,
        expect.objectContaining({
          expiresIn: '7d',
        })
      );
      expect(result).toBe(mockToken);
    });

    it('should generate refresh token with custom expiration', async () => {
      const userId = 'user123';
      const email = 'test@example.com';
      const expiresIn = '30d';

      mockedJwt.sign.mockReturnValue('mock.token');

      await service.generateRefreshToken(userId, email, expiresIn);

      expect(mockedJwt.sign).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({
          expiresIn,
        })
      );
    });
  });

  describe('validateToken', () => {
    it('should validate valid token', async () => {
      const token = 'valid.jwt.token';
      const mockPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
        iat: 1234567890,
        exp: 9999999999,
      };

      mockedJwt.verify.mockReturnValue(mockPayload);

      const result = await service.validateToken(token);

      expect(mockedJwt.verify).toHaveBeenCalledWith(
        token,
        mockPublicKey,
        expect.objectContaining({
          algorithms: ['RS256'],
          issuer: 'auth-service',
          audience: 'auth-client',
        })
      );
      expect(result).toEqual({
        isValid: true,
        payload: mockPayload,
      });
    });

    it('should return invalid for expired token', async () => {
      const token = 'expired.jwt.token';

      mockedJwt.verify.mockImplementation(() => {
        throw new jwt.TokenExpiredError('jwt expired', new Date());
      });

      const result = await service.validateToken(token);

      expect(result).toEqual({
        isValid: false,
        error: 'Token has expired',
      });
    });

    it('should return invalid for malformed token', async () => {
      const token = 'malformed.token';

      mockedJwt.verify.mockImplementation(() => {
        throw new jwt.JsonWebTokenError('invalid token');
      });

      const result = await service.validateToken(token);

      expect(result).toEqual({
        isValid: false,
        error: 'Invalid token format or signature',
      });
    });

    it('should return invalid for blacklisted token', async () => {
      const token = 'blacklisted.jwt.token';

      // First blacklist the token
      mockedJwt.decode.mockReturnValue({
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
      });
      
      mockedCrypto.createHash.mockReturnValue({
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('token-hash'),
      } as any);

      await service.blacklistToken(token);

      // Then try to validate it
      const result = await service.validateToken(token);

      expect(result).toEqual({
        isValid: false,
        error: 'Token has been revoked',
      });
    });

    it('should throw error for invalid token format', async () => {
      const result = await service.validateToken('invalid-format');

      expect(result).toEqual({
        isValid: false,
        error: 'Token validation failed',
      });
    });
  });

  describe('decodeToken', () => {
    it('should decode valid token', () => {
      const token = 'valid.jwt.token';
      const mockPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
      };

      mockedJwt.decode.mockReturnValue(mockPayload);

      const result = service.decodeToken(token);

      expect(mockedJwt.decode).toHaveBeenCalledWith(token);
      expect(result).toEqual(mockPayload);
    });

    it('should return null for invalid token', () => {
      mockedJwt.decode.mockReturnValue(null);

      const result = service.decodeToken('invalid.token');

      expect(result).toBeNull();
    });

    it('should return null for malformed token', () => {
      const result = service.decodeToken('malformed');

      expect(result).toBeNull();
    });
  });

  describe('getTokenExpiration', () => {
    it('should return expiration date for valid token', () => {
      const token = 'valid.jwt.token';
      const exp = 1234567890;
      const mockPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
        exp,
      };

      mockedJwt.decode.mockReturnValue(mockPayload);

      const result = service.getTokenExpiration(token);

      expect(result).toEqual(new Date(exp * 1000));
    });

    it('should return null for token without expiration', () => {
      const token = 'token.without.exp';
      const mockPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
      };

      mockedJwt.decode.mockReturnValue(mockPayload);

      const result = service.getTokenExpiration(token);

      expect(result).toBeNull();
    });

    it('should return null for invalid token', () => {
      mockedJwt.decode.mockReturnValue(null);

      const result = service.getTokenExpiration('invalid.token');

      expect(result).toBeNull();
    });
  });

  describe('isTokenExpired', () => {
    it('should return false for non-expired token', () => {
      const token = 'valid.jwt.token';
      const futureExp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const mockPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
        exp: futureExp,
      };

      mockedJwt.decode.mockReturnValue(mockPayload);

      const result = service.isTokenExpired(token);

      expect(result).toBe(false);
    });

    it('should return true for expired token', () => {
      const token = 'expired.jwt.token';
      const pastExp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
      const mockPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
        exp: pastExp,
      };

      mockedJwt.decode.mockReturnValue(mockPayload);

      const result = service.isTokenExpired(token);

      expect(result).toBe(true);
    });

    it('should return true for invalid token', () => {
      mockedJwt.decode.mockReturnValue(null);

      const result = service.isTokenExpired('invalid.token');

      expect(result).toBe(true);
    });
  });

  describe('getTimeUntilExpiration', () => {
    it('should return remaining time for valid token', () => {
      const token = 'valid.jwt.token';
      const futureExp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const mockPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
        exp: futureExp,
      };

      mockedJwt.decode.mockReturnValue(mockPayload);

      const result = service.getTimeUntilExpiration(token);

      expect(result).toBeGreaterThan(0);
      expect(result).toBeLessThanOrEqual(3600000); // 1 hour in milliseconds
    });

    it('should return 0 for expired token', () => {
      const token = 'expired.jwt.token';
      const pastExp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
      const mockPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
        exp: pastExp,
      };

      mockedJwt.decode.mockReturnValue(mockPayload);

      const result = service.getTimeUntilExpiration(token);

      expect(result).toBe(0);
    });

    it('should return 0 for invalid token', () => {
      mockedJwt.decode.mockReturnValue(null);

      const result = service.getTimeUntilExpiration('invalid.token');

      expect(result).toBe(0);
    });
  });

  describe('refreshAccessToken', () => {
    it('should generate new access token from valid refresh token', async () => {
      const refreshToken = 'valid.refresh.token';
      const mockRefreshPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.REFRESH,
        iat: 1234567890,
        exp: 9999999999,
      };
      const newAccessToken = 'new.access.token';

      // Mock validation of refresh token
      mockedJwt.verify.mockReturnValue(mockRefreshPayload);
      
      // Mock generation of new access token
      mockedJwt.sign.mockReturnValue(newAccessToken);

      const result = await service.refreshAccessToken(refreshToken);

      expect(result).toBe(newAccessToken);
      expect(mockedJwt.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: 'user123',
          email: 'test@example.com',
          type: TokenType.ACCESS,
        }),
        mockPrivateKey,
        expect.objectContaining({
          expiresIn: '15m',
        })
      );
    });

    it('should return null for invalid refresh token', async () => {
      const refreshToken = 'invalid.refresh.token';

      mockedJwt.verify.mockImplementation(() => {
        throw new jwt.JsonWebTokenError('invalid token');
      });

      const result = await service.refreshAccessToken(refreshToken);

      expect(result).toBeNull();
    });

    it('should return null for access token instead of refresh token', async () => {
      const accessToken = 'access.token';
      const mockAccessPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
        iat: 1234567890,
        exp: 9999999999,
      };

      mockedJwt.verify.mockReturnValue(mockAccessPayload);

      const result = await service.refreshAccessToken(accessToken);

      expect(result).toBeNull();
    });
  });

  describe('blacklistToken', () => {
    it('should blacklist valid token', async () => {
      const token = 'valid.jwt.token';
      const mockPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
      };

      mockedJwt.decode.mockReturnValue(mockPayload);
      mockedCrypto.createHash.mockReturnValue({
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('token-hash'),
      } as any);

      const result = await service.blacklistToken(token);

      expect(result).toBe(true);
    });

    it('should handle blacklisting errors', async () => {
      const result = await service.blacklistToken('');

      expect(result).toBe(false);
    });
  });

  describe('isTokenBlacklisted', () => {
    it('should return true for blacklisted token', async () => {
      const token = 'blacklisted.jwt.token';
      const mockPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
      };

      mockedJwt.decode.mockReturnValue(mockPayload);
      mockedCrypto.createHash.mockReturnValue({
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('token-hash'),
      } as any);

      // First blacklist the token
      await service.blacklistToken(token);

      // Then check if it's blacklisted
      const result = await service.isTokenBlacklisted(token);

      expect(result).toBe(true);
    });

    it('should return false for non-blacklisted token', async () => {
      const token = 'valid.jwt.token';
      const mockPayload: JwtPayload = {
        sub: 'user123',
        email: 'test@example.com',
        type: TokenType.ACCESS,
      };

      mockedJwt.decode.mockReturnValue(mockPayload);
      mockedCrypto.createHash.mockReturnValue({
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('token-hash'),
      } as any);

      const result = await service.isTokenBlacklisted(token);

      expect(result).toBe(false);
    });
  });

  describe('generateSecureRandomToken', () => {
    it('should generate random token with default length', () => {
      const mockRandomBytes = Buffer.from('randomBytes');
      mockedCrypto.randomBytes.mockReturnValue(mockRandomBytes);

      const result = service.generateSecureRandomToken();

      expect(mockedCrypto.randomBytes).toHaveBeenCalledWith(16); // ceil(32/2)
      expect(result).toBe(mockRandomBytes.toString('hex').slice(0, 32));
    });

    it('should generate random token with custom length', () => {
      const mockRandomBytes = Buffer.from('randomBytes');
      mockedCrypto.randomBytes.mockReturnValue(mockRandomBytes);

      const result = service.generateSecureRandomToken(16);

      expect(mockedCrypto.randomBytes).toHaveBeenCalledWith(8); // ceil(16/2)
      expect(result).toBe(mockRandomBytes.toString('hex').slice(0, 16));
    });

    it('should throw error for invalid length', () => {
      expect(() => service.generateSecureRandomToken(0))
        .toThrow('Failed to generate secure random token');
    });

    it('should throw error for excessive length', () => {
      expect(() => service.generateSecureRandomToken(300))
        .toThrow('Failed to generate secure random token');
    });
  });

  describe('signData', () => {
    it('should sign custom data', async () => {
      const data = { customField: 'value' };
      const expiresIn = '1h';
      const mockToken = 'signed.data.token';

      mockedJwt.sign.mockReturnValue(mockToken);

      const result = await service.signData(data, expiresIn);

      expect(mockedJwt.sign).toHaveBeenCalledWith(
        data,
        mockPrivateKey,
        expect.objectContaining({
          algorithm: 'RS256',
          expiresIn,
          issuer: 'auth-service',
          audience: 'auth-client',
        })
      );
      expect(result).toBe(mockToken);
    });

    it('should throw error for invalid data', async () => {
      await expect(service.signData(null as any, '1h'))
        .rejects.toThrow('Failed to sign data');
    });

    it('should throw error for empty data', async () => {
      await expect(service.signData({}, '1h'))
        .rejects.toThrow('Failed to sign data');
    });
  });

  describe('verifyData', () => {
    it('should verify and extract data', async () => {
      const token = 'signed.data.token';
      const expectedData = { customField: 'value' };

      mockedJwt.verify.mockReturnValue(expectedData);

      const result = await service.verifyData(token);

      expect(mockedJwt.verify).toHaveBeenCalledWith(
        token,
        mockPublicKey,
        expect.objectContaining({
          algorithms: ['RS256'],
          issuer: 'auth-service',
          audience: 'auth-client',
        })
      );
      expect(result).toEqual(expectedData);
    });

    it('should return null for invalid token', async () => {
      const token = 'invalid.token';

      mockedJwt.verify.mockImplementation(() => {
        throw new jwt.JsonWebTokenError('invalid token');
      });

      const result = await service.verifyData(token);

      expect(result).toBeNull();
    });
  });

  describe('getConfiguration', () => {
    it('should return service configuration', () => {
      const result = service.getConfiguration();

      expect(result).toEqual({
        algorithm: 'RS256',
        issuer: 'auth-service',
        audience: 'auth-client',
        keyType: 'RSA',
      });
    });
  });

  describe('healthCheck', () => {
    it('should return true when service is healthy', async () => {
      const mockToken = 'health.check.token';
      const mockPayload: JwtPayload = {
        sub: 'health-check-user',
        email: 'health@example.com',
        type: TokenType.ACCESS,
        iat: 1234567890,
        exp: 9999999999,
      };

      mockedJwt.sign.mockReturnValue(mockToken);
      mockedJwt.verify.mockReturnValue(mockPayload);

      const result = await service.healthCheck();

      expect(result).toBe(true);
    });

    it('should return false when token generation fails', async () => {
      mockedJwt.sign.mockImplementation(() => {
        throw new Error('Token generation failed');
      });

      const result = await service.healthCheck();

      expect(result).toBe(false);
    });

    it('should return false when token validation fails', async () => {
      const mockToken = 'health.check.token';
      
      mockedJwt.sign.mockReturnValue(mockToken);
      mockedJwt.verify.mockImplementation(() => {
        throw new jwt.JsonWebTokenError('invalid token');
      });

      const result = await service.healthCheck();

      expect(result).toBe(false);
    });
  });
});