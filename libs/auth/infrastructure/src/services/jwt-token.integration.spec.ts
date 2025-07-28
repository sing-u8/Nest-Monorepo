import { Test, TestingModule } from '@nestjs/testing';
import { JwtTokenService } from './jwt-token.service';
import { TokenType, JwtPayload } from '@auth/shared';

describe('JwtTokenService (Integration)', () => {
  let service: JwtTokenService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [JwtTokenService],
    }).compile();

    service = module.get<JwtTokenService>(JwtTokenService);
  });

  describe('Real JWT operations', () => {
    it('should generate and validate access token correctly', async () => {
      const userId = 'user123';
      const email = 'test@example.com';

      // Generate access token
      const accessToken = await service.generateAccessToken(userId, email, '15m');

      // Token should be in JWT format
      expect(accessToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

      // Validate the token
      const validation = await service.validateToken(accessToken);

      expect(validation.isValid).toBe(true);
      expect(validation.payload).toMatchObject({
        sub: userId,
        email,
        type: TokenType.ACCESS,
      });
      expect(validation.payload?.iat).toBeDefined();
      expect(validation.payload?.exp).toBeDefined();
    });

    it('should generate and validate refresh token correctly', async () => {
      const userId = 'user456';
      const email = 'refresh@example.com';

      // Generate refresh token
      const refreshToken = await service.generateRefreshToken(userId, email, '7d');

      // Token should be in JWT format
      expect(refreshToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

      // Validate the token
      const validation = await service.validateToken(refreshToken);

      expect(validation.isValid).toBe(true);
      expect(validation.payload).toMatchObject({
        sub: userId,
        email,
        type: TokenType.REFRESH,
      });
    });

    it('should decode token without verification', () => {
      const userId = 'user789';
      const email = 'decode@example.com';

      return service.generateAccessToken(userId, email).then(token => {
        const decoded = service.decodeToken(token);

        expect(decoded).toMatchObject({
          sub: userId,
          email,
          type: TokenType.ACCESS,
        });
        expect(decoded?.iat).toBeDefined();
        expect(decoded?.exp).toBeDefined();
        expect(decoded?.iss).toBe('auth-service');
        expect(decoded?.aud).toBe('auth-client');
      });
    });

    it('should handle token expiration correctly', async () => {
      const userId = 'user000';
      const email = 'expire@example.com';

      // Generate token with very short expiration
      const shortLivedToken = await service.generateAccessToken(userId, email, '1s');

      // Token should be valid initially
      let validation = await service.validateToken(shortLivedToken);
      expect(validation.isValid).toBe(true);

      // Wait for token to expire
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Token should now be expired
      validation = await service.validateToken(shortLivedToken);
      expect(validation.isValid).toBe(false);
      expect(validation.error).toBe('Token has expired');
    });

    it('should get token expiration correctly', async () => {
      const userId = 'user111';
      const email = 'expiration@example.com';

      const token = await service.generateAccessToken(userId, email, '1h');
      const expiration = service.getTokenExpiration(token);

      expect(expiration).toBeInstanceOf(Date);
      expect(expiration!.getTime()).toBeGreaterThan(Date.now());
      
      // Should expire approximately in 1 hour (with some tolerance)
      const expectedExpiration = Date.now() + (60 * 60 * 1000);
      const timeDiff = Math.abs(expiration!.getTime() - expectedExpiration);
      expect(timeDiff).toBeLessThan(5000); // 5 second tolerance
    });

    it('should check token expiration status correctly', async () => {
      const userId = 'user222';
      const email = 'status@example.com';

      // Test non-expired token
      const validToken = await service.generateAccessToken(userId, email, '1h');
      expect(service.isTokenExpired(validToken)).toBe(false);

      // Test expired token
      const expiredToken = await service.generateAccessToken(userId, email, '1s');
      await new Promise(resolve => setTimeout(resolve, 1100));
      expect(service.isTokenExpired(expiredToken)).toBe(true);
    });

    it('should calculate time until expiration correctly', async () => {
      const userId = 'user333';
      const email = 'time@example.com';

      const token = await service.generateAccessToken(userId, email, '5m');
      const timeUntilExpiration = service.getTimeUntilExpiration(token);

      // Should have approximately 5 minutes (300,000 ms) remaining
      expect(timeUntilExpiration).toBeGreaterThan(290000); // 4 min 50 sec
      expect(timeUntilExpiration).toBeLessThanOrEqual(300000); // 5 minutes
    });

    it('should refresh access token from refresh token', async () => {
      const userId = 'user444';
      const email = 'refresh@example.com';

      // Generate refresh token
      const refreshToken = await service.generateRefreshToken(userId, email, '7d');

      // Use refresh token to get new access token
      const newAccessToken = await service.refreshAccessToken(refreshToken);

      expect(newAccessToken).toBeDefined();
      expect(newAccessToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

      // Validate the new access token
      const validation = await service.validateToken(newAccessToken!);
      expect(validation.isValid).toBe(true);
      expect(validation.payload?.type).toBe(TokenType.ACCESS);
      expect(validation.payload?.sub).toBe(userId);
      expect(validation.payload?.email).toBe(email);
    });

    it('should not refresh access token from access token', async () => {
      const userId = 'user555';
      const email = 'nofresh@example.com';

      // Generate access token
      const accessToken = await service.generateAccessToken(userId, email, '15m');

      // Try to refresh using access token (should fail)
      const result = await service.refreshAccessToken(accessToken);

      expect(result).toBeNull();
    });

    it('should blacklist and detect blacklisted tokens', async () => {
      const userId = 'user666';
      const email = 'blacklist@example.com';

      // Generate token
      const token = await service.generateAccessToken(userId, email, '1h');

      // Token should be valid initially
      let validation = await service.validateToken(token);
      expect(validation.isValid).toBe(true);

      // Blacklist the token
      const blacklistResult = await service.blacklistToken(token);
      expect(blacklistResult).toBe(true);

      // Check if token is blacklisted
      const isBlacklisted = await service.isTokenBlacklisted(token);
      expect(isBlacklisted).toBe(true);

      // Token validation should now fail
      validation = await service.validateToken(token);
      expect(validation.isValid).toBe(false);
      expect(validation.error).toBe('Token has been revoked');
    });

    it('should generate secure random tokens', () => {
      // Test default length
      const token1 = service.generateSecureRandomToken();
      expect(token1).toHaveLength(32);
      expect(token1).toMatch(/^[a-f0-9]+$/); // Hex format

      // Test custom length
      const token2 = service.generateSecureRandomToken(16);
      expect(token2).toHaveLength(16);
      expect(token2).toMatch(/^[a-f0-9]+$/);

      // Test uniqueness
      const token3 = service.generateSecureRandomToken();
      expect(token1).not.toBe(token3);
    });

    it('should sign and verify custom data', async () => {
      const testData = {
        userId: 'user777',
        action: 'password-reset',
        timestamp: Date.now()
      };

      // Sign the data
      const signedToken = await service.signData(testData, '1h');
      expect(signedToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

      // Verify the data
      const verifiedData = await service.verifyData(signedToken);
      expect(verifiedData).toMatchObject(testData);
      expect(verifiedData?.iss).toBe('auth-service');
      expect(verifiedData?.aud).toBe('auth-client');
    });

    it('should handle various token types correctly', async () => {
      const userId = 'user888';
      const email = 'types@example.com';

      // Test different token types
      const tokenTypes = [TokenType.ACCESS, TokenType.REFRESH, TokenType.RESET_PASSWORD, TokenType.EMAIL_VERIFICATION];

      for (const tokenType of tokenTypes) {
        const payload: JwtPayload = {
          sub: userId,
          email,
          type: tokenType,
        };

        const token = await service.generateToken(payload, tokenType, '1h');
        const validation = await service.validateToken(token);

        expect(validation.isValid).toBe(true);
        expect(validation.payload?.type).toBe(tokenType);
      }
    });

    it('should maintain token uniqueness', async () => {
      const userId = 'user999';
      const email = 'unique@example.com';

      // Generate multiple tokens with same parameters
      const tokens = await Promise.all([
        service.generateAccessToken(userId, email, '15m'),
        service.generateAccessToken(userId, email, '15m'),
        service.generateAccessToken(userId, email, '15m'),
      ]);

      // All tokens should be unique
      const tokenSet = new Set(tokens);
      expect(tokenSet.size).toBe(3);

      // All tokens should be valid
      for (const token of tokens) {
        const validation = await service.validateToken(token);
        expect(validation.isValid).toBe(true);
      }
    });

    it('should pass health check', async () => {
      const isHealthy = await service.healthCheck();
      expect(isHealthy).toBe(true);
    });

    it('should return correct configuration', () => {
      const config = service.getConfiguration();

      expect(config).toEqual({
        algorithm: 'RS256',
        issuer: 'auth-service',
        audience: 'auth-client',
        keyType: 'RSA',
      });
    });

    it('should handle invalid tokens gracefully', async () => {
      const invalidTokens = [
        '',
        'invalid',
        'invalid.token',
        'invalid.token.format.extra',
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature',
      ];

      for (const invalidToken of invalidTokens) {
        const validation = await service.validateToken(invalidToken);
        expect(validation.isValid).toBe(false);
        expect(validation.error).toBeDefined();

        const decoded = service.decodeToken(invalidToken);
        if (invalidToken.split('.').length === 3) {
          // May decode even if invalid signature
          expect(decoded).toBeDefined();
        } else {
          expect(decoded).toBeNull();
        }

        const expiration = service.getTokenExpiration(invalidToken);
        expect(expiration).toBeNull();

        const isExpired = service.isTokenExpired(invalidToken);
        expect(isExpired).toBe(true);

        const timeUntilExpiration = service.getTimeUntilExpiration(invalidToken);
        expect(timeUntilExpiration).toBe(0);
      }
    });

    it('should maintain performance within reasonable bounds', async () => {
      const userId = 'performance-user';
      const email = 'performance@example.com';

      // Test token generation performance
      const generateStart = Date.now();
      const token = await service.generateAccessToken(userId, email, '15m');
      const generateTime = Date.now() - generateStart;

      // Test token validation performance
      const validateStart = Date.now();
      const validation = await service.validateToken(token);
      const validateTime = Date.now() - validateStart;

      expect(validation.isValid).toBe(true);

      // Performance should be reasonable (adjust based on hardware)
      expect(generateTime).toBeLessThan(1000); // 1 second max
      expect(validateTime).toBeLessThan(1000); // 1 second max

      console.log(`Generate time: ${generateTime}ms, Validate time: ${validateTime}ms`);
    });
  });
});