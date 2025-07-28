import { Token } from './token.entity';
import { TokenType } from '@auth/shared';

describe('Token Entity', () => {
  describe('constructor', () => {
    it('should create a token with valid data', () => {
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 1);

      const token = new Token(
        '123',
        'user-456',
        TokenType.ACCESS,
        'token-value',
        expiresAt
      );

      expect(token.id).toBe('123');
      expect(token.userId).toBe('user-456');
      expect(token.type).toBe(TokenType.ACCESS);
      expect(token.value).toBe('token-value');
      expect(token.expiresAt).toEqual(expiresAt);
      expect(token.isValid()).toBe(true);
    });

    it('should throw error for past expiration date', () => {
      const pastDate = new Date();
      pastDate.setHours(pastDate.getHours() - 1);

      expect(() => {
        new Token('123', 'user-456', TokenType.ACCESS, 'token-value', pastDate);
      }).toThrow('Token expiration date must be in the future');
    });
  });

  describe('factory methods', () => {
    describe('create', () => {
      it('should create a token using factory method', () => {
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 1);

        const token = Token.create({
          id: '123',
          userId: 'user-456',
          type: TokenType.REFRESH,
          value: 'token-value',
          expiresAt: expiresAt,
        });

        expect(token).toBeInstanceOf(Token);
        expect(token.type).toBe(TokenType.REFRESH);
      });
    });

    describe('createAccessToken', () => {
      it('should create an access token with default expiration', () => {
        const token = Token.createAccessToken({
          id: '123',
          userId: 'user-456',
          value: 'access-token-value',
        });

        expect(token.type).toBe(TokenType.ACCESS);
        expect(token.getTimeUntilExpirationInSeconds()).toBeCloseTo(15 * 60, -1);
      });

      it('should create an access token with custom expiration', () => {
        const token = Token.createAccessToken({
          id: '123',
          userId: 'user-456',
          value: 'access-token-value',
          expirationMinutes: 30,
        });

        expect(token.getTimeUntilExpirationInSeconds()).toBeCloseTo(30 * 60, -1);
      });
    });

    describe('createRefreshToken', () => {
      it('should create a refresh token with default expiration', () => {
        const token = Token.createRefreshToken({
          id: '123',
          userId: 'user-456',
          value: 'refresh-token-value',
        });

        expect(token.type).toBe(TokenType.REFRESH);
        expect(token.getTimeUntilExpirationInSeconds()).toBeCloseTo(7 * 24 * 60 * 60, -1);
      });

      it('should create a refresh token with custom expiration', () => {
        const token = Token.createRefreshToken({
          id: '123',
          userId: 'user-456',
          value: 'refresh-token-value',
          expirationDays: 14,
        });

        expect(token.getTimeUntilExpirationInSeconds()).toBeCloseTo(14 * 24 * 60 * 60, -1);
      });
    });
  });

  describe('expiration methods', () => {
    let token: Token;
    let futureDate: Date;

    beforeEach(() => {
      futureDate = new Date();
      futureDate.setHours(futureDate.getHours() + 1);
      token = new Token('123', 'user-456', TokenType.ACCESS, 'token-value', futureDate);
    });

    describe('isExpired', () => {
      it('should return false for non-expired token', () => {
        expect(token.isExpired()).toBe(false);
      });

      it('should return true for expired token', () => {
        const expiredDate = new Date();
        expiredDate.setSeconds(expiredDate.getSeconds() + 1); // 1 second in future to pass validation
        const expiredToken = new Token('123', 'user-456', TokenType.ACCESS, 'token-value', expiredDate);
        
        // Mock current time to be after expiration
        jest.useFakeTimers();
        jest.setSystemTime(new Date(expiredDate.getTime() + 1000));
        
        expect(expiredToken.isExpired()).toBe(true);
        
        jest.useRealTimers();
      });
    });

    describe('willExpireSoon', () => {
      it('should return true if token expires within threshold', () => {
        const soonDate = new Date();
        soonDate.setMinutes(soonDate.getMinutes() + 4); // 4 minutes from now
        const soonToken = new Token('123', 'user-456', TokenType.ACCESS, 'token-value', soonDate);

        expect(soonToken.willExpireSoon(5)).toBe(true); // Within 5 minutes
        expect(soonToken.willExpireSoon(3)).toBe(false); // Not within 3 minutes
      });

      it('should return false for expired token', () => {
        const expiredDate = new Date();
        expiredDate.setSeconds(expiredDate.getSeconds() + 1);
        const expiredToken = new Token('123', 'user-456', TokenType.ACCESS, 'token-value', expiredDate);
        
        jest.useFakeTimers();
        jest.setSystemTime(new Date(expiredDate.getTime() + 1000));
        
        expect(expiredToken.willExpireSoon(5)).toBe(false);
        
        jest.useRealTimers();
      });
    });

    describe('getTimeUntilExpiration', () => {
      it('should return correct time until expiration', () => {
        const timeUntilExpiration = token.getTimeUntilExpiration();
        expect(timeUntilExpiration).toBeGreaterThan(0);
        expect(timeUntilExpiration).toBeLessThanOrEqual(60 * 60 * 1000); // 1 hour
      });
    });

    describe('extendExpiration', () => {
      it('should extend token expiration', () => {
        const originalExpiration = token.expiresAt.getTime();
        token.extendExpiration(30); // Extend by 30 minutes
        
        expect(token.expiresAt.getTime()).toBe(originalExpiration + 30 * 60 * 1000);
      });

      it('should throw error when extending revoked token', () => {
        token.revoke();
        expect(() => {
          token.extendExpiration(30);
        }).toThrow('Cannot extend expiration of revoked token');
      });

      it('should throw error when extending expired token', () => {
        const expiredDate = new Date();
        expiredDate.setSeconds(expiredDate.getSeconds() + 1);
        const expiredToken = new Token('123', 'user-456', TokenType.ACCESS, 'token-value', expiredDate);
        
        jest.useFakeTimers();
        jest.setSystemTime(new Date(expiredDate.getTime() + 1000));
        
        expect(() => {
          expiredToken.extendExpiration(30);
        }).toThrow('Cannot extend expiration of expired token');
        
        jest.useRealTimers();
      });
    });
  });

  describe('revocation', () => {
    let token: Token;

    beforeEach(() => {
      const futureDate = new Date();
      futureDate.setHours(futureDate.getHours() + 1);
      token = new Token('123', 'user-456', TokenType.ACCESS, 'token-value', futureDate);
    });

    it('should revoke token', () => {
      expect(token.getRevocationStatus()).toBe(false);
      token.revoke();
      expect(token.getRevocationStatus()).toBe(true);
    });

    it('should throw error when revoking already revoked token', () => {
      token.revoke();
      expect(() => {
        token.revoke();
      }).toThrow('Token is already revoked');
    });

    it('should make token invalid after revocation', () => {
      expect(token.isValid()).toBe(true);
      token.revoke();
      expect(token.isValid()).toBe(false);
    });
  });

  describe('isValid', () => {
    it('should return true for valid token', () => {
      const futureDate = new Date();
      futureDate.setHours(futureDate.getHours() + 1);
      const token = new Token('123', 'user-456', TokenType.ACCESS, 'token-value', futureDate);

      expect(token.isValid()).toBe(true);
    });

    it('should return false for revoked token', () => {
      const futureDate = new Date();
      futureDate.setHours(futureDate.getHours() + 1);
      const token = new Token('123', 'user-456', TokenType.ACCESS, 'token-value', futureDate);
      
      token.revoke();
      expect(token.isValid()).toBe(false);
    });

    it('should return false for expired token', () => {
      const expiredDate = new Date();
      expiredDate.setSeconds(expiredDate.getSeconds() + 1);
      const token = new Token('123', 'user-456', TokenType.ACCESS, 'token-value', expiredDate);
      
      jest.useFakeTimers();
      jest.setSystemTime(new Date(expiredDate.getTime() + 1000));
      
      expect(token.isValid()).toBe(false);
      
      jest.useRealTimers();
    });
  });

  describe('serialization', () => {
    let token: Token;

    beforeEach(() => {
      const futureDate = new Date();
      futureDate.setHours(futureDate.getHours() + 1);
      token = new Token('123', 'user-456', TokenType.ACCESS, 'token-value', futureDate);
    });

    describe('toObject', () => {
      it('should convert token to plain object with all data', () => {
        const obj = token.toObject();

        expect(obj).toEqual({
          id: '123',
          userId: 'user-456',
          type: TokenType.ACCESS,
          value: 'token-value',
          expiresAt: token.expiresAt,
          isRevoked: false,
          createdAt: expect.any(Date),
          isValid: true,
          isExpired: false,
        });
      });
    });

    describe('toSafeObject', () => {
      it('should convert token to safe object without sensitive data', () => {
        const obj = token.toSafeObject();

        expect(obj).toEqual({
          id: '123',
          type: TokenType.ACCESS,
          expiresAt: token.expiresAt,
          isValid: true,
        });

        expect(obj['value']).toBeUndefined();
        expect(obj['userId']).toBeUndefined();
      });
    });
  });
});