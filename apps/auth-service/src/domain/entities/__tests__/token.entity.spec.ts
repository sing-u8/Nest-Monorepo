import { Token } from '../token.entity';
import { TokenType } from '@auth/shared/types/auth.types';

describe('Token Entity', () => {
  const validTokenData = {
    id: 'token-123',
    userId: 'user-123',
    type: TokenType.ACCESS,
    value: 'jwt-token-value',
    expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
  };

  describe('constructor', () => {
    it('should create a token with valid data', () => {
      const token = new Token(
        validTokenData.id,
        validTokenData.userId,
        validTokenData.type,
        validTokenData.value,
        validTokenData.expiresAt
      );

      expect(token.id).toBe(validTokenData.id);
      expect(token.userId).toBe(validTokenData.userId);
      expect(token.type).toBe(validTokenData.type);
      expect(token.value).toBe(validTokenData.value);
      expect(token.expiresAt).toEqual(validTokenData.expiresAt);
      expect(token.getIsRevoked()).toBe(false);
    });

    it('should throw error for empty token ID', () => {
      expect(() => {
        new Token('', validTokenData.userId, validTokenData.type, validTokenData.value, validTokenData.expiresAt);
      }).toThrow('Token ID is required');
    });

    it('should throw error for empty user ID', () => {
      expect(() => {
        new Token(validTokenData.id, '', validTokenData.type, validTokenData.value, validTokenData.expiresAt);
      }).toThrow('User ID is required');
    });

    it('should throw error for empty token value', () => {
      expect(() => {
        new Token(validTokenData.id, validTokenData.userId, validTokenData.type, '', validTokenData.expiresAt);
      }).toThrow('Token value is required');
    });

    it('should throw error for invalid token type', () => {
      expect(() => {
        new Token(
          validTokenData.id,
          validTokenData.userId,
          'invalid-type' as TokenType,
          validTokenData.value,
          validTokenData.expiresAt
        );
      }).toThrow('Invalid token type');
    });

    it('should throw error for invalid expiration date', () => {
      expect(() => {
        new Token(
          validTokenData.id,
          validTokenData.userId,
          validTokenData.type,
          validTokenData.value,
          new Date('invalid-date')
        );
      }).toThrow('Invalid expiration date');
    });

    it('should throw error for expiration date in the past', () => {
      const pastDate = new Date(Date.now() - 3600000);
      expect(() => {
        new Token(validTokenData.id, validTokenData.userId, validTokenData.type, validTokenData.value, pastDate);
      }).toThrow('Token expiration date must be in the future');
    });
  });

  describe('isExpired', () => {
    it('should return false for non-expired token', () => {
      const futureDate = new Date(Date.now() + 3600000);
      const token = new Token(
        validTokenData.id,
        validTokenData.userId,
        validTokenData.type,
        validTokenData.value,
        futureDate
      );

      expect(token.isExpired()).toBe(false);
    });

    it('should return true for expired token', () => {
      const pastDate = new Date(Date.now() + 100); // 100ms in future
      const token = new Token(
        validTokenData.id,
        validTokenData.userId,
        validTokenData.type,
        validTokenData.value,
        pastDate,
        false,
        new Date(Date.now() - 1000) // created 1 second ago
      );

      // Wait for token to expire
      jest.advanceTimersByTime(200);

      expect(token.isExpired()).toBe(true);
    });
  });

  describe('revoke', () => {
    it('should revoke a valid token', () => {
      const token = new Token(
        validTokenData.id,
        validTokenData.userId,
        validTokenData.type,
        validTokenData.value,
        validTokenData.expiresAt
      );

      expect(token.getIsRevoked()).toBe(false);
      token.revoke();
      expect(token.getIsRevoked()).toBe(true);
    });

    it('should throw error when revoking already revoked token', () => {
      const token = new Token(
        validTokenData.id,
        validTokenData.userId,
        validTokenData.type,
        validTokenData.value,
        validTokenData.expiresAt,
        true
      );

      expect(() => {
        token.revoke();
      }).toThrow('Token is already revoked');
    });
  });

  describe('isValid', () => {
    it('should return true for valid token', () => {
      const token = new Token(
        validTokenData.id,
        validTokenData.userId,
        validTokenData.type,
        validTokenData.value,
        validTokenData.expiresAt
      );

      expect(token.isValid()).toBe(true);
    });

    it('should return false for revoked token', () => {
      const token = new Token(
        validTokenData.id,
        validTokenData.userId,
        validTokenData.type,
        validTokenData.value,
        validTokenData.expiresAt
      );

      token.revoke();
      expect(token.isValid()).toBe(false);
    });

    it('should return false for expired token', () => {
      const nearFutureDate = new Date(Date.now() + 100);
      const token = new Token(
        validTokenData.id,
        validTokenData.userId,
        validTokenData.type,
        validTokenData.value,
        nearFutureDate,
        false,
        new Date(Date.now() - 1000)
      );

      jest.advanceTimersByTime(200);
      expect(token.isValid()).toBe(false);
    });
  });

  describe('getRemainingTime', () => {
    it('should return remaining time for valid token', () => {
      const expirationTime = Date.now() + 3600000; // 1 hour
      const token = new Token(
        validTokenData.id,
        validTokenData.userId,
        validTokenData.type,
        validTokenData.value,
        new Date(expirationTime)
      );

      const remainingTime = token.getRemainingTime();
      expect(remainingTime).toBeGreaterThan(3599000); // Close to 1 hour
      expect(remainingTime).toBeLessThanOrEqual(3600000);
    });

    it('should return 0 for invalid token', () => {
      const token = new Token(
        validTokenData.id,
        validTokenData.userId,
        validTokenData.type,
        validTokenData.value,
        validTokenData.expiresAt
      );

      token.revoke();
      expect(token.getRemainingTime()).toBe(0);
    });
  });

  describe('toJSON', () => {
    it('should return JSON representation with calculated fields', () => {
      const token = new Token(
        validTokenData.id,
        validTokenData.userId,
        validTokenData.type,
        validTokenData.value,
        validTokenData.expiresAt
      );

      const json = token.toJSON();

      expect(json).toMatchObject({
        id: validTokenData.id,
        userId: validTokenData.userId,
        type: validTokenData.type,
        value: validTokenData.value,
        expiresAt: validTokenData.expiresAt,
        isRevoked: false,
        isValid: true,
      });
      expect(json.remainingTime).toBeGreaterThan(0);
    });
  });
});