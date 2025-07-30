import { AuthSession } from '../auth-session.entity';
import { ClientInfo } from '@auth/shared/types/auth.types';

describe('AuthSession Entity', () => {
  const validSessionData = {
    id: 'session-123',
    userId: 'user-123',
    sessionToken: 'session-token-value',
    clientInfo: {
      userAgent: 'Mozilla/5.0',
      ipAddress: '192.168.1.1',
      deviceId: 'device-123',
    } as ClientInfo,
    expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
  };

  describe('constructor', () => {
    it('should create a session with valid data', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo
      );

      expect(session.id).toBe(validSessionData.id);
      expect(session.userId).toBe(validSessionData.userId);
      expect(session.sessionToken).toBe(validSessionData.sessionToken);
      expect(session.clientInfo).toEqual(validSessionData.clientInfo);
      expect(session.expiresAt).toEqual(validSessionData.expiresAt);
      expect(session.getIsRevoked()).toBe(false);
    });

    it('should create a session without client info', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        undefined
      );

      expect(session.clientInfo).toBeUndefined();
    });

    it('should throw error for empty session ID', () => {
      expect(() => {
        new AuthSession('', validSessionData.userId, validSessionData.sessionToken, validSessionData.expiresAt, undefined);
      }).toThrow('Session ID is required');
    });

    it('should throw error for empty user ID', () => {
      expect(() => {
        new AuthSession(validSessionData.id, '', validSessionData.sessionToken, validSessionData.expiresAt, undefined);
      }).toThrow('User ID is required');
    });

    it('should throw error for empty session token', () => {
      expect(() => {
        new AuthSession(validSessionData.id, validSessionData.userId, '', validSessionData.expiresAt, undefined);
      }).toThrow('Session token is required');
    });

    it('should throw error for invalid expiration date', () => {
      expect(() => {
        new AuthSession(
          validSessionData.id,
          validSessionData.userId,
          validSessionData.sessionToken,
          new Date('invalid-date'),
          undefined
        );
      }).toThrow('Invalid expiration date');
    });

    it('should throw error for expiration date in the past', () => {
      const pastDate = new Date(Date.now() - 3600000);
      expect(() => {
        new AuthSession(validSessionData.id, validSessionData.userId, validSessionData.sessionToken, pastDate, undefined);
      }).toThrow('Session expiration date must be in the future');
    });
  });

  describe('isExpired', () => {
    it('should return false for non-expired session', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo
      );

      expect(session.isExpired()).toBe(false);
    });

    it('should return true for expired session', () => {
      const nearFutureDate = new Date(Date.now() + 100);
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        nearFutureDate,
        validSessionData.clientInfo,
        false,
        new Date(Date.now() - 1000)
      );

      jest.advanceTimersByTime(200);
      expect(session.isExpired()).toBe(true);
    });
  });

  describe('revoke', () => {
    it('should revoke a valid session', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo
      );

      expect(session.getIsRevoked()).toBe(false);
      session.revoke();
      expect(session.getIsRevoked()).toBe(true);
    });

    it('should throw error when revoking already revoked session', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo,
        true
      );

      expect(() => {
        session.revoke();
      }).toThrow('Session is already revoked');
    });
  });

  describe('isValid', () => {
    it('should return true for valid session', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo
      );

      expect(session.isValid()).toBe(true);
    });

    it('should return false for revoked session', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo
      );

      session.revoke();
      expect(session.isValid()).toBe(false);
    });
  });

  describe('updateActivity', () => {
    it('should update last activity time', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo
      );

      const originalActivity = session.getLastActivityAt();
      
      jest.advanceTimersByTime(1000);
      session.updateActivity();
      
      expect(session.getLastActivityAt().getTime()).toBeGreaterThan(originalActivity.getTime());
    });

    it('should throw error when updating activity on invalid session', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo
      );

      session.revoke();

      expect(() => {
        session.updateActivity();
      }).toThrow('Cannot update activity on invalid session');
    });
  });

  describe('getRemainingTime', () => {
    it('should return remaining time for valid session', () => {
      const expirationTime = Date.now() + 3600000; // 1 hour
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        new Date(expirationTime),
        validSessionData.clientInfo
      );

      const remainingTime = session.getRemainingTime();
      expect(remainingTime).toBeGreaterThan(3599000);
      expect(remainingTime).toBeLessThanOrEqual(3600000);
    });

    it('should return 0 for invalid session', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo
      );

      session.revoke();
      expect(session.getRemainingTime()).toBe(0);
    });
  });

  describe('getIdleTime', () => {
    it('should return idle time since last activity', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo,
        false,
        new Date(Date.now() - 5000), // created 5 seconds ago
        new Date(Date.now() - 3000)  // last activity 3 seconds ago
      );

      const idleTime = session.getIdleTime();
      expect(idleTime).toBeGreaterThanOrEqual(3000);
      expect(idleTime).toBeLessThan(4000);
    });
  });

  describe('shouldExpireForInactivity', () => {
    it('should return true when idle time exceeds threshold', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo,
        false,
        new Date(Date.now() - 10000), // created 10 seconds ago
        new Date(Date.now() - 5000)   // last activity 5 seconds ago
      );

      expect(session.shouldExpireForInactivity(3000)).toBe(true);  // 3 second threshold
      expect(session.shouldExpireForInactivity(10000)).toBe(false); // 10 second threshold
    });
  });

  describe('toJSON', () => {
    it('should return JSON representation with calculated fields', () => {
      const session = new AuthSession(
        validSessionData.id,
        validSessionData.userId,
        validSessionData.sessionToken,
        validSessionData.expiresAt,
        validSessionData.clientInfo
      );

      const json = session.toJSON();

      expect(json).toMatchObject({
        id: validSessionData.id,
        userId: validSessionData.userId,
        sessionToken: validSessionData.sessionToken,
        clientInfo: validSessionData.clientInfo,
        expiresAt: validSessionData.expiresAt,
        isRevoked: false,
        isValid: true,
      });
      expect(json.remainingTime).toBeGreaterThan(0);
      expect(json.idleTime).toBeGreaterThanOrEqual(0);
    });
  });
});