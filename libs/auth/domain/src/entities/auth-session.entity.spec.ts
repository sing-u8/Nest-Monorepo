import { AuthSession } from './auth-session.entity';
import { ClientInfo } from '@auth/shared';

describe('AuthSession Entity', () => {
  const mockClientInfo: ClientInfo = {
    userAgent: 'Mozilla/5.0',
    ipAddress: '192.168.1.1',
    deviceId: 'device-123',
    platform: 'web',
  };

  describe('constructor', () => {
    it('should create a session with valid data', () => {
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 24);

      const session = new AuthSession(
        'session-123',
        'user-456',
        'session-token',
        mockClientInfo,
        expiresAt
      );

      expect(session.id).toBe('session-123');
      expect(session.userId).toBe('user-456');
      expect(session.sessionToken).toBe('session-token');
      expect(session.clientInfo).toEqual(mockClientInfo);
      expect(session.expiresAt).toEqual(expiresAt);
      expect(session.isValid()).toBe(true);
    });

    it('should throw error for past expiration date', () => {
      const pastDate = new Date();
      pastDate.setHours(pastDate.getHours() - 1);

      expect(() => {
        new AuthSession(
          'session-123',
          'user-456',
          'session-token',
          mockClientInfo,
          pastDate
        );
      }).toThrow('Session expiration date must be in the future');
    });
  });

  describe('create factory method', () => {
    it('should create a session with default expiration', () => {
      const session = AuthSession.create({
        id: 'session-123',
        userId: 'user-456',
        sessionToken: 'session-token',
        clientInfo: mockClientInfo,
      });

      expect(session).toBeInstanceOf(AuthSession);
      // Default expiration is 24 hours
      const expectedExpiration = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
      expect(session.getTimeUntilExpiration()).toBeCloseTo(expectedExpiration, -4);
    });

    it('should create a session with custom expiration', () => {
      const session = AuthSession.create({
        id: 'session-123',
        userId: 'user-456',
        sessionToken: 'session-token',
        clientInfo: mockClientInfo,
        expirationHours: 48,
      });

      const expectedExpiration = 48 * 60 * 60 * 1000; // 48 hours in milliseconds
      expect(session.getTimeUntilExpiration()).toBeCloseTo(expectedExpiration, -4);
    });
  });

  describe('expiration methods', () => {
    let session: AuthSession;

    beforeEach(() => {
      session = AuthSession.create({
        id: 'session-123',
        userId: 'user-456',
        sessionToken: 'session-token',
        clientInfo: mockClientInfo,
      });
    });

    describe('isExpired', () => {
      it('should return false for non-expired session', () => {
        expect(session.isExpired()).toBe(false);
      });

      it('should return true for expired session', () => {
        const expiredDate = new Date();
        expiredDate.setSeconds(expiredDate.getSeconds() + 1);
        const expiredSession = new AuthSession(
          'session-123',
          'user-456',
          'session-token',
          mockClientInfo,
          expiredDate
        );

        jest.useFakeTimers();
        jest.setSystemTime(new Date(expiredDate.getTime() + 1000));

        expect(expiredSession.isExpired()).toBe(true);

        jest.useRealTimers();
      });
    });

    describe('extendSession', () => {
      it('should extend session expiration', () => {
        const originalExpiration = session.expiresAt.getTime();
        session.extendSession(2); // Extend by 2 hours

        expect(session.expiresAt.getTime()).toBeGreaterThan(originalExpiration);
        expect(session.getLastActivityAt()).toEqual(expect.any(Date));
      });

      it('should throw error when extending inactive session', () => {
        session.invalidate();
        expect(() => {
          session.extendSession(2);
        }).toThrow('Cannot extend inactive session');
      });

      it('should throw error when extending expired session', () => {
        const expiredDate = new Date();
        expiredDate.setSeconds(expiredDate.getSeconds() + 1);
        const expiredSession = new AuthSession(
          'session-123',
          'user-456',
          'session-token',
          mockClientInfo,
          expiredDate
        );

        jest.useFakeTimers();
        jest.setSystemTime(new Date(expiredDate.getTime() + 1000));

        expect(() => {
          expiredSession.extendSession(2);
        }).toThrow('Cannot extend expired session');

        jest.useRealTimers();
      });
    });
  });

  describe('activity tracking', () => {
    let session: AuthSession;

    beforeEach(() => {
      session = AuthSession.create({
        id: 'session-123',
        userId: 'user-456',
        sessionToken: 'session-token',
        clientInfo: mockClientInfo,
      });
    });

    describe('updateActivity', () => {
      it('should update last activity timestamp', () => {
        const originalActivity = session.getLastActivityAt();

        // Wait a bit to ensure time difference
        jest.useFakeTimers();
        jest.advanceTimersByTime(1000);

        session.updateActivity();
        const newActivity = session.getLastActivityAt();

        expect(newActivity.getTime()).toBeGreaterThan(originalActivity.getTime());

        jest.useRealTimers();
      });

      it('should throw error when updating activity on inactive session', () => {
        session.invalidate();
        expect(() => {
          session.updateActivity();
        }).toThrow('Cannot update activity on inactive session');
      });

      it('should throw error when updating activity on expired session', () => {
        const expiredDate = new Date();
        expiredDate.setSeconds(expiredDate.getSeconds() + 1);
        const expiredSession = new AuthSession(
          'session-123',
          'user-456',
          'session-token',
          mockClientInfo,
          expiredDate
        );

        jest.useFakeTimers();
        jest.setSystemTime(new Date(expiredDate.getTime() + 1000));

        expect(() => {
          expiredSession.updateActivity();
        }).toThrow('Cannot update activity on expired session');

        jest.useRealTimers();
      });
    });

    describe('isIdle', () => {
      it('should return false for recently active session', () => {
        expect(session.isIdle(30)).toBe(false);
      });

      it('should return true for idle session', () => {
        jest.useFakeTimers();
        jest.advanceTimersByTime(31 * 60 * 1000); // 31 minutes

        expect(session.isIdle(30)).toBe(true);
        expect(session.isIdle(35)).toBe(false);

        jest.useRealTimers();
      });
    });

    describe('getTimeSinceLastActivity', () => {
      it('should return correct time since last activity', () => {
        jest.useFakeTimers();
        jest.advanceTimersByTime(5 * 60 * 1000); // 5 minutes

        const timeSinceActivity = session.getTimeSinceLastActivity();
        expect(timeSinceActivity).toBe(5 * 60 * 1000);

        jest.useRealTimers();
      });
    });
  });

  describe('session validation', () => {
    let session: AuthSession;

    beforeEach(() => {
      session = AuthSession.create({
        id: 'session-123',
        userId: 'user-456',
        sessionToken: 'session-token',
        clientInfo: mockClientInfo,
      });
    });

    describe('isValid', () => {
      it('should return true for active and non-expired session', () => {
        expect(session.isValid()).toBe(true);
      });

      it('should return false for inactive session', () => {
        session.invalidate();
        expect(session.isValid()).toBe(false);
      });

      it('should return false for expired session', () => {
        const expiredDate = new Date();
        expiredDate.setSeconds(expiredDate.getSeconds() + 1);
        const expiredSession = new AuthSession(
          'session-123',
          'user-456',
          'session-token',
          mockClientInfo,
          expiredDate
        );

        jest.useFakeTimers();
        jest.setSystemTime(new Date(expiredDate.getTime() + 1000));

        expect(expiredSession.isValid()).toBe(false);

        jest.useRealTimers();
      });
    });

    describe('invalidate', () => {
      it('should invalidate active session', () => {
        expect(session.getActiveStatus()).toBe(true);
        session.invalidate();
        expect(session.getActiveStatus()).toBe(false);
        expect(session.isValid()).toBe(false);
      });

      it('should throw error when invalidating already inactive session', () => {
        session.invalidate();
        expect(() => {
          session.invalidate();
        }).toThrow('Session is already inactive');
      });
    });

    describe('getStatus', () => {
      it('should return active for valid session', () => {
        expect(session.getStatus()).toBe('active');
      });

      it('should return inactive for invalidated session', () => {
        session.invalidate();
        expect(session.getStatus()).toBe('inactive');
      });

      it('should return expired for expired session', () => {
        const expiredDate = new Date();
        expiredDate.setSeconds(expiredDate.getSeconds() + 1);
        const expiredSession = new AuthSession(
          'session-123',
          'user-456',
          'session-token',
          mockClientInfo,
          expiredDate
        );

        jest.useFakeTimers();
        jest.setSystemTime(new Date(expiredDate.getTime() + 1000));

        expect(expiredSession.getStatus()).toBe('expired');

        jest.useRealTimers();
      });

      it('should return idle for idle session', () => {
        jest.useFakeTimers();
        jest.advanceTimersByTime(31 * 60 * 1000); // 31 minutes

        expect(session.getStatus()).toBe('idle');

        jest.useRealTimers();
      });
    });
  });

  describe('client info methods', () => {
    let session: AuthSession;

    beforeEach(() => {
      session = AuthSession.create({
        id: 'session-123',
        userId: 'user-456',
        sessionToken: 'session-token',
        clientInfo: mockClientInfo,
      });
    });

    it('should check if session is from specific device', () => {
      expect(session.isFromDevice('device-123')).toBe(true);
      expect(session.isFromDevice('device-456')).toBe(false);
    });

    it('should check if session is from specific IP address', () => {
      expect(session.isFromIpAddress('192.168.1.1')).toBe(true);
      expect(session.isFromIpAddress('192.168.1.2')).toBe(false);
    });
  });

  describe('serialization', () => {
    let session: AuthSession;

    beforeEach(() => {
      session = AuthSession.create({
        id: 'session-123',
        userId: 'user-456',
        sessionToken: 'session-token',
        clientInfo: mockClientInfo,
      });
    });

    describe('toObject', () => {
      it('should convert session to plain object with all data', () => {
        const obj = session.toObject();

        expect(obj).toEqual({
          id: 'session-123',
          userId: 'user-456',
          sessionToken: 'session-token',
          clientInfo: mockClientInfo,
          expiresAt: session.expiresAt,
          isActive: true,
          createdAt: expect.any(Date),
          lastActivityAt: expect.any(Date),
          status: 'active',
          isValid: true,
        });
      });
    });

    describe('toSafeObject', () => {
      it('should convert session to safe object without sensitive data', () => {
        const obj = session.toSafeObject();

        expect(obj).toEqual({
          id: 'session-123',
          clientInfo: {
            platform: 'web',
            deviceId: 'device-123',
          },
          expiresAt: session.expiresAt,
          createdAt: expect.any(Date),
          lastActivityAt: expect.any(Date),
          status: 'active',
        });

        expect(obj['sessionToken']).toBeUndefined();
        expect(obj['userId']).toBeUndefined();
        expect(obj['clientInfo']['ipAddress']).toBeUndefined();
        expect(obj['clientInfo']['userAgent']).toBeUndefined();
      });
    });
  });
});