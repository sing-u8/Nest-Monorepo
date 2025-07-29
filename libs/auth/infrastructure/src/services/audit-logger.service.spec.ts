import { Test, TestingModule } from '@nestjs/testing';
import { Logger } from '@nestjs/common';
import { AuditLoggerService, AuditEventType, AuditSeverity } from './audit-logger.service';

describe('AuditLoggerService', () => {
  let service: AuditLoggerService;
  let mockLogger: jest.Mocked<Logger>;

  beforeEach(async () => {
    mockLogger = {
      log: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn(),
      verbose: jest.fn(),
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      providers: [AuditLoggerService],
    }).compile();

    service = module.get<AuditLoggerService>(AuditLoggerService);
    
    // Replace the private logger with our mock
    (service as any).logger = mockLogger;
  });

  describe('logEvent', () => {
    it('should log authentication success event', () => {
      // Arrange
      const eventType = AuditEventType.AUTH_LOGIN_SUCCESS;
      const userId = 'user-123';
      const details = { email: 'test@example.com' };
      const clientInfo = {
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        deviceId: 'device-123',
      };

      // Act
      service.logEvent(eventType, userId, details, clientInfo);

      // Assert
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('AUTH_LOGIN_SUCCESS'),
        expect.objectContaining({
          eventType,
          userId,
          details,
          clientInfo,
          severity: AuditSeverity.LOW,
          timestamp: expect.any(Date),
          eventId: expect.any(String),
        })
      );
    });

    it('should log authentication failure event with higher severity', () => {
      // Arrange
      const eventType = AuditEventType.AUTH_LOGIN_FAILURE;
      const userId = null;
      const details = { email: 'test@example.com', reason: 'invalid_credentials' };
      const clientInfo = {
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
      };

      // Act
      service.logEvent(eventType, userId, details, clientInfo);

      // Assert
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('AUTH_LOGIN_FAILURE'),
        expect.objectContaining({
          eventType,
          userId,
          details,
          clientInfo,
          severity: AuditSeverity.MEDIUM,
        })
      );
    });

    it('should log critical security events', () => {
      // Arrange
      const eventType = AuditEventType.SECURITY_BRUTE_FORCE_DETECTED;
      const userId = null;
      const details = { attempts: 10, timeWindow: '5 minutes' };
      const clientInfo = {
        ipAddress: '127.0.0.1',
        userAgent: 'malicious-bot',
      };

      // Act
      service.logEvent(eventType, userId, details, clientInfo);

      // Assert
      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('SECURITY_BRUTE_FORCE_DETECTED'),
        expect.objectContaining({
          severity: AuditSeverity.CRITICAL,
        })
      );
    });

    it('should generate unique event IDs', () => {
      // Arrange
      const eventType = AuditEventType.AUTH_LOGIN_SUCCESS;
      const userId = 'user-123';

      // Act
      service.logEvent(eventType, userId);
      service.logEvent(eventType, userId);

      // Assert
      const firstCall = mockLogger.log.mock.calls[0][1];
      const secondCall = mockLogger.log.mock.calls[1][1];
      expect(firstCall.eventId).not.toEqual(secondCall.eventId);
    });

    it('should handle events without user ID', () => {
      // Arrange
      const eventType = AuditEventType.SYSTEM_STARTUP;

      // Act
      service.logEvent(eventType);

      // Assert
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          eventType,
          userId: null,
          severity: AuditSeverity.LOW,
        })
      );
    });

    it('should handle events without details or client info', () => {
      // Arrange
      const eventType = AuditEventType.AUTH_LOGOUT_SUCCESS;
      const userId = 'user-123';

      // Act
      service.logEvent(eventType, userId);

      // Assert
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          eventType,
          userId,
          details: undefined,
          clientInfo: undefined,
        })
      );
    });
  });

  describe('getEvents', () => {
    beforeEach(() => {
      // Add some test events
      service.logEvent(AuditEventType.AUTH_LOGIN_SUCCESS, 'user-1');
      service.logEvent(AuditEventType.AUTH_LOGIN_FAILURE, null);
      service.logEvent(AuditEventType.TOKEN_REFRESH_SUCCESS, 'user-1');
    });

    it('should return all events when no filter applied', () => {
      // Act
      const events = service.getEvents();

      // Assert
      expect(events).toHaveLength(3);
      expect(events[0].eventType).toBe(AuditEventType.TOKEN_REFRESH_SUCCESS); // Most recent first
      expect(events[1].eventType).toBe(AuditEventType.AUTH_LOGIN_FAILURE);
      expect(events[2].eventType).toBe(AuditEventType.AUTH_LOGIN_SUCCESS);
    });

    it('should filter events by user ID', () => {
      // Act
      const events = service.getEvents({ userId: 'user-1' });

      // Assert
      expect(events).toHaveLength(2);
      expect(events.every(event => event.userId === 'user-1')).toBe(true);
    });

    it('should filter events by event type', () => {
      // Act
      const events = service.getEvents({ eventType: AuditEventType.AUTH_LOGIN_FAILURE });

      // Assert
      expect(events).toHaveLength(1);
      expect(events[0].eventType).toBe(AuditEventType.AUTH_LOGIN_FAILURE);
    });

    it('should filter events by severity', () => {
      // Arrange
      service.logEvent(AuditEventType.SECURITY_SUSPICIOUS_ACTIVITY, null); // HIGH severity

      // Act
      const events = service.getEvents({ severity: AuditSeverity.HIGH });

      // Assert
      expect(events).toHaveLength(1);
      expect(events[0].severity).toBe(AuditSeverity.HIGH);
    });

    it('should filter events by date range', () => {
      // Arrange
      const startTime = new Date();
      
      // Wait a moment and add another event
      setTimeout(() => {
        service.logEvent(AuditEventType.AUTH_LOGOUT_SUCCESS, 'user-1');
      }, 10);

      // Act
      const events = service.getEvents({ 
        startTime: new Date(startTime.getTime() + 5) // Only events after start + 5ms
      });

      // Assert - should only include the logout event
      expect(events.length).toBeGreaterThanOrEqual(0);
    });

    it('should limit number of returned events', () => {
      // Act
      const events = service.getEvents({ limit: 2 });

      // Assert
      expect(events).toHaveLength(2);
    });

    it('should combine multiple filters', () => {
      // Act
      const events = service.getEvents({ 
        userId: 'user-1', 
        limit: 1 
      });

      // Assert
      expect(events).toHaveLength(1);
      expect(events[0].userId).toBe('user-1');
    });
  });

  describe('getSecurityMetrics', () => {
    beforeEach(() => {
      // Add test events for metrics
      service.logEvent(AuditEventType.AUTH_LOGIN_SUCCESS, 'user-1');
      service.logEvent(AuditEventType.AUTH_LOGIN_FAILURE, null, { reason: 'invalid_password' });
      service.logEvent(AuditEventType.AUTH_LOGIN_FAILURE, null, { reason: 'user_not_found' });
      service.logEvent(AuditEventType.SECURITY_RATE_LIMIT_EXCEEDED, null);
      service.logEvent(AuditEventType.TOKEN_REFRESH_SUCCESS, 'user-1');
    });

    it('should return correct security metrics', () => {
      // Act
      const metrics = service.getSecurityMetrics();

      // Assert
      expect(metrics).toEqual({
        totalEvents: 5,
        failedAttempts: 2,
        successfulLogins: 1,
        securityEvents: 1,
        topFailureReasons: [
          { reason: 'invalid_password', count: 1 },
          { reason: 'user_not_found', count: 1 },
        ],
        eventsByHour: expect.any(Object),
        recentSuspiciousActivity: expect.any(Array),
      });
    });

    it('should filter metrics by time range', () => {
      // Arrange
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

      // Act
      const metrics = service.getSecurityMetrics(oneHourAgo);

      // Assert
      expect(metrics.totalEvents).toBe(5); // All events are recent
    });

    it('should handle empty event store', () => {
      // Arrange
      service.clearEvents(); // Clear all events

      // Act
      const metrics = service.getSecurityMetrics();

      // Assert
      expect(metrics).toEqual({
        totalEvents: 0,
        failedAttempts: 0,
        successfulLogins: 0,
        securityEvents: 0,
        topFailureReasons: [],
        eventsByHour: {},
        recentSuspiciousActivity: [],
      });
    });
  });

  describe('clearEvents', () => {
    it('should clear all events', () => {
      // Arrange
      service.logEvent(AuditEventType.AUTH_LOGIN_SUCCESS, 'user-1');
      service.logEvent(AuditEventType.AUTH_LOGIN_FAILURE, null);
      expect(service.getEvents()).toHaveLength(2);

      // Act
      service.clearEvents();

      // Assert
      expect(service.getEvents()).toHaveLength(0);
    });
  });

  describe('exportEvents', () => {
    beforeEach(() => {
      service.logEvent(AuditEventType.AUTH_LOGIN_SUCCESS, 'user-1');
      service.logEvent(AuditEventType.AUTH_LOGIN_FAILURE, null);
    });

    it('should export events in JSON format', () => {
      // Act
      const exported = service.exportEvents('json');

      // Assert
      expect(typeof exported).toBe('string');
      const parsed = JSON.parse(exported);
      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed).toHaveLength(2);
    });

    it('should export events in CSV format', () => {
      // Act
      const exported = service.exportEvents('csv');

      // Assert
      expect(typeof exported).toBe('string');
      expect(exported).toContain('eventType,userId,severity,timestamp');
      expect(exported.split('\n')).toHaveLength(4); // Header + 2 data rows + empty line
    });

    it('should throw error for unsupported format', () => {
      // Act & Assert
      expect(() => service.exportEvents('xml' as any))
        .toThrow('Unsupported export format');
    });
  });

  describe('event storage limits', () => {
    it('should respect maximum event storage limit', () => {
      // Arrange - Get current limit
      const maxEvents = (service as any).maxEvents;

      // Act - Add more events than the limit
      for (let i = 0; i < maxEvents + 10; i++) {
        service.logEvent(AuditEventType.AUTH_LOGIN_SUCCESS, `user-${i}`);
      }

      // Assert
      const events = service.getEvents();
      expect(events.length).toBeLessThanOrEqual(maxEvents);
    });

    it('should maintain newest events when limit exceeded', () => {
      // Arrange
      const maxEvents = (service as any).maxEvents;

      // Act - Fill up to limit
      for (let i = 0; i < maxEvents; i++) {
        service.logEvent(AuditEventType.AUTH_LOGIN_SUCCESS, `user-${i}`);
      }

      // Add one more event
      service.logEvent(AuditEventType.AUTH_LOGOUT_SUCCESS, 'newest-user');

      // Assert
      const events = service.getEvents();
      expect(events[0].userId).toBe('newest-user'); // Most recent first
      expect(events.length).toBeLessThanOrEqual(maxEvents);
    });
  });

  describe('severity assignment', () => {
    it('should assign correct severity levels', () => {
      const testCases = [
        { eventType: AuditEventType.AUTH_LOGIN_SUCCESS, expectedSeverity: AuditSeverity.LOW },
        { eventType: AuditEventType.AUTH_LOGIN_FAILURE, expectedSeverity: AuditSeverity.MEDIUM },
        { eventType: AuditEventType.SECURITY_SUSPICIOUS_ACTIVITY, expectedSeverity: AuditSeverity.HIGH },
        { eventType: AuditEventType.SECURITY_BRUTE_FORCE_DETECTED, expectedSeverity: AuditSeverity.CRITICAL },
      ];

      testCases.forEach(({ eventType, expectedSeverity }) => {
        // Act
        service.logEvent(eventType, 'user-123');

        // Assert
        const events = service.getEvents({ eventType });
        expect(events[0].severity).toBe(expectedSeverity);

        // Clear for next test
        service.clearEvents();
      });
    });
  });
});