import { Injectable, Logger } from '@nestjs/common';

export enum AuditEventType {
  // Authentication Events
  AUTH_LOGIN_SUCCESS = 'auth.login.success',
  AUTH_LOGIN_FAILURE = 'auth.login.failure',
  AUTH_LOGIN_BLOCKED = 'auth.login.blocked',
  AUTH_REGISTER_SUCCESS = 'auth.register.success',
  AUTH_REGISTER_FAILURE = 'auth.register.failure',
  AUTH_LOGOUT_SUCCESS = 'auth.logout.success',
  AUTH_LOGOUT_FAILURE = 'auth.logout.failure',
  
  // Token Events
  TOKEN_REFRESH_SUCCESS = 'token.refresh.success',
  TOKEN_REFRESH_FAILURE = 'token.refresh.failure',
  TOKEN_REVOKE_SUCCESS = 'token.revoke.success',
  TOKEN_INVALID = 'token.invalid',
  TOKEN_EXPIRED = 'token.expired',
  
  // Social Authentication Events
  SOCIAL_AUTH_GOOGLE_SUCCESS = 'social.auth.google.success',
  SOCIAL_AUTH_GOOGLE_FAILURE = 'social.auth.google.failure',
  SOCIAL_AUTH_APPLE_SUCCESS = 'social.auth.apple.success',
  SOCIAL_AUTH_APPLE_FAILURE = 'social.auth.apple.failure',
  
  // Profile Events
  PROFILE_UPDATE_SUCCESS = 'profile.update.success',
  PROFILE_UPDATE_FAILURE = 'profile.update.failure',
  PROFILE_PICTURE_UPLOAD_SUCCESS = 'profile.picture.upload.success',
  PROFILE_PICTURE_UPLOAD_FAILURE = 'profile.picture.upload.failure',
  PROFILE_PICTURE_DELETE_SUCCESS = 'profile.picture.delete.success',
  
  // Security Events
  SECURITY_RATE_LIMIT_EXCEEDED = 'security.rate_limit.exceeded',
  SECURITY_IP_BLOCKED = 'security.ip.blocked',
  SECURITY_SUSPICIOUS_ACTIVITY = 'security.suspicious_activity',
  SECURITY_BRUTE_FORCE_DETECTED = 'security.brute_force.detected',
  SECURITY_ACCOUNT_LOCKED = 'security.account.locked',
  SECURITY_PASSWORD_CHANGE = 'security.password.change',
  SECURITY_EMAIL_CHANGE = 'security.email.change',
  
  // Session Events
  SESSION_CREATED = 'session.created',
  SESSION_UPDATED = 'session.updated',
  SESSION_EXPIRED = 'session.expired',
  SESSION_REVOKED = 'session.revoked',
  SESSION_CLEANUP = 'session.cleanup',
  
  // mTLS Events
  MTLS_AUTH_SUCCESS = 'mtls.auth.success',
  MTLS_AUTH_FAILURE = 'mtls.auth.failure',
  MTLS_CERT_INVALID = 'mtls.cert.invalid',
  MTLS_CERT_EXPIRED = 'mtls.cert.expired',
  
  // System Events
  SYSTEM_ERROR = 'system.error',
  SYSTEM_WARNING = 'system.warning',
  SYSTEM_INFO = 'system.info',
}

export enum AuditSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export interface AuditEvent {
  eventType: AuditEventType;
  severity: AuditSeverity;
  timestamp: Date;
  userId?: string;
  sessionId?: string;
  clientInfo: {
    ipAddress: string;
    userAgent?: string;
    deviceId?: string;
    platform?: string;
  };
  details: Record<string, any>;
  success: boolean;
  errorCode?: string;
  errorMessage?: string;
  metadata?: Record<string, any>;
}

export interface SecurityMetrics {
  totalEvents: number;
  securityEvents: number;
  failedAttempts: number;
  blockedIPs: number;
  suspiciousActivities: number;
  topFailureReasons: Array<{ reason: string; count: number }>;
  hourlyDistribution: Array<{ hour: number; count: number }>;
}

/**
 * Audit Logger Service
 * 
 * Provides comprehensive audit logging for authentication and security events.
 * Implements structured logging with proper security event tracking.
 */
@Injectable()
export class AuditLoggerService {
  private readonly logger = new Logger(AuditLoggerService.name);
  private readonly auditEvents: AuditEvent[] = [];
  private readonly maxInMemoryEvents = 10000;
  
  constructor() {
    // Setup cleanup interval
    setInterval(() => this.cleanupOldEvents(), 60 * 60 * 1000); // Every hour
  }

  /**
   * Log authentication success event
   */
  logAuthSuccess(
    eventType: AuditEventType,
    userId: string,
    sessionId: string,
    clientInfo: AuditEvent['clientInfo'],
    details: Record<string, any> = {}
  ): void {
    this.logEvent({
      eventType,
      severity: AuditSeverity.LOW,
      timestamp: new Date(),
      userId,
      sessionId,
      clientInfo,
      details: {
        ...details,
        timestamp: new Date().toISOString(),
      },
      success: true,
    });
  }

  /**
   * Log authentication failure event
   */
  logAuthFailure(
    eventType: AuditEventType,
    clientInfo: AuditEvent['clientInfo'],
    errorCode: string,
    errorMessage: string,
    details: Record<string, any> = {},
    userId?: string
  ): void {
    this.logEvent({
      eventType,
      severity: this.getSeverityForFailure(eventType),
      timestamp: new Date(),
      userId,
      clientInfo,
      details: {
        ...details,
        timestamp: new Date().toISOString(),
        failureReason: errorCode,
      },
      success: false,
      errorCode,
      errorMessage,
    });
  }

  /**
   * Log security event (rate limiting, blocking, suspicious activity)
   */
  logSecurityEvent(
    eventType: AuditEventType,
    severity: AuditSeverity,
    clientInfo: AuditEvent['clientInfo'],
    details: Record<string, any> = {},
    userId?: string
  ): void {
    this.logEvent({
      eventType,
      severity,
      timestamp: new Date(),
      userId,
      clientInfo,
      details: {
        ...details,
        timestamp: new Date().toISOString(),
        securityEvent: true,
      },
      success: false,
    });
  }

  /**
   * Log token-related events
   */
  logTokenEvent(
    eventType: AuditEventType,
    userId: string,
    clientInfo: AuditEvent['clientInfo'],
    success: boolean,
    details: Record<string, any> = {},
    errorCode?: string,
    errorMessage?: string
  ): void {
    this.logEvent({
      eventType,
      severity: success ? AuditSeverity.LOW : AuditSeverity.MEDIUM,
      timestamp: new Date(),
      userId,
      clientInfo,
      details: {
        ...details,
        timestamp: new Date().toISOString(),
        tokenOperation: true,
      },
      success,
      errorCode,
      errorMessage,
    });
  }

  /**
   * Log profile-related events
   */
  logProfileEvent(
    eventType: AuditEventType,
    userId: string,
    clientInfo: AuditEvent['clientInfo'],
    success: boolean,
    details: Record<string, any> = {},
    errorCode?: string,
    errorMessage?: string
  ): void {
    this.logEvent({
      eventType,
      severity: AuditSeverity.LOW,
      timestamp: new Date(),
      userId,
      clientInfo,
      details: {
        ...details,
        timestamp: new Date().toISOString(),
        profileOperation: true,
      },
      success,
      errorCode,
      errorMessage,
    });
  }

  /**
   * Log session events
   */
  logSessionEvent(
    eventType: AuditEventType,
    userId: string,
    sessionId: string,
    clientInfo: AuditEvent['clientInfo'],
    details: Record<string, any> = {}
  ): void {
    this.logEvent({
      eventType,
      severity: AuditSeverity.LOW,
      timestamp: new Date(),
      userId,
      sessionId,
      clientInfo,
      details: {
        ...details,
        timestamp: new Date().toISOString(),
        sessionOperation: true,
      },
      success: true,
    });
  }

  /**
   * Log system events
   */
  logSystemEvent(
    eventType: AuditEventType,
    severity: AuditSeverity,
    details: Record<string, any> = {},
    errorMessage?: string
  ): void {
    this.logEvent({
      eventType,
      severity,
      timestamp: new Date(),
      clientInfo: {
        ipAddress: 'system',
        userAgent: 'system',
      },
      details: {
        ...details,
        timestamp: new Date().toISOString(),
        systemEvent: true,
      },
      success: !errorMessage,
      errorMessage,
    });
  }

  /**
   * Core event logging method
   */
  private logEvent(event: AuditEvent): void {
    // Add to in-memory store
    this.auditEvents.push(event);
    
    // Maintain size limit
    if (this.auditEvents.length > this.maxInMemoryEvents) {
      this.auditEvents.shift();
    }

    // Log to NestJS logger with structured format
    const logData = {
      event: event.eventType,
      severity: event.severity,
      timestamp: event.timestamp.toISOString(),
      userId: event.userId,
      sessionId: event.sessionId,
      clientInfo: event.clientInfo,
      success: event.success,
      errorCode: event.errorCode,
      errorMessage: event.errorMessage,
      details: event.details,
    };

    const logMessage = this.formatLogMessage(event);

    switch (event.severity) {
      case AuditSeverity.CRITICAL:
        this.logger.error(logMessage, JSON.stringify(logData));
        break;
      case AuditSeverity.HIGH:
        this.logger.warn(logMessage, JSON.stringify(logData));
        break;
      case AuditSeverity.MEDIUM:
        this.logger.log(logMessage, JSON.stringify(logData));
        break;
      case AuditSeverity.LOW:
      default:
        this.logger.debug(logMessage, JSON.stringify(logData));
        break;
    }

    // In production, you would also send to external logging system
    // Example: ELK Stack, Splunk, CloudWatch, etc.
    this.sendToExternalLogger(event);
  }

  /**
   * Format log message for human readability
   */
  private formatLogMessage(event: AuditEvent): string {
    const parts = [
      `[${event.eventType}]`,
      event.userId ? `User:${event.userId}` : null,
      event.sessionId ? `Session:${event.sessionId}` : null,
      `IP:${event.clientInfo.ipAddress}`,
      event.success ? 'SUCCESS' : 'FAILURE',
      event.errorCode ? `Error:${event.errorCode}` : null,
    ].filter(Boolean);

    return parts.join(' | ');
  }

  /**
   * Determine severity for failure events
   */
  private getSeverityForFailure(eventType: AuditEventType): AuditSeverity {
    const highSeverityEvents = [
      AuditEventType.AUTH_LOGIN_BLOCKED,
      AuditEventType.SECURITY_BRUTE_FORCE_DETECTED,
      AuditEventType.SECURITY_ACCOUNT_LOCKED,
      AuditEventType.SECURITY_SUSPICIOUS_ACTIVITY,
      AuditEventType.MTLS_CERT_INVALID,
    ];

    const mediumSeverityEvents = [
      AuditEventType.AUTH_LOGIN_FAILURE,
      AuditEventType.TOKEN_REFRESH_FAILURE,
      AuditEventType.TOKEN_INVALID,
      AuditEventType.SECURITY_RATE_LIMIT_EXCEEDED,
    ];

    if (highSeverityEvents.includes(eventType)) {
      return AuditSeverity.HIGH;
    } else if (mediumSeverityEvents.includes(eventType)) {
      return AuditSeverity.MEDIUM;
    } else {
      return AuditSeverity.LOW;
    }
  }

  /**
   * Send events to external logging system
   */
  private sendToExternalLogger(event: AuditEvent): void {
    // In production, implement integration with:
    // - ELK Stack (Elasticsearch, Logstash, Kibana)
    // - Splunk
    // - AWS CloudWatch
    // - Google Cloud Logging
    // - Azure Monitor
    // - Datadog
    // - New Relic
    
    // Example implementation would go here
    if (process.env['NODE_ENV'] === 'production') {
      // Send to external system
    }
  }

  /**
   * Get recent audit events
   */
  getRecentEvents(limit: number = 100, eventType?: AuditEventType): AuditEvent[] {
    let events = this.auditEvents;
    
    if (eventType) {
      events = events.filter(event => event.eventType === eventType);
    }
    
    return events
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  /**
   * Get security metrics
   */
  getSecurityMetrics(hoursBack: number = 24): SecurityMetrics {
    const since = new Date(Date.now() - hoursBack * 60 * 60 * 1000);
    const recentEvents = this.auditEvents.filter(event => event.timestamp >= since);
    
    const securityEvents = recentEvents.filter(event => 
      event.eventType.startsWith('security.') || 
      !event.success
    );
    
    const failedAttempts = recentEvents.filter(event => !event.success);
    
    const blockedIPs = new Set(
      recentEvents
        .filter(event => event.eventType === AuditEventType.SECURITY_IP_BLOCKED)
        .map(event => event.clientInfo.ipAddress)
    ).size;
    
    const suspiciousActivities = recentEvents.filter(event => 
      event.eventType === AuditEventType.SECURITY_SUSPICIOUS_ACTIVITY
    ).length;
    
    // Count failure reasons
    const failureReasons = new Map<string, number>();
    failedAttempts.forEach(event => {
      if (event.errorCode) {
        failureReasons.set(event.errorCode, (failureReasons.get(event.errorCode) || 0) + 1);
      }
    });
    
    const topFailureReasons = Array.from(failureReasons.entries())
      .map(([reason, count]) => ({ reason, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
    
    // Hourly distribution
    const hourlyDistribution = Array.from({ length: 24 }, (_, hour) => {
      const count = recentEvents.filter(event => {
        const eventHour = event.timestamp.getHours();
        return eventHour === hour;
      }).length;
      return { hour, count };
    });
    
    return {
      totalEvents: recentEvents.length,
      securityEvents: securityEvents.length,
      failedAttempts: failedAttempts.length,
      blockedIPs,
      suspiciousActivities,
      topFailureReasons,
      hourlyDistribution,
    };
  }

  /**
   * Get events for specific user
   */
  getUserEvents(userId: string, limit: number = 50): AuditEvent[] {
    return this.auditEvents
      .filter(event => event.userId === userId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  /**
   * Get events from specific IP
   */
  getIPEvents(ipAddress: string, limit: number = 50): AuditEvent[] {
    return this.auditEvents
      .filter(event => event.clientInfo.ipAddress === ipAddress)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  /**
   * Cleanup old events to prevent memory issues
   */
  private cleanupOldEvents(): void {
    const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // 7 days
    const beforeCount = this.auditEvents.length;
    
    // Remove events older than cutoff
    for (let i = this.auditEvents.length - 1; i >= 0; i--) {
      if (this.auditEvents[i].timestamp < cutoff) {
        this.auditEvents.splice(i, 1);
      }
    }
    
    const afterCount = this.auditEvents.length;
    const cleaned = beforeCount - afterCount;
    
    if (cleaned > 0) {
      this.logger.debug(`Cleaned up ${cleaned} old audit events`);
    }
  }

  /**
   * Export events for analysis
   */
  exportEvents(
    startDate?: Date,
    endDate?: Date,
    eventTypes?: AuditEventType[]
  ): AuditEvent[] {
    let events = this.auditEvents;
    
    if (startDate) {
      events = events.filter(event => event.timestamp >= startDate);
    }
    
    if (endDate) {
      events = events.filter(event => event.timestamp <= endDate);
    }
    
    if (eventTypes && eventTypes.length > 0) {
      events = events.filter(event => eventTypes.includes(event.eventType));
    }
    
    return events.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }
}