import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * Audit Logger Service
 * 
 * Provides comprehensive audit logging for security events including:
 * - Authentication events (login, logout, token refresh)
 * - Authorization events (access granted/denied)
 * - Data access events (profile views, updates)
 * - Security events (rate limiting, suspicious activity)
 * - Administrative events (user management)
 */
@Injectable()
export class AuditLogger {
  private readonly logger = new Logger(AuditLogger.name);
  private readonly isAuditEnabled: boolean;
  private readonly auditLevel: string;

  constructor(private readonly configService: ConfigService) {
    this.isAuditEnabled = this.configService.get<boolean>('security.audit.enabled', true);
    this.auditLevel = this.configService.get<string>('security.audit.level', 'info');
  }

  /**
   * Log authentication events
   */
  logAuthEvent(event: AuthAuditEvent): void {
    if (!this.isAuditEnabled) return;

    const auditRecord: AuditRecord = {
      timestamp: new Date().toISOString(),
      category: 'authentication',
      action: event.action,
      result: event.result,
      userId: event.userId,
      sessionId: event.sessionId,
      clientInfo: {
        ip: event.clientIp,
        userAgent: event.userAgent,
        deviceId: event.deviceId,
      },
      details: event.details || {},
      correlationId: event.correlationId || this.generateCorrelationId(),
    };

    this.writeAuditLog(auditRecord);
  }

  /**
   * Log authorization events
   */
  logAuthorizationEvent(event: AuthorizationAuditEvent): void {
    if (!this.isAuditEnabled) return;

    const auditRecord: AuditRecord = {
      timestamp: new Date().toISOString(),
      category: 'authorization',
      action: event.action,
      result: event.result,
      userId: event.userId,
      sessionId: event.sessionId,
      resource: event.resource,
      permission: event.permission,
      clientInfo: {
        ip: event.clientIp,
        userAgent: event.userAgent,
        deviceId: event.deviceId,
      },
      details: event.details || {},
      correlationId: event.correlationId || this.generateCorrelationId(),
    };

    this.writeAuditLog(auditRecord);
  }

  /**
   * Log data access events
   */
  logDataAccessEvent(event: DataAccessAuditEvent): void {
    if (!this.isAuditEnabled) return;

    const auditRecord: AuditRecord = {
      timestamp: new Date().toISOString(),
      category: 'data_access',
      action: event.action,
      result: event.result,
      userId: event.userId,
      sessionId: event.sessionId,
      dataType: event.dataType,
      dataId: event.dataId,
      fieldAccessed: event.fieldAccessed,
      clientInfo: {
        ip: event.clientIp,
        userAgent: event.userAgent,
        deviceId: event.deviceId,
      },
      details: event.details || {},
      correlationId: event.correlationId || this.generateCorrelationId(),
    };

    this.writeAuditLog(auditRecord);
  }

  /**
   * Log security events
   */
  logSecurityEvent(event: SecurityAuditEvent): void {
    if (!this.isAuditEnabled) return;

    const auditRecord: AuditRecord = {
      timestamp: new Date().toISOString(),
      category: 'security',
      action: event.action,
      result: event.result,
      severity: event.severity,
      userId: event.userId,
      sessionId: event.sessionId,
      threatType: event.threatType,
      clientInfo: {
        ip: event.clientIp,
        userAgent: event.userAgent,
        deviceId: event.deviceId,
      },
      details: event.details || {},
      correlationId: event.correlationId || this.generateCorrelationId(),
    };

    this.writeAuditLog(auditRecord);
  }

  /**
   * Log administrative events
   */
  logAdminEvent(event: AdminAuditEvent): void {
    if (!this.isAuditEnabled) return;

    const auditRecord: AuditRecord = {
      timestamp: new Date().toISOString(),
      category: 'administration',
      action: event.action,
      result: event.result,
      userId: event.userId,
      sessionId: event.sessionId,
      targetUserId: event.targetUserId,
      adminAction: event.adminAction,
      clientInfo: {
        ip: event.clientIp,
        userAgent: event.userAgent,
        deviceId: event.deviceId,
      },
      details: event.details || {},
      correlationId: event.correlationId || this.generateCorrelationId(),
    };

    this.writeAuditLog(auditRecord);
  }

  /**
   * Write audit log with appropriate log level
   */
  private writeAuditLog(record: AuditRecord): void {
    const logMessage = this.formatAuditMessage(record);

    // Determine log level based on record content
    const logLevel = this.determineLogLevel(record);

    switch (logLevel) {
      case 'error':
        this.logger.error(logMessage);
        break;
      case 'warn':
        this.logger.warn(logMessage);
        break;
      case 'log':
        this.logger.log(logMessage);
        break;
      case 'debug':
        this.logger.debug(logMessage);
        break;
      default:
        this.logger.log(logMessage);
    }

    // Additional logging for high-severity events
    if (record.severity === 'critical' || record.severity === 'high') {
      this.logger.error(`HIGH SEVERITY AUDIT EVENT: ${JSON.stringify(record, null, 2)}`);
    }
  }

  /**
   * Format audit message for readability
   */
  private formatAuditMessage(record: AuditRecord): string {
    const parts = [
      `AUDIT [${record.category.toUpperCase()}]`,
      `Action: ${record.action}`,
      `Result: ${record.result}`,
    ];

    if (record.userId) {
      parts.push(`User: ${record.userId}`);
    }

    if (record.clientInfo?.ip) {
      parts.push(`IP: ${record.clientInfo.ip}`);
    }

    if (record.correlationId) {
      parts.push(`ID: ${record.correlationId}`);
    }

    return parts.join(' | ');
  }

  /**
   * Determine appropriate log level based on audit record
   */
  private determineLogLevel(record: AuditRecord): string {
    // High severity events should be errors
    if (record.severity === 'critical' || record.severity === 'high') {
      return 'error';
    }

    // Failed actions should be warnings
    if (record.result === 'failure' || record.result === 'denied') {
      return 'warn';
    }

    // Security events should be warnings
    if (record.category === 'security') {
      return 'warn';
    }

    // Data access might be debug level in production
    if (record.category === 'data_access' && this.auditLevel === 'minimal') {
      return 'debug';
    }

    return 'log';
  }

  /**
   * Generate correlation ID for tracking related events
   */
  private generateCorrelationId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get audit statistics for monitoring
   */
  getAuditStatistics(timeframe: number = 3600000): AuditStatistics {
    // This would typically query a persistent audit log store
    // For now, return basic statistics
    return {
      timeframe,
      totalEvents: 0,
      categories: {
        authentication: 0,
        authorization: 0,
        data_access: 0,
        security: 0,
        administration: 0,
      },
      results: {
        success: 0,
        failure: 0,
        denied: 0,
      },
      severities: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
    };
  }
}

/**
 * Base audit event interface
 */
interface BaseAuditEvent {
  action: string;
  result: 'success' | 'failure' | 'denied';
  userId?: string;
  sessionId?: string;
  clientIp: string;
  userAgent?: string;
  deviceId?: string;
  details?: Record<string, any>;
  correlationId?: string;
}

/**
 * Authentication audit event
 */
export interface AuthAuditEvent extends BaseAuditEvent {
  action: 'login' | 'logout' | 'register' | 'token_refresh' | 'password_change' | 'password_reset' | 'social_login';
}

/**
 * Authorization audit event
 */
export interface AuthorizationAuditEvent extends BaseAuditEvent {
  action: 'access_check' | 'permission_grant' | 'permission_deny' | 'role_change';
  resource: string;
  permission: string;
}

/**
 * Data access audit event
 */
export interface DataAccessAuditEvent extends BaseAuditEvent {
  action: 'read' | 'create' | 'update' | 'delete' | 'export' | 'import';
  dataType: string;
  dataId: string;
  fieldAccessed?: string[];
}

/**
 * Security audit event
 */
export interface SecurityAuditEvent extends BaseAuditEvent {
  action: 'rate_limit' | 'suspicious_activity' | 'brute_force' | 'cors_violation' | 'xss_attempt' | 'sql_injection';
  severity: 'critical' | 'high' | 'medium' | 'low';
  threatType: string;
}

/**
 * Administrative audit event
 */
export interface AdminAuditEvent extends BaseAuditEvent {
  action: 'user_create' | 'user_update' | 'user_delete' | 'user_activate' | 'user_deactivate' | 'role_assign';
  targetUserId: string;
  adminAction: string;
}

/**
 * Complete audit record
 */
interface AuditRecord {
  timestamp: string;
  category: 'authentication' | 'authorization' | 'data_access' | 'security' | 'administration';
  action: string;
  result: 'success' | 'failure' | 'denied';
  severity?: 'critical' | 'high' | 'medium' | 'low';
  userId?: string;
  sessionId?: string;
  resource?: string;
  permission?: string;
  dataType?: string;
  dataId?: string;
  fieldAccessed?: string[];
  threatType?: string;
  targetUserId?: string;
  adminAction?: string;
  clientInfo: {
    ip: string;
    userAgent?: string;
    deviceId?: string;
  };
  details: Record<string, any>;
  correlationId: string;
}

/**
 * Audit statistics interface
 */
interface AuditStatistics {
  timeframe: number;
  totalEvents: number;
  categories: {
    authentication: number;
    authorization: number;
    data_access: number;
    security: number;
    administration: number;
  };
  results: {
    success: number;
    failure: number;
    denied: number;
  };
  severities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}