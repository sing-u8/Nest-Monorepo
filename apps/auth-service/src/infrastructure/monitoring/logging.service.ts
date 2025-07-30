import { Injectable, LoggerService, ConsoleLogger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * Log level enumeration
 */
export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  LOG = 2,
  DEBUG = 3,
  VERBOSE = 4,
}

/**
 * Structured log entry interface
 */
interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  context?: string;
  correlationId?: string;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  operation?: string;
  duration?: number;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
  metadata?: Record<string, any>;
}

/**
 * Security log event types
 */
export enum SecurityEventType {
  AUTH_SUCCESS = 'auth_success',
  AUTH_FAILURE = 'auth_failure',
  TOKEN_GENERATION = 'token_generation',
  TOKEN_VALIDATION = 'token_validation',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  ACCESS_DENIED = 'access_denied',
  MTLS_VALIDATION = 'mtls_validation',
  OAUTH_CALLBACK = 'oauth_callback',
  SESSION_CREATED = 'session_created',
  SESSION_EXPIRED = 'session_expired',
  PASSWORD_CHANGE = 'password_change',
  PROFILE_UPDATE = 'profile_update',
}

/**
 * Enhanced Logging Service
 * 
 * Provides structured logging with security event tracking,
 * correlation IDs, and configurable output formats.
 */
@Injectable()
export class LoggingService extends ConsoleLogger implements LoggerService {
  private readonly logLevel: LogLevel;
  private readonly enableStructuredLogging: boolean;
  private readonly enableSecurityLogging: boolean;
  private readonly logBuffer: LogEntry[] = [];
  private readonly bufferSize: number;
  private flushInterval: NodeJS.Timeout | null = null;

  constructor(private readonly configService: ConfigService) {
    super('AuthService');
    
    this.logLevel = this.parseLogLevel(configService.get('LOG_LEVEL', 'LOG'));
    this.enableStructuredLogging = configService.get('ENABLE_STRUCTURED_LOGGING', 'true') === 'true';
    this.enableSecurityLogging = configService.get('ENABLE_SECURITY_LOGGING', 'true') === 'true';
    this.bufferSize = configService.get('LOG_BUFFER_SIZE', 100);
    
    this.initializeLogging();
  }

  /**
   * Initialize logging configuration
   */
  private initializeLogging(): void {
    // Start log buffer flushing if needed
    const flushInterval = this.configService.get('LOG_FLUSH_INTERVAL', 5000);
    if (flushInterval > 0) {
      this.flushInterval = setInterval(() => {
        this.flushLogs();
      }, flushInterval);
    }
  }

  /**
   * Parse log level from string
   */
  private parseLogLevel(level: string): LogLevel {
    switch (level.toUpperCase()) {
      case 'ERROR': return LogLevel.ERROR;
      case 'WARN': return LogLevel.WARN;
      case 'LOG': return LogLevel.LOG;
      case 'DEBUG': return LogLevel.DEBUG;
      case 'VERBOSE': return LogLevel.VERBOSE;
      default: return LogLevel.LOG;
    }
  }

  /**
   * Create structured log entry
   */
  private createLogEntry(
    level: string,
    message: string,
    context?: string,
    metadata?: Record<string, any>
  ): LogEntry {
    return {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
      context,
      correlationId: metadata?.correlationId,
      userId: metadata?.userId,
      sessionId: metadata?.sessionId,
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
      operation: metadata?.operation,
      duration: metadata?.duration,
      error: metadata?.error,
      metadata: metadata?.metadata,
    };
  }

  /**
   * Enhanced error logging with stack traces and context
   */
  error(message: any, stack?: string, context?: string, metadata?: Record<string, any>): void {
    if (this.logLevel < LogLevel.ERROR) return;

    const logEntry = this.createLogEntry('ERROR', message, context, {
      ...metadata,
      error: stack ? { name: 'Error', message, stack } : undefined,
    });

    this.outputLog(logEntry);
    this.bufferLog(logEntry);
  }

  /**
   * Enhanced warning logging
   */
  warn(message: any, context?: string, metadata?: Record<string, any>): void {
    if (this.logLevel < LogLevel.WARN) return;

    const logEntry = this.createLogEntry('WARN', message, context, metadata);
    this.outputLog(logEntry);
    this.bufferLog(logEntry);
  }

  /**
   * Enhanced info/log logging
   */
  log(message: any, context?: string, metadata?: Record<string, any>): void {
    if (this.logLevel < LogLevel.LOG) return;

    const logEntry = this.createLogEntry('LOG', message, context, metadata);
    this.outputLog(logEntry);
    this.bufferLog(logEntry);
  }

  /**
   * Enhanced debug logging
   */
  debug(message: any, context?: string, metadata?: Record<string, any>): void {
    if (this.logLevel < LogLevel.DEBUG) return;

    const logEntry = this.createLogEntry('DEBUG', message, context, metadata);
    this.outputLog(logEntry);
    this.bufferLog(logEntry);
  }

  /**
   * Enhanced verbose logging
   */
  verbose(message: any, context?: string, metadata?: Record<string, any>): void {
    if (this.logLevel < LogLevel.VERBOSE) return;

    const logEntry = this.createLogEntry('VERBOSE', message, context, metadata);
    this.outputLog(logEntry);
    this.bufferLog(logEntry);
  }

  /**
   * Log security events with enhanced metadata
   */
  logSecurityEvent(
    eventType: SecurityEventType,
    message: string,
    metadata?: {
      userId?: string;
      sessionId?: string;
      ipAddress?: string;
      userAgent?: string;
      success?: boolean;
      reason?: string;
      provider?: string;
      correlationId?: string;
      additional?: Record<string, any>;
    }
  ): void {
    if (!this.enableSecurityLogging) return;

    const securityMetadata = {
      ...metadata,
      eventType,
      security: true,
      timestamp: new Date().toISOString(),
    };

    const logEntry = this.createLogEntry('SECURITY', message, 'SecurityAudit', securityMetadata);
    
    this.outputLog(logEntry);
    this.bufferLog(logEntry);

    // Also log to console for immediate visibility
    if (eventType === SecurityEventType.AUTH_FAILURE || 
        eventType === SecurityEventType.RATE_LIMIT_EXCEEDED ||
        eventType === SecurityEventType.SUSPICIOUS_ACTIVITY) {
      console.warn('🔒 SECURITY EVENT:', {
        type: eventType,
        message,
        metadata: securityMetadata,
      });
    }
  }

  /**
   * Log authentication events
   */
  logAuthEvent(
    event: 'login' | 'logout' | 'register' | 'token_refresh' | 'password_change',
    userId: string,
    metadata?: {
      sessionId?: string;
      ipAddress?: string;
      userAgent?: string;
      provider?: string;
      success?: boolean;
      duration?: number;
      correlationId?: string;
    }
  ): void {
    const eventTypeMap = {
      login: SecurityEventType.AUTH_SUCCESS,
      logout: SecurityEventType.SESSION_EXPIRED,
      register: SecurityEventType.AUTH_SUCCESS,
      token_refresh: SecurityEventType.TOKEN_VALIDATION,
      password_change: SecurityEventType.PASSWORD_CHANGE,
    };

    this.logSecurityEvent(
      eventTypeMap[event],
      `User ${event} ${metadata?.success !== false ? 'successful' : 'failed'}`,
      { userId, ...metadata }
    );
  }

  /**
   * Log OAuth events
   */
  logOAuthEvent(
    provider: string,
    event: 'initiate' | 'callback' | 'success' | 'failure',
    metadata?: {
      userId?: string;
      sessionId?: string;
      ipAddress?: string;
      userAgent?: string;
      error?: string;
      duration?: number;
      correlationId?: string;
    }
  ): void {
    this.logSecurityEvent(
      SecurityEventType.OAUTH_CALLBACK,
      `OAuth ${provider} ${event}`,
      { provider, ...metadata }
    );
  }

  /**
   * Log performance events
   */
  logPerformanceEvent(
    operation: string,
    duration: number,
    metadata?: {
      success?: boolean;
      error?: string;
      userId?: string;
      correlationId?: string;
      threshold?: number;
    }
  ): void {
    const level = metadata?.threshold && duration > metadata.threshold ? 'WARN' : 'LOG';
    
    this.log(
      `Performance: ${operation} completed in ${duration}ms`,
      'Performance',
      {
        operation,
        duration,
        performance: true,
        ...metadata,
      }
    );
  }

  /**
   * Log database events
   */
  logDatabaseEvent(
    operation: string,
    duration: number,
    metadata?: {
      query?: string;
      table?: string;
      success?: boolean;
      error?: string;
      rowsAffected?: number;
      correlationId?: string;
    }
  ): void {
    this.debug(
      `Database: ${operation} completed in ${duration}ms`,
      'Database',
      {
        operation,
        duration,
        database: true,
        ...metadata,
      }
    );
  }

  /**
   * Log rate limiting events
   */
  logRateLimitEvent(
    identifier: string,
    limit: number,
    current: number,
    metadata?: {
      endpoint?: string;
      ipAddress?: string;
      userId?: string;
      blocked?: boolean;
      correlationId?: string;
    }
  ): void {
    this.logSecurityEvent(
      SecurityEventType.RATE_LIMIT_EXCEEDED,
      `Rate limit ${metadata?.blocked ? 'exceeded' : 'warning'} for ${identifier}: ${current}/${limit}`,
      metadata
    );
  }

  /**
   * Log suspicious activity
   */
  logSuspiciousActivity(
    activity: string,
    severity: 'low' | 'medium' | 'high',
    metadata?: {
      userId?: string;
      ipAddress?: string;
      userAgent?: string;
      details?: Record<string, any>;
      correlationId?: string;
    }
  ): void {
    this.logSecurityEvent(
      SecurityEventType.SUSPICIOUS_ACTIVITY,
      `Suspicious activity detected: ${activity}`,
      { severity, ...metadata }
    );
  }

  /**
   * Output log entry to console or external system
   */
  private outputLog(logEntry: LogEntry): void {
    if (this.enableStructuredLogging) {
      // Output as JSON for log aggregation systems
      console.log(JSON.stringify(logEntry));
    } else {
      // Output as formatted text for development
      const timestamp = logEntry.timestamp;
      const level = logEntry.level.padEnd(7);
      const context = logEntry.context ? `[${logEntry.context}]` : '';
      const correlationId = logEntry.correlationId ? `[${logEntry.correlationId}]` : '';
      
      let output = `${timestamp} ${level} ${context}${correlationId} ${logEntry.message}`;
      
      if (logEntry.duration) {
        output += ` (${logEntry.duration}ms)`;
      }
      
      if (logEntry.error) {
        output += `\n${logEntry.error.stack || logEntry.error.message}`;
      }
      
      if (logEntry.metadata && Object.keys(logEntry.metadata).length > 0) {
        output += `\nMetadata: ${JSON.stringify(logEntry.metadata, null, 2)}`;
      }
      
      console.log(output);
    }
  }

  /**
   * Buffer log entry for batch processing
   */
  private bufferLog(logEntry: LogEntry): void {
    this.logBuffer.push(logEntry);
    
    if (this.logBuffer.length >= this.bufferSize) {
      this.flushLogs();
    }
  }

  /**
   * Flush buffered logs to external systems
   */
  private flushLogs(): void {
    if (this.logBuffer.length === 0) return;

    // In production, this would send logs to:
    // - Elasticsearch/ELK Stack
    // - AWS CloudWatch
    // - Datadog
    // - Splunk
    // - Other log aggregation services

    const logsToFlush = [...this.logBuffer];
    this.logBuffer.length = 0;

    // For now, just debug log the flush operation
    if (this.logLevel >= LogLevel.DEBUG) {
      console.debug(`Flushed ${logsToFlush.length} log entries to external systems`);
    }

    // Example: Send to external log aggregation service
    // await this.sendToExternalLoggingService(logsToFlush);
  }

  /**
   * Generate correlation ID for request tracking
   */
  generateCorrelationId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get recent logs (for debugging and monitoring)
   */
  getRecentLogs(count = 50): LogEntry[] {
    return this.logBuffer.slice(-count);
  }

  /**
   * Get logs by level
   */
  getLogsByLevel(level: string, count = 50): LogEntry[] {
    return this.logBuffer
      .filter(entry => entry.level === level.toUpperCase())
      .slice(-count);
  }

  /**
   * Get security logs
   */
  getSecurityLogs(count = 50): LogEntry[] {
    return this.logBuffer
      .filter(entry => entry.level === 'SECURITY')
      .slice(-count);
  }

  /**
   * Get logs by user
   */
  getLogsByUser(userId: string, count = 50): LogEntry[] {
    return this.logBuffer
      .filter(entry => entry.userId === userId)
      .slice(-count);
  }

  /**
   * Get logs by correlation ID
   */
  getLogsByCorrelationId(correlationId: string): LogEntry[] {
    return this.logBuffer.filter(entry => entry.correlationId === correlationId);
  }

  /**
   * Clear log buffer (useful for testing)
   */
  clearBuffer(): void {
    this.logBuffer.length = 0;
  }

  /**
   * Cleanup on module destroy
   */
  onModuleDestroy(): void {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
    }
    this.flushLogs();
  }
}