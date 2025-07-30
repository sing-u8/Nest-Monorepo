import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { LoggingService, SecurityEventType } from './logging.service';
import { MetricsService } from './metrics.service';

/**
 * Alert severity levels
 */
export enum AlertSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

/**
 * Alert interface
 */
interface Alert {
  id: string;
  timestamp: Date;
  severity: AlertSeverity;
  title: string;
  description: string;
  category: 'security' | 'performance' | 'availability' | 'capacity';
  source: string;
  metadata?: Record<string, any>;
  acknowledged?: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  resolved?: boolean;
  resolvedBy?: string;
  resolvedAt?: Date;
}

/**
 * Alert rule interface
 */
interface AlertRule {
  id: string;
  name: string;
  description: string;
  category: 'security' | 'performance' | 'availability' | 'capacity';
  condition: (data: any) => boolean;
  severity: AlertSeverity;
  enabled: boolean;
  cooldownMinutes: number;
  lastTriggered?: Date;
}

/**
 * Alerting Service
 * 
 * Monitors system events and metrics to generate alerts
 * for security incidents, performance issues, and system problems.
 */
@Injectable()
export class AlertingService implements OnModuleDestroy {
  private alerts: Map<string, Alert> = new Map();
  private alertRules: Map<string, AlertRule> = new Map();
  private alertHistory: Alert[] = [];
  private monitoringInterval: NodeJS.Timeout | null = null;

  constructor(
    private readonly configService: ConfigService,
    private readonly loggingService: LoggingService,
    private readonly metricsService: MetricsService,
  ) {
    this.initializeAlertRules();
    this.startAlertMonitoring();
  }

  onModuleDestroy() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }
  }

  /**
   * Initialize default alert rules
   */
  private initializeAlertRules(): void {
    // Security alert rules
    this.addAlertRule({
      id: 'multiple_auth_failures',
      name: 'Multiple Authentication Failures',
      description: 'Detects multiple authentication failures from the same IP or user',
      category: 'security',
      condition: (data) => data.authFailures >= 5,
      severity: AlertSeverity.HIGH,
      enabled: true,
      cooldownMinutes: 10,
    });

    this.addAlertRule({
      id: 'rate_limit_violations',
      name: 'Rate Limit Violations',
      description: 'Detects excessive rate limit violations',
      category: 'security',
      condition: (data) => data.rateLimitViolations >= 10,
      severity: AlertSeverity.MEDIUM,
      enabled: true,
      cooldownMinutes: 5,
    });

    this.addAlertRule({
      id: 'suspicious_oauth_activity',
      name: 'Suspicious OAuth Activity',
      description: 'Detects suspicious OAuth authentication patterns',
      category: 'security',
      condition: (data) => data.oauthFailures >= 3 && data.oauthSuccessRate < 50,
      severity: AlertSeverity.HIGH,
      enabled: true,
      cooldownMinutes: 15,
    });

    this.addAlertRule({
      id: 'mtls_validation_failures',
      name: 'mTLS Validation Failures',
      description: 'Detects multiple mTLS certificate validation failures',
      category: 'security',
      condition: (data) => data.mtlsFailures >= 5,
      severity: AlertSeverity.HIGH,
      enabled: true,
      cooldownMinutes: 10,
    });

    // Performance alert rules
    this.addAlertRule({
      id: 'high_response_time',
      name: 'High Response Time',
      description: 'Detects high average response times',
      category: 'performance',
      condition: (data) => data.avgResponseTime >= 2000, // 2 seconds
      severity: AlertSeverity.MEDIUM,
      enabled: true,
      cooldownMinutes: 5,
    });

    this.addAlertRule({
      id: 'database_slow_queries',
      name: 'Database Slow Queries',
      description: 'Detects slow database queries',
      category: 'performance',
      condition: (data) => data.avgDatabaseQueryTime >= 500, // 500ms
      severity: AlertSeverity.MEDIUM,
      enabled: true,
      cooldownMinutes: 5,
    });

    this.addAlertRule({
      id: 'high_error_rate',
      name: 'High Error Rate',
      description: 'Detects high error rates in authentication operations',
      category: 'availability',
      condition: (data) => data.errorRate >= 10, // 10% error rate
      severity: AlertSeverity.HIGH,
      enabled: true,
      cooldownMinutes: 5,
    });

    // Capacity alert rules
    this.addAlertRule({
      id: 'high_memory_usage',
      name: 'High Memory Usage',
      description: 'Detects high memory usage',
      category: 'capacity',
      condition: (data) => data.memoryUsageMb >= 500, // 500MB
      severity: AlertSeverity.MEDIUM,
      enabled: true,
      cooldownMinutes: 10,
    });

    this.addAlertRule({
      id: 'database_connection_pool_exhaustion',
      name: 'Database Connection Pool Exhaustion',
      description: 'Detects database connection pool near exhaustion',
      category: 'capacity',
      condition: (data) => data.dbConnectionsActive >= 20, // Adjust based on pool size
      severity: AlertSeverity.HIGH,
      enabled: true,
      cooldownMinutes: 5,
    });

    // Availability alert rules
    this.addAlertRule({
      id: 'external_service_down',
      name: 'External Service Down',
      description: 'Detects when external services are unreachable',
      category: 'availability',
      condition: (data) => data.externalServiceFailures >= 3,
      severity: AlertSeverity.HIGH,
      enabled: true,
      cooldownMinutes: 15,
    });
  }

  /**
   * Add or update an alert rule
   */
  addAlertRule(rule: Omit<AlertRule, 'lastTriggered'>): void {
    this.alertRules.set(rule.id, { ...rule, lastTriggered: undefined });
  }

  /**
   * Remove an alert rule
   */
  removeAlertRule(ruleId: string): boolean {
    return this.alertRules.delete(ruleId);
  }

  /**
   * Enable or disable an alert rule
   */
  toggleAlertRule(ruleId: string, enabled: boolean): boolean {
    const rule = this.alertRules.get(ruleId);
    if (rule) {
      rule.enabled = enabled;
      return true;
    }
    return false;
  }

  /**
   * Create an alert
   */
  createAlert(
    title: string,
    description: string,
    severity: AlertSeverity,
    category: 'security' | 'performance' | 'availability' | 'capacity',
    source: string,
    metadata?: Record<string, any>
  ): Alert {
    const alert: Alert = {
      id: this.generateAlertId(),
      timestamp: new Date(),
      severity,
      title,
      description,
      category,
      source,
      metadata,
    };

    this.alerts.set(alert.id, alert);
    this.alertHistory.push(alert);

    // Keep only last 1000 alerts in history
    if (this.alertHistory.length > 1000) {
      this.alertHistory.shift();
    }

    // Log the alert
    this.loggingService.warn(
      `ALERT [${severity.toUpperCase()}]: ${title}`,
      'AlertingService',
      {
        alertId: alert.id,
        category,
        source,
        description,
        metadata,
      }
    );

    // Send alert notifications (in production, this would integrate with external systems)
    this.sendAlertNotification(alert);

    return alert;
  }

  /**
   * Acknowledge an alert
   */
  acknowledgeAlert(alertId: string, acknowledgedBy: string): boolean {
    const alert = this.alerts.get(alertId);
    if (alert && !alert.acknowledged) {
      alert.acknowledged = true;
      alert.acknowledgedBy = acknowledgedBy;
      alert.acknowledgedAt = new Date();

      this.loggingService.log(
        `Alert acknowledged: ${alert.title}`,
        'AlertingService',
        {
          alertId,
          acknowledgedBy,
          severity: alert.severity,
        }
      );

      return true;
    }
    return false;
  }

  /**
   * Resolve an alert
   */
  resolveAlert(alertId: string, resolvedBy: string): boolean {
    const alert = this.alerts.get(alertId);
    if (alert && !alert.resolved) {
      alert.resolved = true;
      alert.resolvedBy = resolvedBy;
      alert.resolvedAt = new Date();

      this.loggingService.log(
        `Alert resolved: ${alert.title}`,
        'AlertingService',
        {
          alertId,
          resolvedBy,
          severity: alert.severity,
        }
      );

      // Remove from active alerts
      this.alerts.delete(alertId);
      return true;
    }
    return false;
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): Alert[] {
    return Array.from(this.alerts.values()).sort(
      (a, b) => b.timestamp.getTime() - a.timestamp.getTime()
    );
  }

  /**
   * Get alerts by severity
   */
  getAlertsBySeverity(severity: AlertSeverity): Alert[] {
    return this.getActiveAlerts().filter(alert => alert.severity === severity);
  }

  /**
   * Get alerts by category
   */
  getAlertsByCategory(category: string): Alert[] {
    return this.getActiveAlerts().filter(alert => alert.category === category);
  }

  /**
   * Get alert statistics
   */
  getAlertStatistics(): any {
    const activeAlerts = this.getActiveAlerts();
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentAlerts = this.alertHistory.filter(alert => alert.timestamp > last24h);

    return {
      timestamp: new Date().toISOString(),
      active: {
        total: activeAlerts.length,
        critical: activeAlerts.filter(a => a.severity === AlertSeverity.CRITICAL).length,
        high: activeAlerts.filter(a => a.severity === AlertSeverity.HIGH).length,
        medium: activeAlerts.filter(a => a.severity === AlertSeverity.MEDIUM).length,
        low: activeAlerts.filter(a => a.severity === AlertSeverity.LOW).length,
      },
      last24Hours: {
        total: recentAlerts.length,
        security: recentAlerts.filter(a => a.category === 'security').length,
        performance: recentAlerts.filter(a => a.category === 'performance').length,
        availability: recentAlerts.filter(a => a.category === 'availability').length,
        capacity: recentAlerts.filter(a => a.category === 'capacity').length,
      },
      trends: {
        alertsPerHour: this.calculateAlertsPerHour(),
        topAlertSources: this.getTopAlertSources(),
        resolutionRate: this.calculateResolutionRate(),
      },
    };
  }

  /**
   * Check security events for alerts
   */
  checkSecurityEvents(): void {
    const metrics = this.metricsService.getMetricsSummary();
    
    // Create data object for rule evaluation
    const securityData = {
      authFailures: metrics.authentication?.failedRequests || 0,
      rateLimitViolations: metrics.security?.rateLimitViolations || 0,
      oauthFailures: metrics.oauth?.failedRequests || 0,
      oauthSuccessRate: metrics.oauth?.successRate || 100,
      mtlsFailures: metrics.security?.mtlsFailures || 0,
    };

    // Evaluate security alert rules
    for (const [ruleId, rule] of this.alertRules) {
      if (!rule.enabled || rule.category !== 'security') continue;
      
      if (this.shouldSkipRule(rule)) continue;
      
      if (rule.condition(securityData)) {
        this.createAlert(
          rule.name,
          rule.description,
          rule.severity,
          rule.category,
          'SecurityMonitor',
          { ruleId, data: securityData }
        );
        
        rule.lastTriggered = new Date();
      }
    }
  }

  /**
   * Check performance metrics for alerts
   */
  checkPerformanceMetrics(): void {
    const metrics = this.metricsService.getMetricsSummary();
    
    const performanceData = {
      avgResponseTime: metrics.performance?.avgAuthDuration || 0,
      avgDatabaseQueryTime: metrics.performance?.avgDatabaseQuery || 0,
      errorRate: this.calculateErrorRate(metrics),
      memoryUsageMb: metrics.system?.memoryUsageMB || 0,
      dbConnectionsActive: metrics.system?.databaseConnections || 0,
    };

    // Evaluate performance alert rules
    for (const [ruleId, rule] of this.alertRules) {
      if (!rule.enabled || (rule.category !== 'performance' && rule.category !== 'capacity')) continue;
      
      if (this.shouldSkipRule(rule)) continue;
      
      if (rule.condition(performanceData)) {
        this.createAlert(
          rule.name,
          rule.description,
          rule.severity,
          rule.category,
          'PerformanceMonitor',
          { ruleId, data: performanceData }
        );
        
        rule.lastTriggered = new Date();
      }
    }
  }

  /**
   * Calculate error rate from metrics
   */
  private calculateErrorRate(metrics: any): number {
    const total = metrics.authentication?.totalRequests || 0;
    const failed = metrics.authentication?.failedRequests || 0;
    
    if (total === 0) return 0;
    return (failed / total) * 100;
  }

  /**
   * Check if rule should be skipped due to cooldown
   */
  private shouldSkipRule(rule: AlertRule): boolean {
    if (!rule.lastTriggered) return false;
    
    const cooldownMs = rule.cooldownMinutes * 60 * 1000;
    const timeSinceLastTriggered = Date.now() - rule.lastTriggered.getTime();
    
    return timeSinceLastTriggered < cooldownMs;
  }

  /**
   * Send alert notification (placeholder for external integrations)
   */
  private sendAlertNotification(alert: Alert): void {
    // In production, this would integrate with:
    // - Email notifications
    // - Slack/Teams webhooks
    // - PagerDuty/Opsgenie
    // - SMS notifications
    // - Push notifications

    console.warn(`🚨 ALERT [${alert.severity.toUpperCase()}]: ${alert.title}`, {
      description: alert.description,
      category: alert.category,
      source: alert.source,
      timestamp: alert.timestamp,
      metadata: alert.metadata,
    });

    // Log security alerts with enhanced visibility
    if (alert.category === 'security') {
      this.loggingService.logSecurityEvent(
        SecurityEventType.SUSPICIOUS_ACTIVITY,
        `Security alert triggered: ${alert.title}`,
        {
          correlationId: alert.id,
          additional: alert.metadata,
        }
      );
    }
  }

  /**
   * Generate unique alert ID
   */
  private generateAlertId(): string {
    return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Calculate alerts per hour trend
   */
  private calculateAlertsPerHour(): number {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const recentAlerts = this.alertHistory.filter(alert => alert.timestamp > oneHourAgo);
    return recentAlerts.length;
  }

  /**
   * Get top alert sources
   */
  private getTopAlertSources(): Array<{ source: string; count: number }> {
    const sourceCounts = new Map<string, number>();
    
    for (const alert of this.alertHistory.slice(-100)) { // Last 100 alerts
      const count = sourceCounts.get(alert.source) || 0;
      sourceCounts.set(alert.source, count + 1);
    }
    
    return Array.from(sourceCounts.entries())
      .map(([source, count]) => ({ source, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }

  /**
   * Calculate alert resolution rate
   */
  private calculateResolutionRate(): number {
    const resolvedAlerts = this.alertHistory.filter(alert => alert.resolved);
    if (this.alertHistory.length === 0) return 100;
    
    return Math.round((resolvedAlerts.length / this.alertHistory.length) * 100);
  }

  /**
   * Start periodic alert monitoring
   */
  private startAlertMonitoring(): void {
    const monitoringInterval = this.configService.get<number>('monitoring.alertingInterval', 60000); // Default 1 minute
    
    this.monitoringInterval = setInterval(() => {
      this.checkSecurityEvents();
      this.checkPerformanceMetrics();
    }, monitoringInterval);
  }

  /**
   * Get all alert rules
   */
  getAllAlertRules(): AlertRule[] {
    return Array.from(this.alertRules.values());
  }

  /**
   * Clear alert history (useful for testing)
   */
  clearAlertHistory(): void {
    this.alerts.clear();
    this.alertHistory.length = 0;
  }
}