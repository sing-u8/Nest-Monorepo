import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/app.config';
import { MetricsService, MetricsSummary } from './metrics.service';

export interface AlertRule {
  id: string;
  name: string;
  metric: string;
  condition: 'greater_than' | 'less_than' | 'equals';
  threshold: number;
  windowMinutes: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  tags?: Record<string, string>;
}

export interface Alert {
  id: string;
  ruleId: string;
  ruleName: string;
  metric: string;
  value: number;
  threshold: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  timestamp: Date;
  resolved: boolean;
  resolvedAt?: Date;
  metadata?: Record<string, any>;
}

export interface AlertChannel {
  type: 'webhook' | 'email' | 'slack' | 'console';
  config: Record<string, any>;
  enabled: boolean;
}

/**
 * Alerting Service
 * 
 * Monitors metrics and triggers alerts based on configured rules.
 * Supports multiple notification channels and alert severity levels.
 */
@Injectable()
export class AlertingService {
  private readonly logger = new Logger(AlertingService.name);
  private readonly isEnabled: boolean;
  private readonly alertRules: Map<string, AlertRule> = new Map();
  private readonly activeAlerts: Map<string, Alert> = new Map();
  private readonly alertChannels: AlertChannel[] = [];
  private checkInterval: NodeJS.Timeout | null = null;
  
  constructor(
    private configService: ConfigService,
    private metricsService: MetricsService,
  ) {
    const config = this.configService.get<AppConfig>('app');
    this.isEnabled = config?.MONITORING_ENABLE_ALERTING || false;
    
    if (this.isEnabled) {
      this.logger.log('Alerting service enabled');
      this.initializeDefaultRules();
      this.initializeChannels();
      this.startAlertChecking();
    } else {
      this.logger.log('Alerting service disabled');
    }
  }
  
  /**
   * Add or update an alert rule
   */
  addRule(rule: AlertRule): void {
    this.alertRules.set(rule.id, rule);
    this.logger.log(`Alert rule added: ${rule.name} (${rule.id})`);
  }
  
  /**
   * Remove an alert rule
   */
  removeRule(ruleId: string): void {
    this.alertRules.delete(ruleId);
    this.logger.log(`Alert rule removed: ${ruleId}`);
  }
  
  /**
   * Get all alert rules
   */
  getRules(): AlertRule[] {
    return Array.from(this.alertRules.values());
  }
  
  /**
   * Get active alerts
   */
  getActiveAlerts(): Alert[] {
    return Array.from(this.activeAlerts.values()).filter(alert => !alert.resolved);
  }
  
  /**
   * Get all alerts (including resolved)
   */
  getAllAlerts(): Alert[] {
    return Array.from(this.activeAlerts.values());
  }
  
  /**
   * Resolve an alert
   */
  resolveAlert(alertId: string): void {
    const alert = this.activeAlerts.get(alertId);
    if (alert && !alert.resolved) {
      alert.resolved = true;
      alert.resolvedAt = new Date();
      this.logger.log(`Alert resolved: ${alert.ruleName} (${alertId})`);
    }
  }
  
  /**
   * Manually trigger an alert
   */
  async triggerAlert(
    ruleName: string,
    message: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    metadata?: Record<string, any>,
  ): Promise<void> {
    const alert: Alert = {
      id: this.generateAlertId(),
      ruleId: 'manual',
      ruleName,
      metric: 'manual',
      value: 0,
      threshold: 0,
      severity,
      message,
      timestamp: new Date(),
      resolved: false,
      metadata,
    };
    
    this.activeAlerts.set(alert.id, alert);
    await this.sendAlert(alert);
  }
  
  /**
   * Add alert channel
   */
  addChannel(channel: AlertChannel): void {
    this.alertChannels.push(channel);
    this.logger.log(`Alert channel added: ${channel.type}`);
  }
  
  /**
   * Check all rules and trigger alerts if needed
   */
  async checkRules(): Promise<void> {
    if (!this.isEnabled) return;
    
    for (const rule of this.alertRules.values()) {
      if (!rule.enabled) continue;
      
      try {
        await this.checkRule(rule);
      } catch (error) {
        this.logger.error(`Error checking rule ${rule.name}:`, error);
      }
    }
  }
  
  /**
   * Get alerting service health status
   */
  getHealthStatus(): Record<string, any> {
    return {
      enabled: this.isEnabled,
      rulesCount: this.alertRules.size,
      activeAlertsCount: this.getActiveAlerts().length,
      totalAlertsCount: this.activeAlerts.size,
      channelsCount: this.alertChannels.length,
      enabledChannels: this.alertChannels.filter(c => c.enabled).length,
    };
  }
  
  private async checkRule(rule: AlertRule): Promise<void> {
    const summary = this.metricsService.getMetricsSummary(rule.metric, rule.tags);
    
    if (!summary) {
      return; // Metric not found
    }
    
    const value = this.getValueForCondition(summary, rule);
    const shouldAlert = this.evaluateCondition(value, rule.condition, rule.threshold);
    
    const existingAlert = this.findExistingAlert(rule.id);
    
    if (shouldAlert && !existingAlert) {
      // Trigger new alert
      const alert: Alert = {
        id: this.generateAlertId(),
        ruleId: rule.id,
        ruleName: rule.name,
        metric: rule.metric,
        value,
        threshold: rule.threshold,
        severity: rule.severity,
        message: this.generateAlertMessage(rule, value),
        timestamp: new Date(),
        resolved: false,
        metadata: { summary, rule },
      };
      
      this.activeAlerts.set(alert.id, alert);
      await this.sendAlert(alert);
      
    } else if (!shouldAlert && existingAlert && !existingAlert.resolved) {
      // Auto-resolve alert
      this.resolveAlert(existingAlert.id);
    }
  }
  
  private getValueForCondition(summary: MetricsSummary, rule: AlertRule): number {
    // Use average for rate-based metrics, count for counter metrics
    if (rule.metric.includes('rate') || rule.metric.includes('duration')) {
      return summary.average;
    }
    return summary.count;
  }
  
  private evaluateCondition(
    value: number,
    condition: 'greater_than' | 'less_than' | 'equals',
    threshold: number,
  ): boolean {
    switch (condition) {
      case 'greater_than':
        return value > threshold;
      case 'less_than':
        return value < threshold;
      case 'equals':
        return value === threshold;
      default:
        return false;
    }
  }
  
  private findExistingAlert(ruleId: string): Alert | undefined {
    return Array.from(this.activeAlerts.values()).find(
      alert => alert.ruleId === ruleId && !alert.resolved
    );
  }
  
  private generateAlertMessage(rule: AlertRule, value: number): string {
    const condition = rule.condition.replace('_', ' ');
    return `${rule.name}: ${rule.metric} is ${value} (${condition} ${rule.threshold})`;
  }
  
  private generateAlertId(): string {
    return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  private async sendAlert(alert: Alert): Promise<void> {
    this.logger.warn(`ALERT [${alert.severity.toUpperCase()}]: ${alert.message}`, {
      alertId: alert.id,
      metric: alert.metric,
      value: alert.value,
      threshold: alert.threshold,
      metadata: alert.metadata,
    });
    
    // Send to all enabled channels
    const promises = this.alertChannels
      .filter(channel => channel.enabled)
      .map(channel => this.sendToChannel(channel, alert));
    
    await Promise.allSettled(promises);
  }
  
  private async sendToChannel(channel: AlertChannel, alert: Alert): Promise<void> {
    try {
      switch (channel.type) {
        case 'webhook':
          await this.sendWebhook(channel.config, alert);
          break;
        case 'email':
          await this.sendEmail(channel.config, alert);
          break;
        case 'slack':
          await this.sendSlack(channel.config, alert);
          break;
        case 'console':
          this.sendConsole(alert);
          break;
        default:
          this.logger.warn(`Unknown alert channel type: ${channel.type}`);
      }
    } catch (error) {
      this.logger.error(`Failed to send alert to ${channel.type}:`, error);
    }
  }
  
  private async sendWebhook(config: any, alert: Alert): Promise<void> {
    // Placeholder for webhook implementation
    this.logger.debug(`Would send webhook to ${config.url} for alert: ${alert.message}`);
  }
  
  private async sendEmail(config: any, alert: Alert): Promise<void> {
    // Placeholder for email implementation
    this.logger.debug(`Would send email to ${config.to} for alert: ${alert.message}`);
  }
  
  private async sendSlack(config: any, alert: Alert): Promise<void> {
    // Placeholder for Slack implementation
    this.logger.debug(`Would send Slack message to ${config.channel} for alert: ${alert.message}`);
  }
  
  private sendConsole(alert: Alert): void {
    const severityColor = {
      low: '\x1b[32m',      // Green
      medium: '\x1b[33m',   // Yellow
      high: '\x1b[31m',     // Red
      critical: '\x1b[35m', // Magenta
    };
    
    const color = severityColor[alert.severity] || '\x1b[0m';
    const reset = '\x1b[0m';
    
    console.log(`${color}🚨 ALERT [${alert.severity.toUpperCase()}]: ${alert.message}${reset}`);
    console.log(`   Time: ${alert.timestamp.toISOString()}`);
    console.log(`   Metric: ${alert.metric} = ${alert.value} (threshold: ${alert.threshold})`);
    console.log(`   Alert ID: ${alert.id}`);
    console.log('');
  }
  
  private initializeDefaultRules(): void {
    const defaultRules: AlertRule[] = [
      {
        id: 'high_login_failures',
        name: 'High Login Failure Rate',
        metric: 'auth.login.failure',
        condition: 'greater_than',
        threshold: 10,
        windowMinutes: 5,
        severity: 'high',
        enabled: true,
      },
      {
        id: 'rate_limit_exceeded',
        name: 'Rate Limit Exceeded',
        metric: 'security.rate_limit.exceeded',
        condition: 'greater_than',
        threshold: 5,
        windowMinutes: 1,
        severity: 'medium',
        enabled: true,
      },
      {
        id: 'brute_force_detected',
        name: 'Brute Force Attack Detected',
        metric: 'security.brute_force.detected',
        condition: 'greater_than',
        threshold: 0,
        windowMinutes: 1,
        severity: 'critical',
        enabled: true,
      },
      {
        id: 'high_api_response_time',
        name: 'High API Response Time',
        metric: 'api.request.duration',
        condition: 'greater_than',
        threshold: 2000, // 2 seconds
        windowMinutes: 5,
        severity: 'medium',
        enabled: true,
      },
      {
        id: 'high_memory_usage',
        name: 'High Memory Usage',
        metric: 'system.memory.usage',
        condition: 'greater_than',
        threshold: 512, // 512 MB
        windowMinutes: 5,
        severity: 'medium',
        enabled: true,
        tags: { type: 'heap_used' },
      },
      {
        id: 'oauth_failures',
        name: 'OAuth Login Failures',
        metric: 'auth.oauth.login.failure',
        condition: 'greater_than',
        threshold: 5,
        windowMinutes: 10,
        severity: 'medium',
        enabled: true,
      },
    ];
    
    defaultRules.forEach(rule => this.addRule(rule));
  }
  
  private initializeChannels(): void {
    // Console channel is always enabled for development
    this.addChannel({
      type: 'console',
      config: {},
      enabled: true,
    });
    
    // Add other channels based on configuration
    const config = this.configService.get<AppConfig>('app');
    
    if (config?.MONITORING_WEBHOOK_URL) {
      this.addChannel({
        type: 'webhook',
        config: { url: config.MONITORING_WEBHOOK_URL },
        enabled: true,
      });
    }
    
    if (config?.MONITORING_EMAIL_TO) {
      this.addChannel({
        type: 'email',
        config: { to: config.MONITORING_EMAIL_TO },
        enabled: true,
      });
    }
  }
  
  private startAlertChecking(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }
    
    // Check rules every minute
    this.checkInterval = setInterval(() => {
      this.checkRules().catch(error => {
        this.logger.error('Error during rule checking:', error);
      });
    }, 60000);
    
    this.logger.log('Alert checking started (interval: 1 minute)');
  }
  
  onModuleDestroy() {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.logger.log('Alert checking stopped');
    }
  }
}