import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/app.config';

export interface MetricType {
  // Authentication metrics
  LOGIN_SUCCESS: 'auth.login.success';
  LOGIN_FAILURE: 'auth.login.failure';
  REGISTER_SUCCESS: 'auth.register.success';
  REGISTER_FAILURE: 'auth.register.failure';
  LOGOUT: 'auth.logout';
  TOKEN_REFRESH_SUCCESS: 'auth.token.refresh.success';
  TOKEN_REFRESH_FAILURE: 'auth.token.refresh.failure';
  TOKEN_VALIDATION_SUCCESS: 'auth.token.validation.success';
  TOKEN_VALIDATION_FAILURE: 'auth.token.validation.failure';
  
  // OAuth metrics
  OAUTH_LOGIN_SUCCESS: 'auth.oauth.login.success';
  OAUTH_LOGIN_FAILURE: 'auth.oauth.login.failure';
  OAUTH_CALLBACK_SUCCESS: 'auth.oauth.callback.success';
  OAUTH_CALLBACK_FAILURE: 'auth.oauth.callback.failure';
  
  // Security metrics
  RATE_LIMIT_EXCEEDED: 'security.rate_limit.exceeded';
  SUSPICIOUS_ACTIVITY: 'security.suspicious_activity';
  INVALID_TOKEN_ATTEMPT: 'security.invalid_token.attempt';
  BRUTE_FORCE_DETECTED: 'security.brute_force.detected';
  
  // Performance metrics
  API_REQUEST_DURATION: 'api.request.duration';
  DATABASE_QUERY_DURATION: 'database.query.duration';
  EXTERNAL_SERVICE_DURATION: 'external.service.duration';
  
  // System metrics
  MEMORY_USAGE: 'system.memory.usage';
  CPU_USAGE: 'system.cpu.usage';
  ACTIVE_CONNECTIONS: 'system.connections.active';
  ERROR_RATE: 'system.error.rate';
}

export const METRIC_TYPES: MetricType = {
  // Authentication metrics
  LOGIN_SUCCESS: 'auth.login.success',
  LOGIN_FAILURE: 'auth.login.failure',
  REGISTER_SUCCESS: 'auth.register.success',
  REGISTER_FAILURE: 'auth.register.failure',
  LOGOUT: 'auth.logout',
  TOKEN_REFRESH_SUCCESS: 'auth.token.refresh.success',
  TOKEN_REFRESH_FAILURE: 'auth.token.refresh.failure',
  TOKEN_VALIDATION_SUCCESS: 'auth.token.validation.success',
  TOKEN_VALIDATION_FAILURE: 'auth.token.validation.failure',
  
  // OAuth metrics
  OAUTH_LOGIN_SUCCESS: 'auth.oauth.login.success',
  OAUTH_LOGIN_FAILURE: 'auth.oauth.login.failure',
  OAUTH_CALLBACK_SUCCESS: 'auth.oauth.callback.success',
  OAUTH_CALLBACK_FAILURE: 'auth.oauth.callback.failure',
  
  // Security metrics
  RATE_LIMIT_EXCEEDED: 'security.rate_limit.exceeded',
  SUSPICIOUS_ACTIVITY: 'security.suspicious_activity',
  INVALID_TOKEN_ATTEMPT: 'security.invalid_token.attempt',
  BRUTE_FORCE_DETECTED: 'security.brute_force.detected',
  
  // Performance metrics
  API_REQUEST_DURATION: 'api.request.duration',
  DATABASE_QUERY_DURATION: 'database.query.duration',
  EXTERNAL_SERVICE_DURATION: 'external.service.duration',
  
  // System metrics
  MEMORY_USAGE: 'system.memory.usage',
  CPU_USAGE: 'system.cpu.usage',
  ACTIVE_CONNECTIONS: 'system.connections.active',
  ERROR_RATE: 'system.error.rate',
};

export interface MetricData {
  metric: string;
  value: number;
  timestamp: Date;
  tags?: Record<string, string>;
  metadata?: Record<string, any>;
}

export interface MetricsSummary {
  metric: string;
  count: number;
  sum: number;
  min: number;
  max: number;
  average: number;
  p50?: number;
  p95?: number;
  p99?: number;
  tags?: Record<string, string>;
}

/**
 * Metrics Service
 * 
 * Collects and manages application metrics for monitoring and alerting.
 * Provides interfaces for authentication events, performance monitoring,
 * and security event tracking.
 */
@Injectable()
export class MetricsService {
  private readonly logger = new Logger(MetricsService.name);
  private readonly metrics: Map<string, MetricData[]> = new Map();
  private readonly maxMetricsPerType = 10000;
  private readonly metricsRetentionMs = 3600000; // 1 hour
  private readonly isEnabled: boolean;
  
  constructor(private configService: ConfigService) {
    const config = this.configService.get<AppConfig>('app');
    this.isEnabled = config?.MONITORING_ENABLE_METRICS || false;
    
    if (this.isEnabled) {
      this.logger.log('Metrics collection enabled');
      this.startCleanupInterval();
    } else {
      this.logger.log('Metrics collection disabled');
    }
  }
  
  /**
   * Increment a counter metric
   */
  increment(
    metric: string,
    tags?: Record<string, string>,
    metadata?: Record<string, any>,
  ): void {
    if (!this.isEnabled) return;
    
    this.record(metric, 1, tags, metadata);
  }
  
  /**
   * Decrement a counter metric
   */
  decrement(
    metric: string,
    tags?: Record<string, string>,
    metadata?: Record<string, any>,
  ): void {
    if (!this.isEnabled) return;
    
    this.record(metric, -1, tags, metadata);
  }
  
  /**
   * Record a gauge metric value
   */
  gauge(
    metric: string,
    value: number,
    tags?: Record<string, string>,
    metadata?: Record<string, any>,
  ): void {
    if (!this.isEnabled) return;
    
    this.record(metric, value, tags, metadata);
  }
  
  /**
   * Record a timing metric (in milliseconds)
   */
  timing(
    metric: string,
    duration: number,
    tags?: Record<string, string>,
    metadata?: Record<string, any>,
  ): void {
    if (!this.isEnabled) return;
    
    this.record(metric, duration, tags, metadata);
  }
  
  /**
   * Start a timer for measuring duration
   */
  startTimer(metric: string, tags?: Record<string, string>): () => void {
    const startTime = Date.now();
    
    return () => {
      const duration = Date.now() - startTime;
      this.timing(metric, duration, tags);
    };
  }
  
  /**
   * Record authentication success
   */
  recordAuthSuccess(
    type: 'login' | 'register' | 'oauth' | 'refresh',
    provider?: string,
    metadata?: Record<string, any>,
  ): void {
    const metric = this.getAuthMetric(type, true);
    const tags = provider ? { provider } : undefined;
    
    this.increment(metric, tags, metadata);
    this.logger.debug(`Authentication success recorded: ${type}`, { provider, metadata });
  }
  
  /**
   * Record authentication failure
   */
  recordAuthFailure(
    type: 'login' | 'register' | 'oauth' | 'refresh',
    reason: string,
    provider?: string,
    metadata?: Record<string, any>,
  ): void {
    const metric = this.getAuthMetric(type, false);
    const tags = { reason, ...(provider ? { provider } : {}) };
    
    this.increment(metric, tags, metadata);
    this.logger.debug(`Authentication failure recorded: ${type}`, { reason, provider, metadata });
  }
  
  /**
   * Record security event
   */
  recordSecurityEvent(
    type: 'rate_limit' | 'suspicious_activity' | 'invalid_token' | 'brute_force',
    metadata?: Record<string, any>,
  ): void {
    const metricMap = {
      rate_limit: METRIC_TYPES.RATE_LIMIT_EXCEEDED,
      suspicious_activity: METRIC_TYPES.SUSPICIOUS_ACTIVITY,
      invalid_token: METRIC_TYPES.INVALID_TOKEN_ATTEMPT,
      brute_force: METRIC_TYPES.BRUTE_FORCE_DETECTED,
    };
    
    const metric = metricMap[type];
    this.increment(metric, undefined, metadata);
    
    this.logger.warn(`Security event recorded: ${type}`, metadata);
  }
  
  /**
   * Record API performance
   */
  recordApiPerformance(
    endpoint: string,
    method: string,
    statusCode: number,
    duration: number,
    metadata?: Record<string, any>,
  ): void {
    const tags = { endpoint, method, status: statusCode.toString() };
    
    this.timing(METRIC_TYPES.API_REQUEST_DURATION, duration, tags, metadata);
    
    if (duration > 1000) {
      this.logger.warn(`Slow API request detected: ${method} ${endpoint} (${duration}ms)`);
    }
  }
  
  /**
   * Record database query performance
   */
  recordDatabasePerformance(
    operation: string,
    table: string,
    duration: number,
    metadata?: Record<string, any>,
  ): void {
    const tags = { operation, table };
    
    this.timing(METRIC_TYPES.DATABASE_QUERY_DURATION, duration, tags, metadata);
    
    if (duration > 100) {
      this.logger.warn(`Slow database query detected: ${operation} on ${table} (${duration}ms)`);
    }
  }
  
  /**
   * Record external service performance
   */
  recordExternalServicePerformance(
    service: string,
    operation: string,
    duration: number,
    success: boolean,
    metadata?: Record<string, any>,
  ): void {
    const tags = { service, operation, success: success.toString() };
    
    this.timing(METRIC_TYPES.EXTERNAL_SERVICE_DURATION, duration, tags, metadata);
    
    if (duration > 5000) {
      this.logger.warn(`Slow external service call: ${service}/${operation} (${duration}ms)`);
    }
  }
  
  /**
   * Record system metrics
   */
  recordSystemMetrics(): void {
    if (!this.isEnabled) return;
    
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    
    // Memory metrics (in MB)
    this.gauge(METRIC_TYPES.MEMORY_USAGE, memoryUsage.heapUsed / 1024 / 1024, { type: 'heap_used' });
    this.gauge(METRIC_TYPES.MEMORY_USAGE, memoryUsage.heapTotal / 1024 / 1024, { type: 'heap_total' });
    this.gauge(METRIC_TYPES.MEMORY_USAGE, memoryUsage.rss / 1024 / 1024, { type: 'rss' });
    this.gauge(METRIC_TYPES.MEMORY_USAGE, memoryUsage.external / 1024 / 1024, { type: 'external' });
    
    // CPU metrics (in microseconds)
    this.gauge(METRIC_TYPES.CPU_USAGE, cpuUsage.user, { type: 'user' });
    this.gauge(METRIC_TYPES.CPU_USAGE, cpuUsage.system, { type: 'system' });
  }
  
  /**
   * Get metrics summary for a specific metric
   */
  getMetricsSummary(metric: string, tags?: Record<string, string>): MetricsSummary | null {
    if (!this.isEnabled) return null;
    
    const metricKey = this.getMetricKey(metric, tags);
    const data = this.metrics.get(metricKey);
    
    if (!data || data.length === 0) {
      return null;
    }
    
    const values = data.map(d => d.value).sort((a, b) => a - b);
    const sum = values.reduce((acc, val) => acc + val, 0);
    
    return {
      metric,
      count: values.length,
      sum,
      min: values[0],
      max: values[values.length - 1],
      average: sum / values.length,
      p50: this.percentile(values, 0.5),
      p95: this.percentile(values, 0.95),
      p99: this.percentile(values, 0.99),
      tags,
    };
  }
  
  /**
   * Get all metrics summaries
   */
  getAllMetricsSummaries(): MetricsSummary[] {
    if (!this.isEnabled) return [];
    
    const summaries: MetricsSummary[] = [];
    
    for (const [key, data] of this.metrics.entries()) {
      if (data.length > 0) {
        const [metric, ...tagPairs] = key.split('|');
        const tags = tagPairs.length > 0 
          ? Object.fromEntries(tagPairs.map(pair => pair.split(':')))
          : undefined;
        
        const summary = this.getMetricsSummary(metric, tags);
        if (summary) {
          summaries.push(summary);
        }
      }
    }
    
    return summaries;
  }
  
  /**
   * Get metrics for export
   */
  exportMetrics(format: 'json' | 'prometheus' = 'json'): string {
    if (!this.isEnabled) return '';
    
    const summaries = this.getAllMetricsSummaries();
    
    if (format === 'json') {
      return JSON.stringify(summaries, null, 2);
    }
    
    // Prometheus format
    const lines: string[] = [];
    
    for (const summary of summaries) {
      const labels = summary.tags 
        ? Object.entries(summary.tags).map(([k, v]) => `${k}="${v}"`).join(',')
        : '';
      
      const metricName = summary.metric.replace(/\./g, '_');
      
      lines.push(`# TYPE ${metricName}_count counter`);
      lines.push(`${metricName}_count${labels ? `{${labels}}` : ''} ${summary.count}`);
      
      lines.push(`# TYPE ${metricName}_sum gauge`);
      lines.push(`${metricName}_sum${labels ? `{${labels}}` : ''} ${summary.sum}`);
      
      if (summary.p50 !== undefined) {
        lines.push(`# TYPE ${metricName}_percentile gauge`);
        lines.push(`${metricName}_percentile{quantile="0.5"${labels ? `,${labels}` : ''}} ${summary.p50}`);
        lines.push(`${metricName}_percentile{quantile="0.95"${labels ? `,${labels}` : ''}} ${summary.p95}`);
        lines.push(`${metricName}_percentile{quantile="0.99"${labels ? `,${labels}` : ''}} ${summary.p99}`);
      }
    }
    
    return lines.join('\n');
  }
  
  /**
   * Clear all metrics
   */
  clearMetrics(): void {
    this.metrics.clear();
    this.logger.log('All metrics cleared');
  }
  
  /**
   * Get health status
   */
  getHealthStatus(): Record<string, any> {
    const totalMetrics = Array.from(this.metrics.values()).reduce((sum, data) => sum + data.length, 0);
    
    return {
      enabled: this.isEnabled,
      totalMetrics,
      metricsTypes: this.metrics.size,
      maxMetricsPerType: this.maxMetricsPerType,
      retentionMs: this.metricsRetentionMs,
    };
  }
  
  private record(
    metric: string,
    value: number,
    tags?: Record<string, string>,
    metadata?: Record<string, any>,
  ): void {
    const metricKey = this.getMetricKey(metric, tags);
    
    if (!this.metrics.has(metricKey)) {
      this.metrics.set(metricKey, []);
    }
    
    const data = this.metrics.get(metricKey)!;
    
    data.push({
      metric,
      value,
      timestamp: new Date(),
      tags,
      metadata,
    });
    
    // Limit metrics per type
    if (data.length > this.maxMetricsPerType) {
      data.shift();
    }
  }
  
  private getMetricKey(metric: string, tags?: Record<string, string>): string {
    if (!tags || Object.keys(tags).length === 0) {
      return metric;
    }
    
    const tagPairs = Object.entries(tags)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}:${v}`)
      .join('|');
    
    return `${metric}|${tagPairs}`;
  }
  
  private getAuthMetric(type: string, success: boolean): string {
    const metricMap = {
      login: success ? METRIC_TYPES.LOGIN_SUCCESS : METRIC_TYPES.LOGIN_FAILURE,
      register: success ? METRIC_TYPES.REGISTER_SUCCESS : METRIC_TYPES.REGISTER_FAILURE,
      oauth: success ? METRIC_TYPES.OAUTH_LOGIN_SUCCESS : METRIC_TYPES.OAUTH_LOGIN_FAILURE,
      refresh: success ? METRIC_TYPES.TOKEN_REFRESH_SUCCESS : METRIC_TYPES.TOKEN_REFRESH_FAILURE,
    };
    
    return metricMap[type] || (success ? METRIC_TYPES.LOGIN_SUCCESS : METRIC_TYPES.LOGIN_FAILURE);
  }
  
  private percentile(sortedValues: number[], p: number): number {
    const index = Math.ceil(sortedValues.length * p) - 1;
    return sortedValues[Math.max(0, Math.min(index, sortedValues.length - 1))];
  }
  
  private startCleanupInterval(): void {
    setInterval(() => {
      this.cleanupOldMetrics();
    }, 60000); // Run every minute
  }
  
  private cleanupOldMetrics(): void {
    const now = Date.now();
    let cleanedCount = 0;
    
    for (const [key, data] of this.metrics.entries()) {
      const filtered = data.filter(d => 
        now - d.timestamp.getTime() < this.metricsRetentionMs
      );
      
      if (filtered.length < data.length) {
        cleanedCount += data.length - filtered.length;
        
        if (filtered.length === 0) {
          this.metrics.delete(key);
        } else {
          this.metrics.set(key, filtered);
        }
      }
    }
    
    if (cleanedCount > 0) {
      this.logger.debug(`Cleaned up ${cleanedCount} old metrics`);
    }
  }
}