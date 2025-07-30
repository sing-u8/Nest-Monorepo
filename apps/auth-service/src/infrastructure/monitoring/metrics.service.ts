import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * Metrics Service
 * 
 * Collects and manages application metrics for monitoring
 * authentication events, performance, and system health.
 */
@Injectable()
export class MetricsService implements OnModuleDestroy {
  private metrics: Map<string, any> = new Map();
  private counters: Map<string, number> = new Map();
  private gauges: Map<string, number> = new Map();
  private histograms: Map<string, number[]> = new Map();
  private timers: Map<string, number> = new Map();
  private labels: Map<string, Record<string, string>> = new Map();
  private metricsFlushInterval: NodeJS.Timeout | null = null;

  constructor(private readonly configService: ConfigService) {
    this.initializeMetrics();
    this.startMetricsFlush();
  }

  onModuleDestroy() {
    if (this.metricsFlushInterval) {
      clearInterval(this.metricsFlushInterval);
    }
  }

  /**
   * Initialize core metrics
   */
  private initializeMetrics(): void {
    // Authentication metrics
    this.initCounter('auth_requests_total', 'Total authentication requests');
    this.initCounter('auth_success_total', 'Successful authentication requests');
    this.initCounter('auth_failures_total', 'Failed authentication requests');
    this.initCounter('auth_registrations_total', 'Total user registrations');
    this.initCounter('auth_logins_total', 'Total user logins');
    this.initCounter('auth_logouts_total', 'Total user logouts');
    this.initCounter('auth_token_refreshes_total', 'Total token refresh requests');
    
    // OAuth metrics
    this.initCounter('oauth_requests_total', 'Total OAuth authentication requests');
    this.initCounter('oauth_success_total', 'Successful OAuth authentications');
    this.initCounter('oauth_failures_total', 'Failed OAuth authentications');
    
    // Security metrics
    this.initCounter('security_rate_limits_total', 'Total rate limit violations');
    this.initCounter('security_blocked_requests_total', 'Total blocked requests');
    this.initCounter('security_mtls_requests_total', 'Total mTLS authentication attempts');
    this.initCounter('security_mtls_failures_total', 'Failed mTLS authentications');
    
    // Performance metrics
    this.initHistogram('auth_request_duration_ms', 'Authentication request duration');
    this.initHistogram('database_query_duration_ms', 'Database query duration');
    this.initHistogram('oauth_external_request_duration_ms', 'OAuth external request duration');
    
    // System metrics
    this.initGauge('active_sessions_count', 'Number of active user sessions');
    this.initGauge('database_connections_active', 'Active database connections');
    this.initGauge('memory_usage_mb', 'Memory usage in MB');
    this.initGauge('cpu_usage_percent', 'CPU usage percentage');
  }

  /**
   * Initialize a counter metric
   */
  private initCounter(name: string, description: string): void {
    this.counters.set(name, 0);
    this.metrics.set(name, {
      type: 'counter',
      description,
      value: 0,
      createdAt: new Date(),
    });
  }

  /**
   * Initialize a gauge metric
   */
  private initGauge(name: string, description: string): void {
    this.gauges.set(name, 0);
    this.metrics.set(name, {
      type: 'gauge',
      description,
      value: 0,
      createdAt: new Date(),
    });
  }

  /**
   * Initialize a histogram metric
   */
  private initHistogram(name: string, description: string): void {
    this.histograms.set(name, []);
    this.metrics.set(name, {
      type: 'histogram',
      description,
      values: [],
      count: 0,
      sum: 0,
      avg: 0,
      min: 0,
      max: 0,
      p50: 0,
      p90: 0,
      p95: 0,
      p99: 0,
      createdAt: new Date(),
    });
  }

  /**
   * Increment a counter metric
   */
  incrementCounter(name: string, value = 1, labels?: Record<string, string>): void {
    const currentValue = this.counters.get(name) || 0;
    const newValue = currentValue + value;
    
    this.counters.set(name, newValue);
    
    const metric = this.metrics.get(name);
    if (metric) {
      metric.value = newValue;
      metric.lastUpdated = new Date();
      if (labels) {
        this.labels.set(`${name}_${JSON.stringify(labels)}`, labels);
      }
    }
  }

  /**
   * Set a gauge metric value
   */
  setGauge(name: string, value: number, labels?: Record<string, string>): void {
    this.gauges.set(name, value);
    
    const metric = this.metrics.get(name);
    if (metric) {
      metric.value = value;
      metric.lastUpdated = new Date();
      if (labels) {
        this.labels.set(`${name}_${JSON.stringify(labels)}`, labels);
      }
    }
  }

  /**
   * Add a value to a histogram metric
   */
  observeHistogram(name: string, value: number, labels?: Record<string, string>): void {
    const values = this.histograms.get(name) || [];
    values.push(value);
    
    // Keep only last 1000 values for memory efficiency
    if (values.length > 1000) {
      values.shift();
    }
    
    this.histograms.set(name, values);
    
    const metric = this.metrics.get(name);
    if (metric) {
      metric.values = values;
      metric.count = values.length;
      metric.sum = values.reduce((sum, val) => sum + val, 0);
      metric.avg = metric.sum / metric.count;
      metric.min = Math.min(...values);
      metric.max = Math.max(...values);
      
      // Calculate percentiles
      const sorted = [...values].sort((a, b) => a - b);
      metric.p50 = this.percentile(sorted, 0.5);
      metric.p90 = this.percentile(sorted, 0.9);
      metric.p95 = this.percentile(sorted, 0.95);
      metric.p99 = this.percentile(sorted, 0.99);
      
      metric.lastUpdated = new Date();
      if (labels) {
        this.labels.set(`${name}_${JSON.stringify(labels)}`, labels);
      }
    }
  }

  /**
   * Start a timer for measuring duration
   */
  startTimer(name: string): () => void {
    const startTime = Date.now();
    this.timers.set(name, startTime);
    
    return () => {
      const endTime = Date.now();
      const duration = endTime - startTime;
      this.observeHistogram(name, duration);
      this.timers.delete(name);
    };
  }

  /**
   * Record authentication event metrics
   */
  recordAuthEvent(event: 'request' | 'success' | 'failure' | 'registration' | 'login' | 'logout', 
                  provider?: string, duration?: number): void {
    const labels = provider ? { provider } : undefined;
    
    switch (event) {
      case 'request':
        this.incrementCounter('auth_requests_total', 1, labels);
        break;
      case 'success':
        this.incrementCounter('auth_success_total', 1, labels);
        break;
      case 'failure':
        this.incrementCounter('auth_failures_total', 1, labels);
        break;
      case 'registration':
        this.incrementCounter('auth_registrations_total', 1, labels);
        break;
      case 'login':
        this.incrementCounter('auth_logins_total', 1, labels);
        break;
      case 'logout':
        this.incrementCounter('auth_logouts_total', 1, labels);
        break;
    }
    
    if (duration !== undefined) {
      this.observeHistogram('auth_request_duration_ms', duration, labels);
    }
  }

  /**
   * Record OAuth event metrics
   */
  recordOAuthEvent(event: 'request' | 'success' | 'failure', provider: string, duration?: number): void {
    const labels = { provider };
    
    this.incrementCounter('oauth_requests_total', 1, labels);
    
    switch (event) {
      case 'success':
        this.incrementCounter('oauth_success_total', 1, labels);
        break;
      case 'failure':
        this.incrementCounter('oauth_failures_total', 1, labels);
        break;
    }
    
    if (duration !== undefined) {
      this.observeHistogram('oauth_external_request_duration_ms', duration, labels);
    }
  }

  /**
   * Record security event metrics
   */
  recordSecurityEvent(event: 'rate_limit' | 'blocked_request' | 'mtls_attempt' | 'mtls_failure',
                      reason?: string): void {
    const labels = reason ? { reason } : undefined;
    
    switch (event) {
      case 'rate_limit':
        this.incrementCounter('security_rate_limits_total', 1, labels);
        break;
      case 'blocked_request':
        this.incrementCounter('security_blocked_requests_total', 1, labels);
        break;
      case 'mtls_attempt':
        this.incrementCounter('security_mtls_requests_total', 1, labels);
        break;
      case 'mtls_failure':
        this.incrementCounter('security_mtls_failures_total', 1, labels);
        break;
    }
  }

  /**
   * Record database metrics
   */
  recordDatabaseMetrics(activeConnections: number, queryDuration?: number): void {
    this.setGauge('database_connections_active', activeConnections);
    
    if (queryDuration !== undefined) {
      this.observeHistogram('database_query_duration_ms', queryDuration);
    }
  }

  /**
   * Record system metrics
   */
  recordSystemMetrics(): void {
    const memUsage = process.memoryUsage();
    const memUsageMB = Math.round(memUsage.heapUsed / 1024 / 1024);
    
    this.setGauge('memory_usage_mb', memUsageMB);
    
    // CPU usage would require additional system monitoring libraries
    // For now, we'll use process.cpuUsage() as an approximation
    const cpuUsage = process.cpuUsage();
    const cpuPercent = Math.round((cpuUsage.user + cpuUsage.system) / 1000000); // Convert to percentage approximation
    this.setGauge('cpu_usage_percent', Math.min(cpuPercent, 100));
  }

  /**
   * Get all metrics
   */
  getAllMetrics(): Record<string, any> {
    const result: Record<string, any> = {};
    
    for (const [name, metric] of this.metrics) {
      result[name] = { ...metric };
    }
    
    return result;
  }

  /**
   * Get metrics in Prometheus format
   */
  getPrometheusMetrics(): string {
    let output = '';
    
    for (const [name, metric] of this.metrics) {
      output += `# HELP ${name} ${metric.description}\n`;
      output += `# TYPE ${name} ${metric.type}\n`;
      
      if (metric.type === 'counter' || metric.type === 'gauge') {
        output += `${name} ${metric.value}\n`;
      } else if (metric.type === 'histogram') {
        output += `${name}_count ${metric.count}\n`;
        output += `${name}_sum ${metric.sum}\n`;
        output += `${name}_avg ${metric.avg}\n`;
        output += `${name}_min ${metric.min}\n`;
        output += `${name}_max ${metric.max}\n`;
        output += `${name}{quantile="0.5"} ${metric.p50}\n`;
        output += `${name}{quantile="0.9"} ${metric.p90}\n`;
        output += `${name}{quantile="0.95"} ${metric.p95}\n`;
        output += `${name}{quantile="0.99"} ${metric.p99}\n`;
      }
      
      output += '\n';
    }
    
    return output;
  }

  /**
   * Get metrics summary
   */
  getMetricsSummary(): any {
    const summary = {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      authentication: {
        totalRequests: this.counters.get('auth_requests_total'),
        successfulRequests: this.counters.get('auth_success_total'),
        failedRequests: this.counters.get('auth_failures_total'),
        successRate: this.calculateSuccessRate('auth_success_total', 'auth_requests_total'),
        registrations: this.counters.get('auth_registrations_total'),
        logins: this.counters.get('auth_logins_total'),
        logouts: this.counters.get('auth_logouts_total'),
      },
      oauth: {
        totalRequests: this.counters.get('oauth_requests_total'),
        successfulRequests: this.counters.get('oauth_success_total'),
        failedRequests: this.counters.get('oauth_failures_total'),
        successRate: this.calculateSuccessRate('oauth_success_total', 'oauth_requests_total'),
      },
      security: {
        rateLimitViolations: this.counters.get('security_rate_limits_total'),
        blockedRequests: this.counters.get('security_blocked_requests_total'),
        mtlsAttempts: this.counters.get('security_mtls_requests_total'),
        mtlsFailures: this.counters.get('security_mtls_failures_total'),
      },
      system: {
        activeSessions: this.gauges.get('active_sessions_count'),
        memoryUsageMB: this.gauges.get('memory_usage_mb'),
        cpuUsagePercent: this.gauges.get('cpu_usage_percent'),
        databaseConnections: this.gauges.get('database_connections_active'),
      },
      performance: {
        avgAuthDuration: this.metrics.get('auth_request_duration_ms')?.avg || 0,
        avgDatabaseQuery: this.metrics.get('database_query_duration_ms')?.avg || 0,
        avgOAuthRequest: this.metrics.get('oauth_external_request_duration_ms')?.avg || 0,
      },
    };
    
    return summary;
  }

  /**
   * Calculate success rate percentage
   */
  private calculateSuccessRate(successMetric: string, totalMetric: string): number {
    const success = this.counters.get(successMetric) || 0;
    const total = this.counters.get(totalMetric) || 0;
    
    if (total === 0) return 0;
    return Math.round((success / total) * 100 * 100) / 100; // Round to 2 decimal places
  }

  /**
   * Calculate percentile from sorted array
   */
  private percentile(sortedArray: number[], percentile: number): number {
    if (sortedArray.length === 0) return 0;
    
    const index = percentile * (sortedArray.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    
    if (lower === upper) {
      return sortedArray[lower];
    }
    
    const weight = index - lower;
    return sortedArray[lower] * (1 - weight) + sortedArray[upper] * weight;
  }

  /**
   * Start periodic metrics flushing
   */
  private startMetricsFlush(): void {
    const flushInterval = this.configService.get<number>('monitoring.metricsFlushInterval', 60000); // Default 1 minute
    
    this.metricsFlushInterval = setInterval(() => {
      this.recordSystemMetrics();
      this.flushMetrics();
    }, flushInterval);
  }

  /**
   * Flush metrics (can be extended to send to external monitoring systems)
   */
  private flushMetrics(): void {
    // Log metrics summary for now
    // In production, this could send metrics to Prometheus, DataDog, etc.
    const summary = this.getMetricsSummary();
    console.log('Metrics Summary:', JSON.stringify(summary, null, 2));
  }

  /**
   * Reset all metrics (useful for testing)
   */
  resetMetrics(): void {
    this.counters.clear();
    this.gauges.clear();
    this.histograms.clear();
    this.timers.clear();
    this.labels.clear();
    this.metrics.clear();
    this.initializeMetrics();
  }
}