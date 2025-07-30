import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MetricsService } from './metrics.service';

/**
 * Performance monitoring data structure
 */
interface PerformanceData {
  operationName: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  metadata?: Record<string, any>;
  success?: boolean;
  error?: string;
}

/**
 * Performance threshold configuration
 */
interface PerformanceThreshold {
  warning: number;
  critical: number;
  unit: 'ms' | 's' | 'count';
}

/**
 * Performance Monitoring Service
 * 
 * Monitors critical application paths, tracks performance metrics,
 * and provides alerting for performance degradation.
 */
@Injectable()
export class PerformanceService implements OnModuleDestroy {
  private activeOperations: Map<string, PerformanceData> = new Map();
  private performanceHistory: PerformanceData[] = [];
  private thresholds: Map<string, PerformanceThreshold> = new Map();
  private alerts: Array<{ timestamp: Date; message: string; severity: 'warning' | 'critical' }> = [];
  private monitoringInterval: NodeJS.Timeout | null = null;

  constructor(
    private readonly metricsService: MetricsService,
    private readonly configService: ConfigService,
  ) {
    this.initializeThresholds();
    this.startPerformanceMonitoring();
  }

  onModuleDestroy() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }
  }

  /**
   * Initialize performance thresholds for critical operations
   */
  private initializeThresholds(): void {
    // Authentication operations
    this.thresholds.set('auth.register', { warning: 2000, critical: 5000, unit: 'ms' });
    this.thresholds.set('auth.login', { warning: 1000, critical: 3000, unit: 'ms' });
    this.thresholds.set('auth.refresh', { warning: 500, critical: 1500, unit: 'ms' });
    this.thresholds.set('auth.logout', { warning: 300, critical: 1000, unit: 'ms' });
    
    // Database operations
    this.thresholds.set('database.query', { warning: 100, critical: 500, unit: 'ms' });
    this.thresholds.set('database.transaction', { warning: 200, critical: 1000, unit: 'ms' });
    this.thresholds.set('database.migration', { warning: 10000, critical: 30000, unit: 'ms' });
    
    // External service operations
    this.thresholds.set('oauth.google', { warning: 2000, critical: 5000, unit: 'ms' });
    this.thresholds.set('oauth.apple', { warning: 3000, critical: 7000, unit: 'ms' });
    this.thresholds.set('external.http', { warning: 1000, critical: 3000, unit: 'ms' });
    
    // Business logic operations
    this.thresholds.set('password.hash', { warning: 200, critical: 500, unit: 'ms' });
    this.thresholds.set('token.generate', { warning: 50, critical: 200, unit: 'ms' });
    this.thresholds.set('token.verify', { warning: 50, critical: 200, unit: 'ms' });
    
    // Security operations
    this.thresholds.set('security.ratelimit', { warning: 10, critical: 50, unit: 'ms' });
    this.thresholds.set('security.mtls', { warning: 100, critical: 300, unit: 'ms' });
    this.thresholds.set('security.audit', { warning: 50, critical: 200, unit: 'ms' });
  }

  /**
   * Start monitoring a performance-critical operation
   */
  startOperation(operationName: string, metadata?: Record<string, any>): string {
    const operationId = `${operationName}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const performanceData: PerformanceData = {
      operationName,
      startTime: Date.now(),
      metadata,
    };
    
    this.activeOperations.set(operationId, performanceData);
    
    return operationId;
  }

  /**
   * End monitoring of an operation
   */
  endOperation(operationId: string, success = true, error?: string): PerformanceData | null {
    const operation = this.activeOperations.get(operationId);
    
    if (!operation) {
      console.warn(`Performance monitoring: Operation ${operationId} not found`);
      return null;
    }
    
    const endTime = Date.now();
    const duration = endTime - operation.startTime;
    
    operation.endTime = endTime;
    operation.duration = duration;
    operation.success = success;
    operation.error = error;
    
    // Record metrics
    this.metricsService.observeHistogram(
      `performance_${operation.operationName.replace(/\./g, '_')}_duration_ms`,
      duration,
      { success: success.toString() }
    );
    
    // Check thresholds and generate alerts
    this.checkPerformanceThreshold(operation);
    
    // Store in history (keep last 1000 operations)
    this.performanceHistory.push({ ...operation });
    if (this.performanceHistory.length > 1000) {
      this.performanceHistory.shift();
    }
    
    // Remove from active operations
    this.activeOperations.delete(operationId);
    
    return operation;
  }

  /**
   * Monitor a function execution
   */
  async monitorFunction<T>(
    operationName: string,
    fn: () => Promise<T>,
    metadata?: Record<string, any>
  ): Promise<T> {
    const operationId = this.startOperation(operationName, metadata);
    
    try {
      const result = await fn();
      this.endOperation(operationId, true);
      return result;
    } catch (error) {
      this.endOperation(operationId, false, error.message);
      throw error;
    }
  }

  /**
   * Monitor a synchronous function execution
   */
  monitorSync<T>(
    operationName: string,
    fn: () => T,
    metadata?: Record<string, any>
  ): T {
    const operationId = this.startOperation(operationName, metadata);
    
    try {
      const result = fn();
      this.endOperation(operationId, true);
      return result;
    } catch (error) {
      this.endOperation(operationId, false, error.message);
      throw error;
    }
  }

  /**
   * Get performance statistics for an operation
   */
  getOperationStats(operationName: string): any {
    const operations = this.performanceHistory.filter(op => op.operationName === operationName);
    
    if (operations.length === 0) {
      return null;
    }
    
    const durations = operations.map(op => op.duration!).filter(d => d !== undefined);
    const successfulOps = operations.filter(op => op.success);
    const failedOps = operations.filter(op => !op.success);
    
    const sortedDurations = [...durations].sort((a, b) => a - b);
    
    return {
      operationName,
      totalOperations: operations.length,
      successfulOperations: successfulOps.length,
      failedOperations: failedOps.length,
      successRate: (successfulOps.length / operations.length) * 100,
      duration: {
        min: Math.min(...durations),
        max: Math.max(...durations),
        avg: durations.reduce((sum, d) => sum + d, 0) / durations.length,
        median: this.percentile(sortedDurations, 0.5),
        p90: this.percentile(sortedDurations, 0.9),
        p95: this.percentile(sortedDurations, 0.95),
        p99: this.percentile(sortedDurations, 0.99),
      },
      recentOperations: operations.slice(-10),
      threshold: this.thresholds.get(operationName),
    };
  }

  /**
   * Get overall performance summary
   */
  getPerformanceSummary(): any {
    const uniqueOperations = [...new Set(this.performanceHistory.map(op => op.operationName))];
    const operationStats = uniqueOperations.map(op => this.getOperationStats(op));
    
    const recentAlerts = this.alerts.slice(-10);
    const criticalAlerts = this.alerts.filter(alert => alert.severity === 'critical').length;
    const warningAlerts = this.alerts.filter(alert => alert.severity === 'warning').length;
    
    return {
      timestamp: new Date().toISOString(),
      activeOperations: this.activeOperations.size,
      totalOperationsTracked: this.performanceHistory.length,
      uniqueOperationTypes: uniqueOperations.length,
      alerts: {
        total: this.alerts.length,
        critical: criticalAlerts,
        warnings: warningAlerts,
        recent: recentAlerts,
      },
      operationStats,
      systemHealth: this.assessSystemHealth(),
    };
  }

  /**
   * Get slow operations report
   */
  getSlowOperationsReport(limit = 20): any[] {
    return this.performanceHistory
      .filter(op => op.duration !== undefined)
      .sort((a, b) => b.duration! - a.duration!)
      .slice(0, limit)
      .map(op => ({
        operationName: op.operationName,
        duration: op.duration,
        timestamp: new Date(op.startTime).toISOString(),
        success: op.success,
        error: op.error,
        metadata: op.metadata,
        threshold: this.thresholds.get(op.operationName),
      }));
  }

  /**
   * Get failed operations report
   */
  getFailedOperationsReport(limit = 20): any[] {
    return this.performanceHistory
      .filter(op => !op.success)
      .slice(-limit)
      .map(op => ({
        operationName: op.operationName,
        duration: op.duration,
        timestamp: new Date(op.startTime).toISOString(),
        error: op.error,
        metadata: op.metadata,
      }));
  }

  /**
   * Check if operation exceeds performance thresholds
   */
  private checkPerformanceThreshold(operation: PerformanceData): void {
    const threshold = this.thresholds.get(operation.operationName);
    
    if (!threshold || operation.duration === undefined) {
      return;
    }
    
    const alertData = {
      timestamp: new Date(),
      operationName: operation.operationName,
      duration: operation.duration,
      threshold,
    };
    
    if (operation.duration >= threshold.critical) {
      const message = `CRITICAL: Operation '${operation.operationName}' took ${operation.duration}ms (threshold: ${threshold.critical}ms)`;
      this.alerts.push({
        timestamp: new Date(),
        message,
        severity: 'critical',
      });
      
      console.error('Performance Alert:', message, alertData);
      
      // Record critical performance alert metric
      this.metricsService.incrementCounter('performance_critical_alerts_total', 1, {
        operation: operation.operationName,
      });
    } else if (operation.duration >= threshold.warning) {
      const message = `WARNING: Operation '${operation.operationName}' took ${operation.duration}ms (threshold: ${threshold.warning}ms)`;
      this.alerts.push({
        timestamp: new Date(),
        message,
        severity: 'warning',
      });
      
      console.warn('Performance Warning:', message, alertData);
      
      // Record warning performance alert metric
      this.metricsService.incrementCounter('performance_warning_alerts_total', 1, {
        operation: operation.operationName,
      });
    }
    
    // Limit alerts history
    if (this.alerts.length > 500) {
      this.alerts = this.alerts.slice(-500);
    }
  }

  /**
   * Assess overall system health based on performance metrics
   */
  private assessSystemHealth(): { status: string; score: number; issues: string[] } {
    const issues: string[] = [];
    let healthScore = 100;
    
    // Check for critical alerts in the last 5 minutes
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    const recentCriticalAlerts = this.alerts.filter(
      alert => alert.severity === 'critical' && alert.timestamp > fiveMinutesAgo
    );
    
    if (recentCriticalAlerts.length > 0) {
      healthScore -= recentCriticalAlerts.length * 20;
      issues.push(`${recentCriticalAlerts.length} critical performance alerts in last 5 minutes`);
    }
    
    // Check for high failure rates
    const recentOperations = this.performanceHistory.slice(-100);
    const failureRate = recentOperations.filter(op => !op.success).length / recentOperations.length;
    
    if (failureRate > 0.1) { // 10% failure rate
      healthScore -= 30;
      issues.push(`High failure rate: ${(failureRate * 100).toFixed(1)}%`);
    }
    
    // Check for slow operations
    const slowOperations = recentOperations.filter(op => {
      const threshold = this.thresholds.get(op.operationName);
      return threshold && op.duration && op.duration > threshold.warning;
    });
    
    if (slowOperations.length > recentOperations.length * 0.2) { // 20% of operations are slow
      healthScore -= 20;
      issues.push(`${slowOperations.length} slow operations in recent history`);
    }
    
    // Check for stuck operations
    const stuckOperations = Array.from(this.activeOperations.values()).filter(
      op => Date.now() - op.startTime > 30000 // 30 seconds
    );
    
    if (stuckOperations.length > 0) {
      healthScore -= stuckOperations.length * 10;
      issues.push(`${stuckOperations.length} operations appear to be stuck`);
    }
    
    healthScore = Math.max(0, healthScore);
    
    let status = 'healthy';
    if (healthScore < 50) {
      status = 'critical';
    } else if (healthScore < 80) {
      status = 'degraded';
    }
    
    return { status, score: healthScore, issues };
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
   * Start periodic performance monitoring
   */
  private startPerformanceMonitoring(): void {
    const monitoringInterval = this.configService.get<number>('monitoring.performanceInterval', 30000); // Default 30 seconds
    
    this.monitoringInterval = setInterval(() => {
      this.performPeriodicCheck();
    }, monitoringInterval);
  }

  /**
   * Perform periodic system health checks
   */
  private performPeriodicCheck(): void {
    // Check for stuck operations
    const now = Date.now();
    const stuckThreshold = 60000; // 1 minute
    
    for (const [operationId, operation] of this.activeOperations) {
      if (now - operation.startTime > stuckThreshold) {
        console.warn('Performance Monitor: Stuck operation detected', {
          operationId,
          operationName: operation.operationName,
          duration: now - operation.startTime,
          metadata: operation.metadata,
        });
        
        // Record stuck operation metric
        this.metricsService.incrementCounter('performance_stuck_operations_total', 1, {
          operation: operation.operationName,
        });
      }
    }
    
    // Log performance summary
    const summary = this.getPerformanceSummary();
    if (summary.systemHealth.status !== 'healthy') {
      console.warn('Performance Monitor: System health degraded', summary.systemHealth);
    }
  }

  /**
   * Clear performance history (useful for testing)
   */
  clearHistory(): void {
    this.performanceHistory.length = 0;
    this.alerts.length = 0;
    this.activeOperations.clear();
  }
}