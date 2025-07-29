import { Inject } from '@nestjs/common';
import { MetricsService } from '../services/metrics.service';

/**
 * Decorator to measure method execution time
 */
export function MeasureTime(metricName?: string) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor,
  ) {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function (...args: any[]) {
      const metricsService: MetricsService = this.metricsService || this._metricsService;
      
      if (!metricsService) {
        console.warn('MetricsService not found in instance. Skipping metrics collection.');
        return originalMethod.apply(this, args);
      }
      
      const metric = metricName || `${target.constructor.name}.${propertyKey}`;
      const timer = metricsService.startTimer(metric);
      
      try {
        const result = await originalMethod.apply(this, args);
        timer();
        return result;
      } catch (error) {
        timer();
        throw error;
      }
    };
    
    return descriptor;
  };
}

/**
 * Decorator to track database operations
 */
export function TrackDatabaseOperation(operation: string, table: string) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor,
  ) {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function (...args: any[]) {
      const metricsService: MetricsService = this.metricsService || this._metricsService;
      
      if (!metricsService) {
        return originalMethod.apply(this, args);
      }
      
      const startTime = Date.now();
      
      try {
        const result = await originalMethod.apply(this, args);
        const duration = Date.now() - startTime;
        
        metricsService.recordDatabasePerformance(operation, table, duration, {
          method: propertyKey,
          rowCount: Array.isArray(result) ? result.length : 1,
        });
        
        return result;
      } catch (error) {
        const duration = Date.now() - startTime;
        
        metricsService.recordDatabasePerformance(operation, table, duration, {
          method: propertyKey,
          error: error.message,
        });
        
        throw error;
      }
    };
    
    return descriptor;
  };
}

/**
 * Decorator to track external service calls
 */
export function TrackExternalService(service: string, operation: string) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor,
  ) {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function (...args: any[]) {
      const metricsService: MetricsService = this.metricsService || this._metricsService;
      
      if (!metricsService) {
        return originalMethod.apply(this, args);
      }
      
      const startTime = Date.now();
      
      try {
        const result = await originalMethod.apply(this, args);
        const duration = Date.now() - startTime;
        
        metricsService.recordExternalServicePerformance(
          service,
          operation,
          duration,
          true,
          { method: propertyKey },
        );
        
        return result;
      } catch (error) {
        const duration = Date.now() - startTime;
        
        metricsService.recordExternalServicePerformance(
          service,
          operation,
          duration,
          false,
          {
            method: propertyKey,
            error: error.message,
          },
        );
        
        throw error;
      }
    };
    
    return descriptor;
  };
}

/**
 * Property decorator to inject MetricsService
 */
export function InjectMetrics() {
  return Inject(MetricsService);
}