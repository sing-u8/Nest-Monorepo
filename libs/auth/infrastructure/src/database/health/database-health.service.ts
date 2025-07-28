import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

export interface DatabaseHealthResult {
  status: 'healthy' | 'unhealthy' | 'degraded';
  response_time: number;
  connection_count: number;
  details: {
    can_connect: boolean;
    can_query: boolean;
    version: string | null;
    uptime: number | null;
    total_connections: number | null;
    active_connections: number | null;
    idle_connections: number | null;
    error?: string;
  };
}

/**
 * Database Health Service
 * 
 * Provides comprehensive database health monitoring including:
 * - Connection status validation
 * - Query response time measurement
 * - Connection pool monitoring
 * - Database version and uptime tracking
 */
@Injectable()
export class DatabaseHealthService {
  private readonly logger = new Logger(DatabaseHealthService.name);
  private readonly healthThresholds = {
    response_time_warning: 1000, // 1 second
    response_time_critical: 3000, // 3 seconds
    connection_usage_warning: 0.8, // 80% of max connections
    connection_usage_critical: 0.95, // 95% of max connections
  };

  constructor(
    @InjectDataSource()
    private readonly dataSource: DataSource,
  ) {}

  /**
   * Performs comprehensive database health check
   */
  async checkHealth(): Promise<DatabaseHealthResult> {
    const startTime = Date.now();
    
    try {
      // Test basic connectivity
      const canConnect = await this.testConnection();
      if (!canConnect) {
        return this.createUnhealthyResult(startTime, 'Cannot establish database connection');
      }

      // Test query execution
      const canQuery = await this.testQuery();
      if (!canQuery) {
        return this.createUnhealthyResult(startTime, 'Cannot execute database queries');
      }

      // Get database metrics
      const metrics = await this.getDatabaseMetrics();
      const responseTime = Date.now() - startTime;
      
      // Determine health status based on metrics
      const status = this.calculateHealthStatus(responseTime, metrics);

      return {
        status,
        response_time: responseTime,
        connection_count: metrics.active_connections || 0,
        details: {
          can_connect: true,
          can_query: true,
          version: metrics.version,
          uptime: metrics.uptime,
          total_connections: metrics.total_connections,
          active_connections: metrics.active_connections,
          idle_connections: metrics.idle_connections,
        },
      };

    } catch (error) {
      this.logger.error('Database health check failed:', error);
      return this.createUnhealthyResult(startTime, error.message);
    }
  }

  /**
   * Tests basic database connection
   */
  private async testConnection(): Promise<boolean> {
    try {
      if (!this.dataSource.isInitialized) {
        await this.dataSource.initialize();
      }
      return this.dataSource.isInitialized;
    } catch (error) {
      this.logger.error('Database connection test failed:', error);
      return false;
    }
  }

  /**
   * Tests database query execution
   */
  private async testQuery(): Promise<boolean> {
    try {
      await this.dataSource.query('SELECT 1 as health_check');
      return true;
    } catch (error) {
      this.logger.error('Database query test failed:', error);
      return false;
    }
  }

  /**
   * Retrieves database performance and connection metrics
   */
  private async getDatabaseMetrics(): Promise<{
    version: string | null;
    uptime: number | null;
    total_connections: number | null;
    active_connections: number | null;
    idle_connections: number | null;
  }> {
    try {
      // Get PostgreSQL version
      const versionResult = await this.dataSource.query('SELECT version()');
      const version = versionResult[0]?.version || null;

      // Get database uptime (PostgreSQL specific)
      const uptimeResult = await this.dataSource.query(`
        SELECT EXTRACT(EPOCH FROM (now() - pg_postmaster_start_time())) as uptime
      `);
      const uptime = uptimeResult[0]?.uptime || null;

      // Get connection statistics
      const connectionStats = await this.dataSource.query(`
        SELECT 
          count(*) as total_connections,
          count(*) FILTER (WHERE state = 'active') as active_connections,
          count(*) FILTER (WHERE state = 'idle') as idle_connections
        FROM pg_stat_activity 
        WHERE datname = current_database()
      `);

      const stats = connectionStats[0] || {};

      return {
        version,
        uptime: uptime ? Math.floor(uptime) : null,
        total_connections: parseInt(stats.total_connections) || null,
        active_connections: parseInt(stats.active_connections) || null,
        idle_connections: parseInt(stats.idle_connections) || null,
      };

    } catch (error) {
      this.logger.warn('Could not retrieve database metrics:', error);
      return {
        version: null,
        uptime: null,
        total_connections: null,
        active_connections: null,
        idle_connections: null,
      };
    }
  }

  /**
   * Calculates overall health status based on metrics
   */
  private calculateHealthStatus(
    responseTime: number,
    metrics: {
      total_connections: number | null;
      active_connections: number | null;
    }
  ): 'healthy' | 'unhealthy' | 'degraded' {
    // Check response time
    if (responseTime > this.healthThresholds.response_time_critical) {
      return 'unhealthy';
    }

    // Check connection pool usage if available
    if (metrics.total_connections && metrics.active_connections) {
      const maxConnections = parseInt(process.env['DB_POOL_MAX'] || '20');
      const connectionUsage = metrics.active_connections / maxConnections;
      
      if (connectionUsage > this.healthThresholds.connection_usage_critical) {
        return 'unhealthy';
      }
    }

    // Check for degraded performance
    if (responseTime > this.healthThresholds.response_time_warning) {
      return 'degraded';
    }

    if (metrics.total_connections && metrics.active_connections) {
      const maxConnections = parseInt(process.env['DB_POOL_MAX'] || '20');
      const connectionUsage = metrics.active_connections / maxConnections;
      
      if (connectionUsage > this.healthThresholds.connection_usage_warning) {
        return 'degraded';
      }
    }

    return 'healthy';
  }

  /**
   * Creates unhealthy result object
   */
  private createUnhealthyResult(startTime: number, error: string): DatabaseHealthResult {
    return {
      status: 'unhealthy',
      response_time: Date.now() - startTime,
      connection_count: 0,
      details: {
        can_connect: false,
        can_query: false,
        version: null,
        uptime: null,
        total_connections: null,
        active_connections: null,
        idle_connections: null,
        error,
      },
    };
  }

  /**
   * Gets current connection pool status
   */
  async getConnectionPoolStatus(): Promise<{
    max_connections: number;
    current_connections: number;
    idle_connections: number;
    usage_percentage: number;
  }> {
    try {
      const stats = await this.dataSource.query(`
        SELECT 
          count(*) as current_connections,
          count(*) FILTER (WHERE state = 'idle') as idle_connections
        FROM pg_stat_activity 
        WHERE datname = current_database()
      `);

      const maxConnections = parseInt(process.env['DB_POOL_MAX'] || '20');
      const currentConnections = parseInt(stats[0]?.current_connections) || 0;
      const idleConnections = parseInt(stats[0]?.idle_connections) || 0;
      const usagePercentage = (currentConnections / maxConnections) * 100;

      return {
        max_connections: maxConnections,
        current_connections: currentConnections,
        idle_connections: idleConnections,
        usage_percentage: Math.round(usagePercentage * 100) / 100,
      };

    } catch (error) {
      this.logger.error('Failed to get connection pool status:', error);
      throw new Error('Unable to retrieve connection pool status');
    }
  }

  /**
   * Monitors database performance metrics
   */
  async getPerformanceMetrics(): Promise<{
    avg_query_time: number | null;
    slow_queries_count: number | null;
    total_queries: number | null;
    cache_hit_ratio: number | null;
  }> {
    try {
      // Get query performance statistics
      const queryStats = await this.dataSource.query(`
        SELECT 
          round(avg(mean_exec_time)::numeric, 2) as avg_query_time,
          sum(calls) as total_queries,
          sum(calls) FILTER (WHERE mean_exec_time > 1000) as slow_queries_count
        FROM pg_stat_statements 
        WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
      `);

      // Get cache hit ratio
      const cacheStats = await this.dataSource.query(`
        SELECT 
          round(
            (sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read) + 1)::numeric) * 100, 
            2
          ) as cache_hit_ratio
        FROM pg_statio_user_tables
      `);

      const stats = queryStats[0] || {};
      const cache = cacheStats[0] || {};

      return {
        avg_query_time: parseFloat(stats.avg_query_time) || null,
        slow_queries_count: parseInt(stats.slow_queries_count) || null,
        total_queries: parseInt(stats.total_queries) || null,
        cache_hit_ratio: parseFloat(cache.cache_hit_ratio) || null,
      };

    } catch (error) {
      this.logger.warn('Could not retrieve performance metrics:', error);
      return {
        avg_query_time: null,
        slow_queries_count: null,
        total_queries: null,
        cache_hit_ratio: null,
      };
    }
  }

  /**
   * Logs database health status
   */
  async logHealthStatus(): Promise<void> {
    try {
      const health = await this.checkHealth();
      const poolStatus = await this.getConnectionPoolStatus();
      
      this.logger.log(`Database Health Check:
        Status: ${health.status.toUpperCase()}
        Response Time: ${health.response_time}ms
        Connections: ${poolStatus.current_connections}/${poolStatus.max_connections} (${poolStatus.usage_percentage}%)
        Version: ${health.details.version?.split(' ')[0] || 'Unknown'}
        Uptime: ${health.details.uptime ? Math.floor(health.details.uptime / 3600) + 'h' : 'Unknown'}
      `);

      if (health.status === 'unhealthy') {
        this.logger.error(`Database unhealthy: ${health.details.error}`);
      } else if (health.status === 'degraded') {
        this.logger.warn('Database performance degraded');
      }

    } catch (error) {
      this.logger.error('Failed to log health status:', error);
    }
  }
}