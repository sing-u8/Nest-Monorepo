import { Injectable } from '@nestjs/common';
import { HealthIndicator, HealthIndicatorResult, HealthCheckError } from '@nestjs/terminus';
import { DataSource } from 'typeorm';
import { InjectDataSource } from '@nestjs/typeorm';

/**
 * Database health check indicator
 * 
 * Provides health check functionality for the database connection
 * including connection status, query execution time, and pool status.
 */
@Injectable()
export class DatabaseHealthIndicator extends HealthIndicator {
  constructor(
    @InjectDataSource() private readonly dataSource: DataSource,
  ) {
    super();
  }

  /**
   * Check database health status
   * 
   * @param key - Health check identifier
   * @param timeout - Maximum time to wait for connection (default: 3000ms)
   * @returns Health check result with connection and performance metrics
   */
  async isHealthy(key: string, timeout = 3000): Promise<HealthIndicatorResult> {
    const startTime = Date.now();
    
    try {
      // Check if data source is initialized
      if (!this.dataSource.isInitialized) {
        throw new Error('DataSource is not initialized');
      }

      // Execute a simple query to test database connection
      const queryPromise = this.dataSource.query('SELECT 1 as health_check');
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Database query timeout')), timeout);
      });

      await Promise.race([queryPromise, timeoutPromise]);

      const responseTime = Date.now() - startTime;
      
      // Get connection pool information
      const poolInfo = this.getConnectionPoolInfo();
      
      const result = this.getStatus(key, true, {
        status: 'up',
        responseTime: `${responseTime}ms`,
        connection: {
          isInitialized: this.dataSource.isInitialized,
          hasMetadata: this.dataSource.hasMetadata,
          database: this.dataSource.options.database,
          host: this.dataSource.options.host,
          port: this.dataSource.options.port,
        },
        pool: poolInfo,
        timestamp: new Date().toISOString(),
      });

      return result;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      const result = this.getStatus(key, false, {
        status: 'down',
        error: error.message,
        responseTime: `${responseTime}ms`,
        connection: {
          isInitialized: this.dataSource?.isInitialized || false,
          hasMetadata: this.dataSource?.hasMetadata || false,
        },
        timestamp: new Date().toISOString(),
      });

      throw new HealthCheckError('Database health check failed', result);
    }
  }

  /**
   * Get connection pool information
   * 
   * @returns Connection pool statistics
   */
  private getConnectionPoolInfo(): any {
    try {
      // TypeORM doesn't expose pool statistics directly
      // This is a simplified version that could be extended
      const driver = this.dataSource.driver;
      
      return {
        type: driver.options.type,
        maxConnections: driver.options.extra?.max || 'not configured',
        minConnections: driver.options.extra?.min || 'not configured',
        acquireTimeout: driver.options.extra?.acquire || 'not configured',
        idleTimeout: driver.options.extra?.idle || 'not configured',
      };
    } catch (error) {
      return {
        error: 'Could not retrieve pool information',
        details: error.message,
      };
    }
  }

  /**
   * Perform a quick connection test
   * 
   * @returns Simple health status
   */
  async quickCheck(): Promise<boolean> {
    try {
      if (!this.dataSource.isInitialized) {
        return false;
      }

      await this.dataSource.query('SELECT 1');
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get detailed database information
   * 
   * @returns Database metadata and configuration
   */
  async getDatabaseInfo(): Promise<any> {
    try {
      const [versionResult] = await this.dataSource.query('SELECT version()');
      const [currentDbResult] = await this.dataSource.query('SELECT current_database()');
      
      return {
        version: versionResult.version,
        currentDatabase: currentDbResult.current_database,
        driver: this.dataSource.driver.options.type,
        entities: this.dataSource.entityMetadatas.map(meta => meta.name),
        migrations: {
          table: this.dataSource.options.migrationsTableName,
          hasRun: this.dataSource.options.migrationsRun,
        },
      };
    } catch (error) {
      return {
        error: 'Could not retrieve database information',
        details: error.message,
      };
    }
  }
}