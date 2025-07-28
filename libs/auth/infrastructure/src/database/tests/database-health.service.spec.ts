import { Test, TestingModule } from '@nestjs/testing';
import { getDataSourceToken } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { DatabaseHealthService } from '../health/database-health.service';

describe('DatabaseHealthService', () => {
  let service: DatabaseHealthService;
  let mockDataSource: jest.Mocked<DataSource>;

  beforeEach(async () => {
    mockDataSource = {
      isInitialized: true,
      initialize: jest.fn(),
      query: jest.fn(),
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DatabaseHealthService,
        {
          provide: getDataSourceToken(),
          useValue: mockDataSource,
        },
      ],
    }).compile();

    service = module.get<DatabaseHealthService>(DatabaseHealthService);
  });

  describe('checkHealth', () => {
    it('should return healthy status when database is working', async () => {
      mockDataSource.query
        .mockResolvedValueOnce([{ health_check: 1 }]) // Health check query
        .mockResolvedValueOnce([{ version: 'PostgreSQL 15.0' }]) // Version query
        .mockResolvedValueOnce([{ uptime: 3600 }]) // Uptime query
        .mockResolvedValueOnce([{ 
          total_connections: 5, 
          active_connections: 2, 
          idle_connections: 3 
        }]); // Connection stats query

      const result = await service.checkHealth();

      expect(result.status).toBe('healthy');
      expect(result.details.can_connect).toBe(true);
      expect(result.details.can_query).toBe(true);
      expect(result.details.version).toBe('PostgreSQL 15.0');
      expect(result.details.uptime).toBe(3600);
      expect(result.details.total_connections).toBe(5);
      expect(result.details.active_connections).toBe(2);
      expect(result.details.idle_connections).toBe(3);
    });

    it('should return unhealthy status when database connection fails', async () => {
      mockDataSource.isInitialized = false;
      mockDataSource.initialize.mockRejectedValue(new Error('Connection failed'));

      const result = await service.checkHealth();

      expect(result.status).toBe('unhealthy');
      expect(result.details.can_connect).toBe(false);
      expect(result.details.can_query).toBe(false);
      expect(result.details.error).toBe('Cannot establish database connection');
    });

    it('should return unhealthy status when queries fail', async () => {
      mockDataSource.query.mockRejectedValue(new Error('Query failed'));

      const result = await service.checkHealth();

      expect(result.status).toBe('unhealthy');
      expect(result.details.can_connect).toBe(true);
      expect(result.details.can_query).toBe(false);
      expect(result.details.error).toBe('Cannot execute database queries');
    });

    it('should return degraded status for slow response times', async () => {
      // Mock slow response
      mockDataSource.query
        .mockImplementation(() => new Promise(resolve => 
          setTimeout(() => resolve([{ health_check: 1 }]), 1500)
        ))
        .mockResolvedValueOnce([{ version: 'PostgreSQL 15.0' }])
        .mockResolvedValueOnce([{ uptime: 3600 }])
        .mockResolvedValueOnce([{ 
          total_connections: 5, 
          active_connections: 2, 
          idle_connections: 3 
        }]);

      const result = await service.checkHealth();

      expect(result.status).toBe('degraded');
      expect(result.response_time).toBeGreaterThan(1000);
    });

    it('should handle missing metrics gracefully', async () => {
      mockDataSource.query
        .mockResolvedValueOnce([{ health_check: 1 }]) // Health check query
        .mockRejectedValueOnce(new Error('Version query failed')) // Version query fails
        .mockRejectedValueOnce(new Error('Uptime query failed')) // Uptime query fails
        .mockRejectedValueOnce(new Error('Stats query failed')); // Connection stats query fails

      const result = await service.checkHealth();

      expect(result.status).toBe('healthy');
      expect(result.details.can_connect).toBe(true);
      expect(result.details.can_query).toBe(true);
      expect(result.details.version).toBeNull();
      expect(result.details.uptime).toBeNull();
      expect(result.details.total_connections).toBeNull();
    });
  });

  describe('getConnectionPoolStatus', () => {
    it('should return connection pool statistics', async () => {
      process.env['DB_POOL_MAX'] = '20';
      
      mockDataSource.query.mockResolvedValue([{
        current_connections: 8,
        idle_connections: 3,
      }]);

      const result = await service.getConnectionPoolStatus();

      expect(result.max_connections).toBe(20);
      expect(result.current_connections).toBe(8);
      expect(result.idle_connections).toBe(3);
      expect(result.usage_percentage).toBe(40); // 8/20 * 100
    });

    it('should handle query failures', async () => {
      mockDataSource.query.mockRejectedValue(new Error('Query failed'));

      await expect(service.getConnectionPoolStatus()).rejects.toThrow('Unable to retrieve connection pool status');
    });

    it('should use default max connections when env var not set', async () => {
      delete process.env['DB_POOL_MAX'];
      
      mockDataSource.query.mockResolvedValue([{
        current_connections: 5,
        idle_connections: 2,
      }]);

      const result = await service.getConnectionPoolStatus();

      expect(result.max_connections).toBe(20); // Default value
      expect(result.usage_percentage).toBe(25); // 5/20 * 100
    });
  });

  describe('getPerformanceMetrics', () => {
    it('should return performance metrics when available', async () => {
      mockDataSource.query
        .mockResolvedValueOnce([{
          avg_query_time: 150.5,
          total_queries: 1000,
          slow_queries_count: 5,
        }])
        .mockResolvedValueOnce([{
          cache_hit_ratio: 95.5,
        }]);

      const result = await service.getPerformanceMetrics();

      expect(result.avg_query_time).toBe(150.5);
      expect(result.total_queries).toBe(1000);
      expect(result.slow_queries_count).toBe(5);
      expect(result.cache_hit_ratio).toBe(95.5);
    });

    it('should handle missing performance data', async () => {
      mockDataSource.query
        .mockResolvedValueOnce([{}]) // Empty query stats
        .mockResolvedValueOnce([{}]); // Empty cache stats

      const result = await service.getPerformanceMetrics();

      expect(result.avg_query_time).toBeNull();
      expect(result.total_queries).toBeNull();
      expect(result.slow_queries_count).toBeNull();
      expect(result.cache_hit_ratio).toBeNull();
    });

    it('should handle query failures gracefully', async () => {
      mockDataSource.query.mockRejectedValue(new Error('pg_stat_statements not available'));

      const result = await service.getPerformanceMetrics();

      expect(result.avg_query_time).toBeNull();
      expect(result.total_queries).toBeNull();
      expect(result.slow_queries_count).toBeNull();
      expect(result.cache_hit_ratio).toBeNull();
    });
  });

  describe('logHealthStatus', () => {
    it('should log healthy status', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      mockDataSource.query
        .mockResolvedValueOnce([{ health_check: 1 }])
        .mockResolvedValueOnce([{ version: 'PostgreSQL 15.0 on x86_64' }])
        .mockResolvedValueOnce([{ uptime: 7200 }])
        .mockResolvedValueOnce([{ 
          total_connections: 10, 
          active_connections: 3, 
          idle_connections: 7 
        }])
        .mockResolvedValueOnce([{
          current_connections: 3,
          idle_connections: 7,
        }]);

      await service.logHealthStatus();

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Database Health Check:')
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Status: HEALTHY')
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('PostgreSQL')
      );

      consoleSpy.mockRestore();
    });

    it('should log unhealthy status with error', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      mockDataSource.isInitialized = false;
      mockDataSource.initialize.mockRejectedValue(new Error('Connection failed'));

      await service.logHealthStatus();

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Database unhealthy:')
      );

      consoleErrorSpy.mockRestore();
    });

    it('should log degraded status with warning', async () => {
      const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Mock slow response to trigger degraded status
      mockDataSource.query
        .mockImplementation(() => new Promise(resolve => 
          setTimeout(() => resolve([{ health_check: 1 }]), 1500)
        ))
        .mockResolvedValueOnce([{ version: 'PostgreSQL 15.0' }])
        .mockResolvedValueOnce([{ uptime: 3600 }])
        .mockResolvedValueOnce([{ 
          total_connections: 5, 
          active_connections: 2, 
          idle_connections: 3 
        }])
        .mockResolvedValueOnce([{
          current_connections: 2,
          idle_connections: 3,
        }]);

      await service.logHealthStatus();

      expect(consoleWarnSpy).toHaveBeenCalledWith('Database performance degraded');

      consoleWarnSpy.mockRestore();
    });

    it('should handle logging errors gracefully', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      mockDataSource.query.mockRejectedValue(new Error('Unexpected error'));

      await service.logHealthStatus();

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Failed to log health status:',
        expect.any(Error)
      );

      consoleErrorSpy.mockRestore();
    });
  });
});