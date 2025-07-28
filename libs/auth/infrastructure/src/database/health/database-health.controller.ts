import { Controller, Get } from '@nestjs/common';
import { DatabaseHealthService, DatabaseHealthResult } from './database-health.service';

/**
 * Database Health Controller
 * 
 * Provides HTTP endpoints for database health monitoring
 */
@Controller('health/database')
export class DatabaseHealthController {
  constructor(
    private readonly databaseHealthService: DatabaseHealthService,
  ) {}

  /**
   * GET /health/database
   * 
   * Returns comprehensive database health information
   */
  @Get()
  async getHealth(): Promise<DatabaseHealthResult> {
    return this.databaseHealthService.checkHealth();
  }

  /**
   * GET /health/database/pool
   * 
   * Returns connection pool status
   */
  @Get('pool')
  async getConnectionPoolStatus(): Promise<{
    max_connections: number;
    current_connections: number;
    idle_connections: number;
    usage_percentage: number;
  }> {
    return this.databaseHealthService.getConnectionPoolStatus();
  }

  /**
   * GET /health/database/performance
   * 
   * Returns database performance metrics
   */
  @Get('performance')
  async getPerformanceMetrics(): Promise<{
    avg_query_time: number | null;
    slow_queries_count: number | null;
    total_queries: number | null;
    cache_hit_ratio: number | null;
  }> {
    return this.databaseHealthService.getPerformanceMetrics();
  }
}