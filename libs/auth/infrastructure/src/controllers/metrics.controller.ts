import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiQuery, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { MetricsService, MetricsSummary } from '../services/metrics.service';

/**
 * Metrics Controller
 * 
 * Provides endpoints for retrieving application metrics and monitoring data.
 * All endpoints require authentication for security.
 */
@ApiTags('Metrics')
@Controller('metrics')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class MetricsController {
  constructor(private metricsService: MetricsService) {}
  
  /**
   * Get all metrics summaries
   */
  @Get()
  @ApiOperation({ 
    summary: 'Get all metrics summaries',
    description: 'Retrieve summaries of all collected metrics with statistics'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Metrics summaries retrieved successfully',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          metric: { type: 'string', example: 'auth.login.success' },
          count: { type: 'number', example: 1234 },
          sum: { type: 'number', example: 5678 },
          min: { type: 'number', example: 10 },
          max: { type: 'number', example: 1000 },
          average: { type: 'number', example: 250 },
          p50: { type: 'number', example: 200 },
          p95: { type: 'number', example: 800 },
          p99: { type: 'number', example: 950 },
          tags: { type: 'object', example: { provider: 'google' } }
        }
      }
    }
  })
  getAllMetrics(): MetricsSummary[] {
    return this.metricsService.getAllMetricsSummaries();
  }
  
  /**
   * Get specific metric summary
   */
  @Get('summary')
  @ApiOperation({ 
    summary: 'Get specific metric summary',
    description: 'Retrieve summary for a specific metric with optional tag filtering'
  })
  @ApiQuery({ 
    name: 'metric', 
    required: true, 
    description: 'Metric name',
    example: 'auth.login.success'
  })
  @ApiQuery({ 
    name: 'tags', 
    required: false, 
    description: 'JSON string of tags for filtering',
    example: '{"provider":"google"}'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Metric summary retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        metric: { type: 'string', example: 'auth.login.success' },
        count: { type: 'number', example: 1234 },
        sum: { type: 'number', example: 5678 },
        min: { type: 'number', example: 10 },
        max: { type: 'number', example: 1000 },
        average: { type: 'number', example: 250 },
        p50: { type: 'number', example: 200 },
        p95: { type: 'number', example: 800 },
        p99: { type: 'number', example: 950 },
        tags: { type: 'object', example: { provider: 'google' } }
      }
    }
  })
  @ApiResponse({ 
    status: 404, 
    description: 'Metric not found'
  })
  getMetricSummary(
    @Query('metric') metric: string,
    @Query('tags') tagsJson?: string,
  ): MetricsSummary | { message: string } {
    let tags: Record<string, string> | undefined;
    
    if (tagsJson) {
      try {
        tags = JSON.parse(tagsJson);
      } catch (error) {
        return { message: 'Invalid tags JSON format' };
      }
    }
    
    const summary = this.metricsService.getMetricsSummary(metric, tags);
    
    if (!summary) {
      return { message: 'Metric not found' };
    }
    
    return summary;
  }
  
  /**
   * Export metrics in different formats
   */
  @Get('export')
  @ApiOperation({ 
    summary: 'Export metrics',
    description: 'Export all metrics in JSON or Prometheus format'
  })
  @ApiQuery({ 
    name: 'format', 
    required: false, 
    enum: ['json', 'prometheus'],
    description: 'Export format',
    example: 'prometheus'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Metrics exported successfully',
    content: {
      'application/json': {
        schema: { type: 'string' }
      },
      'text/plain': {
        schema: { type: 'string' }
      }
    }
  })
  exportMetrics(
    @Query('format') format: 'json' | 'prometheus' = 'json',
  ): string {
    return this.metricsService.exportMetrics(format);
  }
  
  /**
   * Get authentication metrics
   */
  @Get('auth')
  @ApiOperation({ 
    summary: 'Get authentication metrics',
    description: 'Retrieve metrics related to authentication events'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Authentication metrics retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        login: {
          type: 'object',
          properties: {
            success: { type: 'object' },
            failure: { type: 'object' }
          }
        },
        register: {
          type: 'object',
          properties: {
            success: { type: 'object' },
            failure: { type: 'object' }
          }
        },
        oauth: {
          type: 'object',
          properties: {
            google: { type: 'object' },
            apple: { type: 'object' }
          }
        },
        tokens: {
          type: 'object',
          properties: {
            refresh: { type: 'object' },
            validation: { type: 'object' }
          }
        }
      }
    }
  })
  getAuthMetrics(): Record<string, any> {
    const metrics = this.metricsService.getAllMetricsSummaries();
    
    const authMetrics = {
      login: {
        success: metrics.find(m => m.metric === 'auth.login.success'),
        failure: metrics.find(m => m.metric === 'auth.login.failure'),
      },
      register: {
        success: metrics.find(m => m.metric === 'auth.register.success'),
        failure: metrics.find(m => m.metric === 'auth.register.failure'),
      },
      oauth: {
        google: {
          success: metrics.find(m => 
            m.metric === 'auth.oauth.login.success' && 
            m.tags?.provider === 'google'
          ),
          failure: metrics.find(m => 
            m.metric === 'auth.oauth.login.failure' && 
            m.tags?.provider === 'google'
          ),
        },
        apple: {
          success: metrics.find(m => 
            m.metric === 'auth.oauth.login.success' && 
            m.tags?.provider === 'apple'
          ),
          failure: metrics.find(m => 
            m.metric === 'auth.oauth.login.failure' && 
            m.tags?.provider === 'apple'
          ),
        },
      },
      tokens: {
        refresh: {
          success: metrics.find(m => m.metric === 'auth.token.refresh.success'),
          failure: metrics.find(m => m.metric === 'auth.token.refresh.failure'),
        },
        validation: {
          success: metrics.find(m => m.metric === 'auth.token.validation.success'),
          failure: metrics.find(m => m.metric === 'auth.token.validation.failure'),
        },
      },
      logout: metrics.find(m => m.metric === 'auth.logout'),
    };
    
    return authMetrics;
  }
  
  /**
   * Get performance metrics
   */
  @Get('performance')
  @ApiOperation({ 
    summary: 'Get performance metrics',
    description: 'Retrieve metrics related to API and database performance'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Performance metrics retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        api: {
          type: 'array',
          items: { type: 'object' }
        },
        database: {
          type: 'array',
          items: { type: 'object' }
        },
        external: {
          type: 'array',
          items: { type: 'object' }
        }
      }
    }
  })
  getPerformanceMetrics(): Record<string, any> {
    const metrics = this.metricsService.getAllMetricsSummaries();
    
    return {
      api: metrics.filter(m => m.metric === 'api.request.duration'),
      database: metrics.filter(m => m.metric === 'database.query.duration'),
      external: metrics.filter(m => m.metric === 'external.service.duration'),
    };
  }
  
  /**
   * Get security metrics
   */
  @Get('security')
  @ApiOperation({ 
    summary: 'Get security metrics',
    description: 'Retrieve metrics related to security events and threats'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Security metrics retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        rateLimits: { type: 'object' },
        suspiciousActivity: { type: 'object' },
        invalidTokens: { type: 'object' },
        bruteForce: { type: 'object' }
      }
    }
  })
  getSecurityMetrics(): Record<string, any> {
    const metrics = this.metricsService.getAllMetricsSummaries();
    
    return {
      rateLimits: metrics.find(m => m.metric === 'security.rate_limit.exceeded'),
      suspiciousActivity: metrics.find(m => m.metric === 'security.suspicious_activity'),
      invalidTokens: metrics.find(m => m.metric === 'security.invalid_token.attempt'),
      bruteForce: metrics.find(m => m.metric === 'security.brute_force.detected'),
    };
  }
  
  /**
   * Get system metrics
   */
  @Get('system')
  @ApiOperation({ 
    summary: 'Get system metrics',
    description: 'Retrieve metrics related to system resources and health'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'System metrics retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        memory: {
          type: 'object',
          properties: {
            heapUsed: { type: 'object' },
            heapTotal: { type: 'object' },
            rss: { type: 'object' },
            external: { type: 'object' }
          }
        },
        cpu: {
          type: 'object',
          properties: {
            user: { type: 'object' },
            system: { type: 'object' }
          }
        },
        connections: { type: 'object' },
        errorRate: { type: 'object' }
      }
    }
  })
  getSystemMetrics(): Record<string, any> {
    const metrics = this.metricsService.getAllMetricsSummaries();
    
    return {
      memory: {
        heapUsed: metrics.find(m => 
          m.metric === 'system.memory.usage' && 
          m.tags?.type === 'heap_used'
        ),
        heapTotal: metrics.find(m => 
          m.metric === 'system.memory.usage' && 
          m.tags?.type === 'heap_total'
        ),
        rss: metrics.find(m => 
          m.metric === 'system.memory.usage' && 
          m.tags?.type === 'rss'
        ),
        external: metrics.find(m => 
          m.metric === 'system.memory.usage' && 
          m.tags?.type === 'external'
        ),
      },
      cpu: {
        user: metrics.find(m => 
          m.metric === 'system.cpu.usage' && 
          m.tags?.type === 'user'
        ),
        system: metrics.find(m => 
          m.metric === 'system.cpu.usage' && 
          m.tags?.type === 'system'
        ),
      },
      connections: metrics.find(m => m.metric === 'system.connections.active'),
      errorRate: metrics.find(m => m.metric === 'system.error.rate'),
    };
  }
  
  /**
   * Get metrics health status
   */
  @Get('health')
  @ApiOperation({ 
    summary: 'Get metrics service health',
    description: 'Check if metrics collection is enabled and working'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Metrics service health status',
    schema: {
      type: 'object',
      properties: {
        enabled: { type: 'boolean', example: true },
        totalMetrics: { type: 'number', example: 15432 },
        metricsTypes: { type: 'number', example: 25 },
        maxMetricsPerType: { type: 'number', example: 10000 },
        retentionMs: { type: 'number', example: 3600000 }
      }
    }
  })
  getMetricsHealth(): Record<string, any> {
    return this.metricsService.getHealthStatus();
  }
}