import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppService } from './app.service';

/**
 * Application Root Controller
 * 
 * Provides basic application information and status endpoints.
 * Serves as the entry point for the API.
 */
@ApiTags('Application')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  /**
   * Root endpoint - API information
   * Provides basic information about the API service
   */
  @Get()
  @ApiOperation({ 
    summary: 'API Information',
    description: 'Get basic information about the authentication API service'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'API information retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', example: 'Auth Service API' },
        version: { type: 'string', example: '1.0.0' },
        description: { type: 'string', example: 'NestJS Authentication Service' },
        documentation: { type: 'string', example: '/docs' },
        health: { type: 'string', example: '/health' },
        environment: { type: 'string', example: 'development' },
        timestamp: { type: 'string', example: '2023-12-01T10:00:00Z' },
      }
    }
  })
  getApiInfo() {
    return this.appService.getApiInfo();
  }

  /**
   * API status endpoint
   * Quick status check for the API service
   */
  @Get('status')
  @ApiOperation({ 
    summary: 'API Status',
    description: 'Get current status of the API service'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'API status retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'online' },
        uptime: { type: 'number', example: 12345 },
        timestamp: { type: 'string', example: '2023-12-01T10:00:00Z' },
        version: { type: 'string', example: '1.0.0' },
        environment: { type: 'string', example: 'development' },
      }
    }
  })
  getStatus() {
    return this.appService.getStatus();
  }
}
