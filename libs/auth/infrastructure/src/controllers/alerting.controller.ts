import { 
  Controller, 
  Get, 
  Post, 
  Put, 
  Delete, 
  Body, 
  Param, 
  UseGuards,
  HttpCode,
  HttpStatus 
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiParam, ApiBody } from '@nestjs/swagger';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { AlertingService, AlertRule, Alert } from '../services/alerting.service';

/**
 * Alerting Controller
 * 
 * Provides endpoints for managing alert rules and viewing alerts.
 * All endpoints require authentication for security.
 */
@ApiTags('Alerting')
@Controller('alerting')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class AlertingController {
  constructor(private alertingService: AlertingService) {}
  
  /**
   * Get all alert rules
   */
  @Get('rules')
  @ApiOperation({ 
    summary: 'Get all alert rules',
    description: 'Retrieve all configured alert rules'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Alert rules retrieved successfully',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string', example: 'high_login_failures' },
          name: { type: 'string', example: 'High Login Failure Rate' },
          metric: { type: 'string', example: 'auth.login.failure' },
          condition: { type: 'string', enum: ['greater_than', 'less_than', 'equals'] },
          threshold: { type: 'number', example: 10 },
          windowMinutes: { type: 'number', example: 5 },
          severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
          enabled: { type: 'boolean', example: true },
          tags: { type: 'object', example: { provider: 'google' } }
        }
      }
    }
  })
  getRules(): AlertRule[] {
    return this.alertingService.getRules();
  }
  
  /**
   * Add a new alert rule
   */
  @Post('rules')
  @ApiOperation({ 
    summary: 'Add alert rule',
    description: 'Create a new alert rule for monitoring'
  })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['id', 'name', 'metric', 'condition', 'threshold', 'windowMinutes', 'severity'],
      properties: {
        id: { type: 'string', example: 'custom_rule_1' },
        name: { type: 'string', example: 'Custom Alert Rule' },
        metric: { type: 'string', example: 'auth.login.failure' },
        condition: { type: 'string', enum: ['greater_than', 'less_than', 'equals'] },
        threshold: { type: 'number', example: 5 },
        windowMinutes: { type: 'number', example: 10 },
        severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
        enabled: { type: 'boolean', example: true },
        tags: { type: 'object', example: { provider: 'google' } }
      }
    }
  })
  @ApiResponse({ 
    status: 201, 
    description: 'Alert rule created successfully'
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Invalid rule configuration'
  })
  @HttpCode(HttpStatus.CREATED)
  addRule(@Body() rule: AlertRule): { message: string } {
    this.alertingService.addRule(rule);
    return { message: `Alert rule '${rule.name}' added successfully` };
  }
  
  /**
   * Remove an alert rule
   */
  @Delete('rules/:ruleId')
  @ApiOperation({ 
    summary: 'Remove alert rule',
    description: 'Delete an existing alert rule'
  })
  @ApiParam({ 
    name: 'ruleId', 
    description: 'Alert rule ID',
    example: 'high_login_failures'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Alert rule removed successfully'
  })
  @ApiResponse({ 
    status: 404, 
    description: 'Alert rule not found'
  })
  removeRule(@Param('ruleId') ruleId: string): { message: string } {
    this.alertingService.removeRule(ruleId);
    return { message: `Alert rule '${ruleId}' removed successfully` };
  }
  
  /**
   * Get active alerts
   */
  @Get('alerts')
  @ApiOperation({ 
    summary: 'Get active alerts',
    description: 'Retrieve all currently active (unresolved) alerts'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Active alerts retrieved successfully',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string', example: 'alert_1642345678_abc123' },
          ruleId: { type: 'string', example: 'high_login_failures' },
          ruleName: { type: 'string', example: 'High Login Failure Rate' },
          metric: { type: 'string', example: 'auth.login.failure' },
          value: { type: 'number', example: 15 },
          threshold: { type: 'number', example: 10 },
          severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
          message: { type: 'string', example: 'High Login Failure Rate: auth.login.failure is 15 (greater than 10)' },
          timestamp: { type: 'string', format: 'date-time' },
          resolved: { type: 'boolean', example: false },
          resolvedAt: { type: 'string', format: 'date-time', nullable: true },
          metadata: { type: 'object' }
        }
      }
    }
  })
  getActiveAlerts(): Alert[] {
    return this.alertingService.getActiveAlerts();
  }
  
  /**
   * Get all alerts (including resolved)
   */
  @Get('alerts/all')
  @ApiOperation({ 
    summary: 'Get all alerts',
    description: 'Retrieve all alerts including resolved ones'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'All alerts retrieved successfully'
  })
  getAllAlerts(): Alert[] {
    return this.alertingService.getAllAlerts();
  }
  
  /**
   * Resolve an alert
   */
  @Put('alerts/:alertId/resolve')
  @ApiOperation({ 
    summary: 'Resolve alert',
    description: 'Mark an active alert as resolved'
  })
  @ApiParam({ 
    name: 'alertId', 
    description: 'Alert ID',
    example: 'alert_1642345678_abc123'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Alert resolved successfully'
  })
  @ApiResponse({ 
    status: 404, 
    description: 'Alert not found'
  })
  resolveAlert(@Param('alertId') alertId: string): { message: string } {
    this.alertingService.resolveAlert(alertId);
    return { message: `Alert '${alertId}' resolved successfully` };
  }
  
  /**
   * Trigger a manual alert
   */
  @Post('alerts/trigger')
  @ApiOperation({ 
    summary: 'Trigger manual alert',
    description: 'Manually trigger an alert for testing or custom scenarios'
  })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['ruleName', 'message', 'severity'],
      properties: {
        ruleName: { type: 'string', example: 'Manual Test Alert' },
        message: { type: 'string', example: 'This is a test alert triggered manually' },
        severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'], example: 'medium' },
        metadata: { 
          type: 'object', 
          example: { source: 'manual', user: 'admin' }
        }
      }
    }
  })
  @ApiResponse({ 
    status: 201, 
    description: 'Alert triggered successfully'
  })
  @HttpCode(HttpStatus.CREATED)
  async triggerAlert(@Body() body: {
    ruleName: string;
    message: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    metadata?: Record<string, any>;
  }): Promise<{ message: string }> {
    await this.alertingService.triggerAlert(
      body.ruleName,
      body.message,
      body.severity,
      body.metadata,
    );
    return { message: 'Alert triggered successfully' };
  }
  
  /**
   * Check all rules manually
   */
  @Post('rules/check')
  @ApiOperation({ 
    summary: 'Check all rules',
    description: 'Manually trigger a check of all alert rules'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Rules checked successfully'
  })
  @HttpCode(HttpStatus.OK)
  async checkRules(): Promise<{ message: string }> {
    await this.alertingService.checkRules();
    return { message: 'All rules checked successfully' };
  }
  
  /**
   * Get alerting service health
   */
  @Get('health')
  @ApiOperation({ 
    summary: 'Get alerting service health',
    description: 'Check if alerting service is enabled and working'
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Alerting service health status',
    schema: {
      type: 'object',
      properties: {
        enabled: { type: 'boolean', example: true },
        rulesCount: { type: 'number', example: 6 },
        activeAlertsCount: { type: 'number', example: 2 },
        totalAlertsCount: { type: 'number', example: 25 },
        channelsCount: { type: 'number', example: 3 },
        enabledChannels: { type: 'number', example: 2 }
      }
    }
  })
  getAlertingHealth(): Record<string, any> {
    return this.alertingService.getHealthStatus();
  }
}