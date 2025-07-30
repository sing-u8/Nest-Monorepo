import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';

import { RateLimitGuard } from '../guards/rate-limit.guard';
import { SecurityService } from './security.service';
import { AuditLogger } from './audit-logger.service';
import { InputSanitizer } from './input-sanitizer.service';

/**
 * Security Module
 * 
 * Provides comprehensive security features including:
 * - Rate limiting and throttling
 * - Audit logging
 * - Input validation and sanitization
 * - Security headers configuration
 */
@Module({
  imports: [
    ConfigModule,
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        throttlers: [
          {
            // Global rate limit
            name: 'global',
            ttl: configService.get<number>('security.rateLimit.global.ttl', 60000), // 1 minute
            limit: configService.get<number>('security.rateLimit.global.limit', 100), // 100 requests per minute
          },
          {
            // Authentication endpoints (stricter)
            name: 'auth',
            ttl: configService.get<number>('security.rateLimit.auth.ttl', 60000), // 1 minute
            limit: configService.get<number>('security.rateLimit.auth.limit', 10), // 10 requests per minute
          },
          {
            // Login attempts (very strict)
            name: 'login',
            ttl: configService.get<number>('security.rateLimit.login.ttl', 300000), // 5 minutes
            limit: configService.get<number>('security.rateLimit.login.limit', 5), // 5 attempts per 5 minutes
          },
        ],
        storage: configService.get<string>('security.rateLimit.storage', 'memory'),
        ignoreUserAgents: [
          /googlebot/gi,
          /bingbot/gi,
          /slurp/gi,
          /duckduckbot/gi,
        ],
        skipIf: (context) => {
          // Skip rate limiting for health checks
          const request = context.switchToHttp().getRequest();
          return request.url === '/health' || request.url === '/metrics';
        },
      }),
    }),
  ],
  providers: [
    // Security services
    SecurityService,
    AuditLogger,
    InputSanitizer,
    
    // Rate limiting guard (global)
    {
      provide: APP_GUARD,
      useClass: RateLimitGuard,
    },
  ],
  exports: [
    SecurityService,
    AuditLogger,
    InputSanitizer,
    ThrottlerModule,
  ],
})
export class SecurityModule {}