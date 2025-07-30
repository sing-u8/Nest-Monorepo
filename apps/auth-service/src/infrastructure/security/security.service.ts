import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

/**
 * Security Service
 * 
 * Provides core security utilities including:
 * - Security header configuration
 * - CORS policy management
 * - Cryptographic utilities
 * - Security validation helpers
 */
@Injectable()
export class SecurityService {
  private readonly logger = new Logger(SecurityService.name);

  constructor(private readonly configService: ConfigService) {}

  /**
   * Get security headers configuration
   */
  getSecurityHeaders(): Record<string, string> {
    return {
      // Prevent XSS attacks
      'X-XSS-Protection': '1; mode=block',
      
      // Prevent content type sniffing
      'X-Content-Type-Options': 'nosniff',
      
      // Prevent clickjacking
      'X-Frame-Options': 'DENY',
      
      // Strict Transport Security (HTTPS only)
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      
      // Content Security Policy
      'Content-Security-Policy': this.getContentSecurityPolicy(),
      
      // Referrer Policy
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      
      // Permissions Policy
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      
      // Remove server information
      'X-Powered-By': '',
      'Server': '',
    };
  }

  /**
   * Get CORS configuration
   */
  getCorsConfiguration(): any {
    const allowedOrigins = this.configService.get<string[]>('security.cors.allowedOrigins', [
      'http://localhost:3000',
      'http://localhost:3001',
    ]);

    return {
      origin: (origin: string, callback: (err: Error | null, allow?: boolean) => void) => {
        // Allow requests with no origin (mobile apps, etc.)
        if (!origin) return callback(null, true);
        
        // Check if origin is in allowed list
        if (allowedOrigins.includes(origin)) {
          return callback(null, true);
        }

        // Check if origin matches patterns in production
        if (process.env.NODE_ENV === 'production') {
          const allowedPatterns = this.configService.get<string[]>('security.cors.allowedPatterns', []);
          const isAllowed = allowedPatterns.some(pattern => {
            const regex = new RegExp(pattern);
            return regex.test(origin);
          });
          
          if (isAllowed) {
            return callback(null, true);
          }
        }

        this.logger.warn(`CORS blocked origin: ${origin}`);
        callback(new Error('CORS policy violation'), false);
      },
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: [
        'Origin',
        'X-Requested-With',
        'Content-Type',
        'Accept',
        'Authorization',
        'X-Device-ID',
        'X-Client-Version',
      ],
      exposedHeaders: [
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset',
      ],
      credentials: true,
      maxAge: 86400, // 24 hours
    };
  }

  /**
   * Generate Content Security Policy
   */
  private getContentSecurityPolicy(): string {
    const policies = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-src 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ];

    // Add additional sources in development
    if (process.env.NODE_ENV === 'development') {
      policies.push("script-src 'self' 'unsafe-inline' 'unsafe-eval'");
    }

    return policies.join('; ');
  }

  /**
   * Generate cryptographically secure random string
   */
  generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Generate secure state parameter for OAuth
   */
  generateOAuthState(): string {
    return this.generateSecureToken(16);
  }

  /**
   * Generate secure nonce for OIDC
   */
  generateNonce(): string {
    return this.generateSecureToken(16);
  }

  /**
   * Validate and sanitize redirect URL
   */
  validateRedirectUrl(url: string): boolean {
    if (!url) return false;

    try {
      const parsed = new URL(url);
      
      // Only allow HTTPS in production
      if (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:') {
        return false;
      }

      // Check against allowed domains
      const allowedDomains = this.configService.get<string[]>('security.redirectUrls.allowedDomains', [
        'localhost',
      ]);

      return allowedDomains.some(domain => 
        parsed.hostname === domain || parsed.hostname.endsWith(`.${domain}`)
      );
    } catch (error) {
      this.logger.warn(`Invalid redirect URL: ${url}`);
      return false;
    }
  }

  /**
   * Sanitize file upload name
   */
  sanitizeFileName(fileName: string): string {
    if (!fileName) return '';

    // Remove path traversal attempts
    let sanitized = fileName.replace(/[\.\/\\]/g, '');
    
    // Remove special characters except dash, underscore, and dot
    sanitized = sanitized.replace(/[^a-zA-Z0-9\-_\.]/g, '');
    
    // Limit length
    sanitized = sanitized.substring(0, 100);
    
    // Ensure it's not empty
    if (!sanitized) {
      sanitized = 'file';
    }

    return sanitized;
  }

  /**
   * Check if IP address is from a private network
   */
  isPrivateIP(ip: string): boolean {
    if (!ip || ip === 'Unknown') return false;

    const privateRanges = [
      /^127\./,                    // 127.0.0.0/8 (localhost)
      /^192\.168\./,               // 192.168.0.0/16
      /^10\./,                     // 10.0.0.0/8
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
      /^::1$/,                     // IPv6 localhost
      /^fc00:/,                    // IPv6 unique local addresses
    ];

    return privateRanges.some(range => range.test(ip));
  }

  /**
   * Rate limit key generator for different contexts
   */
  generateRateLimitKey(context: string, identifier: string): string {
    return `rate_limit:${context}:${identifier}`;
  }

  /**
   * Security event logging helper
   */
  logSecurityEvent(event: SecurityEvent): void {
    const logData = {
      timestamp: new Date().toISOString(),
      event: event.type,
      severity: event.severity,
      clientIp: event.clientIp,
      userAgent: event.userAgent,
      userId: event.userId,
      details: event.details,
      correlationId: event.correlationId || this.generateSecureToken(8),
    };

    switch (event.severity) {
      case 'critical':
        this.logger.error(`SECURITY CRITICAL: ${JSON.stringify(logData)}`);
        break;
      case 'high':
        this.logger.error(`SECURITY HIGH: ${JSON.stringify(logData)}`);
        break;
      case 'medium':
        this.logger.warn(`SECURITY MEDIUM: ${JSON.stringify(logData)}`);
        break;
      case 'low':
        this.logger.log(`SECURITY LOW: ${JSON.stringify(logData)}`);
        break;
      default:
        this.logger.debug(`SECURITY INFO: ${JSON.stringify(logData)}`);
    }
  }

  /**
   * Validate user agent string for suspicious patterns
   */
  validateUserAgent(userAgent: string): SecurityValidationResult {
    if (!userAgent) {
      return {
        isValid: false,
        risk: 'medium',
        reason: 'Missing user agent',
      };
    }

    // Check for suspicious patterns
    const suspiciousPatterns = [
      /curl/i,
      /wget/i,
      /python/i,
      /bot(?!.*google|.*bing|.*yahoo)/i,
      /crawler/i,
      /spider/i,
      /scraper/i,
    ];

    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(userAgent));
    
    if (isSuspicious) {
      return {
        isValid: false,
        risk: 'high',
        reason: 'Suspicious user agent pattern detected',
      };
    }

    return {
      isValid: true,
      risk: 'low',
      reason: 'Valid user agent',
    };
  }
}

/**
 * Security event interface
 */
export interface SecurityEvent {
  type: 'auth_failure' | 'rate_limit' | 'cors_violation' | 'suspicious_activity' | 'data_breach';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  clientIp: string;
  userAgent?: string;
  userId?: string;
  details: Record<string, any>;
  correlationId?: string;
}

/**
 * Security validation result
 */
export interface SecurityValidationResult {
  isValid: boolean;
  risk: 'critical' | 'high' | 'medium' | 'low';
  reason: string;
}