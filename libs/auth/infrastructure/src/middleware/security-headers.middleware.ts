import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

export interface SecurityHeadersConfig {
  // Content Security Policy
  csp?: {
    enabled: boolean;
    directives: Record<string, string[]>;
    reportOnly: boolean;
  };
  
  // HTTP Strict Transport Security
  hsts?: {
    enabled: boolean;
    maxAge: number;
    includeSubDomains: boolean;
    preload: boolean;
  };
  
  // X-Frame-Options
  frameOptions?: 'DENY' | 'SAMEORIGIN' | 'ALLOW-FROM' | false;
  
  // X-Content-Type-Options
  noSniff?: boolean;
  
  // X-XSS-Protection
  xssProtection?: {
    enabled: boolean;
    mode: 'block' | 'report';
    reportUri?: string;
  };
  
  // Referrer Policy
  referrerPolicy?: string;
  
  // Permissions Policy (formerly Feature Policy)
  permissionsPolicy?: Record<string, string[]>;
  
  // CORS
  cors?: {
    enabled: boolean;
    origin: string | string[] | boolean;
    methods: string[];
    allowedHeaders: string[];
    exposedHeaders: string[];
    credentials: boolean;
    maxAge: number;
  };
  
  // Additional custom headers
  customHeaders?: Record<string, string>;
}

/**
 * Security Headers Middleware
 * 
 * Adds comprehensive security headers to protect against various attacks
 * including XSS, clickjacking, MIME type sniffing, and more.
 */
@Injectable()
export class SecurityHeadersMiddleware implements NestMiddleware {
  private readonly config: SecurityHeadersConfig;

  constructor(config?: Partial<SecurityHeadersConfig>) {
    this.config = this.mergeWithDefaults(config || {});
  }

  use(req: Request, res: Response, next: NextFunction): void {
    try {
      // Set Content Security Policy
      this.setCSP(res);
      
      // Set HSTS
      this.setHSTS(res);
      
      // Set X-Frame-Options
      this.setFrameOptions(res);
      
      // Set X-Content-Type-Options
      this.setNoSniff(res);
      
      // Set X-XSS-Protection
      this.setXSSProtection(res);
      
      // Set Referrer Policy
      this.setReferrerPolicy(res);
      
      // Set Permissions Policy
      this.setPermissionsPolicy(res);
      
      // Set CORS headers
      this.setCORS(req, res);
      
      // Set custom headers
      this.setCustomHeaders(res);
      
      // Security-focused headers
      this.setAdditionalSecurityHeaders(res);

      next();
    } catch (error) {
      // Continue on error to avoid breaking the application
      next();
    }
  }

  /**
   * Set Content Security Policy
   */
  private setCSP(res: Response): void {
    if (!this.config.csp?.enabled) return;

    const directives = Object.entries(this.config.csp.directives)
      .map(([key, values]) => `${key} ${values.join(' ')}`)
      .join('; ');

    const headerName = this.config.csp.reportOnly 
      ? 'Content-Security-Policy-Report-Only' 
      : 'Content-Security-Policy';

    res.set(headerName, directives);
  }

  /**
   * Set HTTP Strict Transport Security
   */
  private setHSTS(res: Response): void {
    if (!this.config.hsts?.enabled) return;

    let hstsValue = `max-age=${this.config.hsts.maxAge}`;
    
    if (this.config.hsts.includeSubDomains) {
      hstsValue += '; includeSubDomains';
    }
    
    if (this.config.hsts.preload) {
      hstsValue += '; preload';
    }

    res.set('Strict-Transport-Security', hstsValue);
  }

  /**
   * Set X-Frame-Options
   */
  private setFrameOptions(res: Response): void {
    if (this.config.frameOptions) {
      res.set('X-Frame-Options', this.config.frameOptions);
    }
  }

  /**
   * Set X-Content-Type-Options
   */
  private setNoSniff(res: Response): void {
    if (this.config.noSniff) {
      res.set('X-Content-Type-Options', 'nosniff');
    }
  }

  /**
   * Set X-XSS-Protection
   */
  private setXSSProtection(res: Response): void {
    if (!this.config.xssProtection?.enabled) return;

    let xssValue = '1';
    
    if (this.config.xssProtection.mode === 'block') {
      xssValue += '; mode=block';
    } else if (this.config.xssProtection.mode === 'report' && this.config.xssProtection.reportUri) {
      xssValue += `; report=${this.config.xssProtection.reportUri}`;
    }

    res.set('X-XSS-Protection', xssValue);
  }

  /**
   * Set Referrer Policy
   */
  private setReferrerPolicy(res: Response): void {
    if (this.config.referrerPolicy) {
      res.set('Referrer-Policy', this.config.referrerPolicy);
    }
  }

  /**
   * Set Permissions Policy
   */
  private setPermissionsPolicy(res: Response): void {
    if (!this.config.permissionsPolicy) return;

    const policy = Object.entries(this.config.permissionsPolicy)
      .map(([feature, allowlist]) => `${feature}=(${allowlist.join(' ')})`)
      .join(', ');

    res.set('Permissions-Policy', policy);
  }

  /**
   * Set CORS headers
   */
  private setCORS(req: Request, res: Response): void {
    if (!this.config.cors?.enabled) return;

    const origin = req.headers.origin;
    
    // Set Access-Control-Allow-Origin
    if (this.config.cors.origin === true) {
      res.set('Access-Control-Allow-Origin', '*');
    } else if (typeof this.config.cors.origin === 'string') {
      res.set('Access-Control-Allow-Origin', this.config.cors.origin);
    } else if (Array.isArray(this.config.cors.origin) && origin) {
      if (this.config.cors.origin.includes(origin)) {
        res.set('Access-Control-Allow-Origin', origin);
      }
    }

    // Set other CORS headers
    res.set('Access-Control-Allow-Methods', this.config.cors.methods.join(', '));
    res.set('Access-Control-Allow-Headers', this.config.cors.allowedHeaders.join(', '));
    
    if (this.config.cors.exposedHeaders.length > 0) {
      res.set('Access-Control-Expose-Headers', this.config.cors.exposedHeaders.join(', '));
    }
    
    if (this.config.cors.credentials) {
      res.set('Access-Control-Allow-Credentials', 'true');
    }
    
    if (this.config.cors.maxAge > 0) {
      res.set('Access-Control-Max-Age', this.config.cors.maxAge.toString());
    }
  }

  /**
   * Set custom headers
   */
  private setCustomHeaders(res: Response): void {
    if (!this.config.customHeaders) return;

    Object.entries(this.config.customHeaders).forEach(([name, value]) => {
      res.set(name, value);
    });
  }

  /**
   * Set additional security headers
   */
  private setAdditionalSecurityHeaders(res: Response): void {
    // Remove server information
    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');
    
    // Prevent MIME type sniffing
    res.set('X-Content-Type-Options', 'nosniff');
    
    // Prevent DNS prefetching
    res.set('X-DNS-Prefetch-Control', 'off');
    
    // Download options for IE
    res.set('X-Download-Options', 'noopen');
    
    // Cross-domain policies
    res.set('X-Permitted-Cross-Domain-Policies', 'none');
    
    // Cache control for sensitive content
    if (this.isSensitiveEndpoint(res.req?.url)) {
      res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.set('Pragma', 'no-cache');
      res.set('Expires', '0');
    }
  }

  /**
   * Check if endpoint contains sensitive data
   */
  private isSensitiveEndpoint(url?: string): boolean {
    if (!url) return false;
    
    const sensitivePatterns = [
      '/auth/',
      '/login',
      '/register',
      '/profile',
      '/admin',
      '/api/auth',
    ];
    
    return sensitivePatterns.some(pattern => url.includes(pattern));
  }

  /**
   * Merge user config with secure defaults
   */
  private mergeWithDefaults(config: Partial<SecurityHeadersConfig>): SecurityHeadersConfig {
    const defaults: SecurityHeadersConfig = {
      csp: {
        enabled: true,
        reportOnly: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'", "'unsafe-inline'"],
          'style-src': ["'self'", "'unsafe-inline'"],
          'img-src': ["'self'", 'data:', 'https:'],
          'font-src': ["'self'"],
          'connect-src': ["'self'"],
          'frame-src': ["'none'"],
          'object-src': ["'none'"],
          'base-uri': ["'self'"],
          'form-action': ["'self'"],
          'frame-ancestors': ["'none'"],
          'upgrade-insecure-requests': [],
        },
      },
      
      hsts: {
        enabled: true,
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
      },
      
      frameOptions: 'DENY',
      noSniff: true,
      
      xssProtection: {
        enabled: true,
        mode: 'block',
      },
      
      referrerPolicy: 'strict-origin-when-cross-origin',
      
      permissionsPolicy: {
        'camera': ['none'],
        'microphone': ['none'],
        'geolocation': ['none'],
        'gyroscope': ['none'],
        'magnetometer': ['none'],
        'payment': ['none'],
        'usb': ['none'],
      },
      
      cors: {
        enabled: true,
        origin: false, // No CORS by default for security
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
        exposedHeaders: [],
        credentials: false,
        maxAge: 86400, // 24 hours
      },
      
      customHeaders: {
        'X-API-Version': '1.0',
        'X-Security-Policy': 'strict',
      },
    };

    return this.deepMerge(defaults, config);
  }

  /**
   * Deep merge configuration objects
   */
  private deepMerge(target: any, source: any): any {
    const result = { ...target };
    
    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = this.deepMerge(target[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    }
    
    return result;
  }
}

/**
 * Factory function to create security headers middleware with custom config
 */
export function createSecurityHeadersMiddleware(config?: Partial<SecurityHeadersConfig>) {
  return new SecurityHeadersMiddleware(config);
}

/**
 * Predefined security configurations for different environments
 */
export const SecurityPresets = {
  development: {
    csp: {
      enabled: true,
      reportOnly: true,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'data:', 'https:', 'http:'],
        'connect-src': ["'self'", 'http://localhost:*', 'ws://localhost:*'],
      },
    },
    hsts: { enabled: false },
    cors: {
      enabled: true,
      origin: true,
      credentials: true,
    },
  } as Partial<SecurityHeadersConfig>,

  production: {
    csp: {
      enabled: true,
      reportOnly: false,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'data:'],
        'connect-src': ["'self'"],
        'frame-src': ["'none'"],
        'object-src': ["'none'"],
        'upgrade-insecure-requests': [],
      },
    },
    hsts: {
      enabled: true,
      maxAge: 63072000, // 2 years
      includeSubDomains: true,
      preload: true,
    },
    cors: {
      enabled: true,
      origin: false,
      credentials: false,
    },
  } as Partial<SecurityHeadersConfig>,

  api: {
    frameOptions: 'DENY',
    csp: {
      enabled: true,
      directives: {
        'default-src': ["'none'"],
        'frame-ancestors': ["'none'"],
      },
    },
    cors: {
      enabled: true,
      origin: process.env['ALLOWED_ORIGINS']?.split(',') || false,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
      credentials: true,
    },
  } as Partial<SecurityHeadersConfig>,
};