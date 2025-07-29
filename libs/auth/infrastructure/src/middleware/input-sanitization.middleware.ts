import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

/**
 * Input Sanitization Middleware
 * 
 * Sanitizes incoming request data to prevent various injection attacks
 * and normalize input data for consistent processing.
 */
@Injectable()
export class InputSanitizationMiddleware implements NestMiddleware {
  private readonly logger = new Logger(InputSanitizationMiddleware.name);

  use(req: Request, res: Response, next: NextFunction): void {
    try {
      // Sanitize request body
      if (req.body && typeof req.body === 'object') {
        req.body = this.sanitizeObject(req.body);
      }

      // Sanitize query parameters
      if (req.query && typeof req.query === 'object') {
        req.query = this.sanitizeObject(req.query);
      }

      // Sanitize route parameters
      if (req.params && typeof req.params === 'object') {
        req.params = this.sanitizeObject(req.params);
      }

      // Log suspicious patterns
      this.detectSuspiciousPatterns(req);

      next();
    } catch (error) {
      this.logger.error('Input sanitization error:', error);
      next(); // Continue on error to avoid blocking legitimate requests
    }
  }

  /**
   * Sanitize an object recursively
   */
  private sanitizeObject(obj: any): any {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item));
    }

    if (typeof obj === 'object') {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(obj)) {
        const sanitizedKey = this.sanitizeString(key);
        sanitized[sanitizedKey] = this.sanitizeObject(value);
      }
      return sanitized;
    }

    if (typeof obj === 'string') {
      return this.sanitizeString(obj);
    }

    return obj;
  }

  /**
   * Sanitize a string value
   */
  private sanitizeString(str: string): string {
    if (typeof str !== 'string') {
      return str;
    }

    let sanitized = str;

    // Remove null bytes
    sanitized = sanitized.replace(/\x00/g, '');

    // Normalize Unicode
    sanitized = sanitized.normalize('NFC');

    // Remove BOM (Byte Order Mark)
    sanitized = sanitized.replace(/\uFEFF/g, '');

    // Trim whitespace
    sanitized = sanitized.trim();

    // Limit length to prevent DoS attacks
    if (sanitized.length > 10000) {
      sanitized = sanitized.substring(0, 10000);
      this.logger.warn('Input truncated due to excessive length');
    }

    // Remove potentially dangerous characters for specific contexts
    sanitized = this.removeSpecialCharacters(sanitized);

    return sanitized;
  }

  /**
   * Remove potentially dangerous special characters
   */
  private removeSpecialCharacters(str: string): string {
    // Remove control characters except tab, newline, and carriage return
    let cleaned = str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    // Remove dangerous HTML entities
    cleaned = cleaned.replace(/&[#\w]+;/g, '');

    // Remove potentially dangerous Unicode characters
    cleaned = cleaned.replace(/[\u202A-\u202E\u2066-\u2069]/g, ''); // Directional formatting
    cleaned = cleaned.replace(/[\uFFF0-\uFFFF]/g, ''); // Special area
    cleaned = cleaned.replace(/[\u0000-\u001F]/g, ''); // Control characters

    return cleaned;
  }

  /**
   * Detect suspicious patterns in the request
   */
  private detectSuspiciousPatterns(req: Request): void {
    const suspiciousPatterns = [
      // SQL Injection patterns
      /(union\s+select|insert\s+into|delete\s+from|drop\s+table|alter\s+table)/i,
      /('|(\\')|(;)|(--)|(\/\*)|(\*\/))/,
      
      // XSS patterns
      /(<script|<\/script|javascript:|on\w+\s*=)/i,
      /(alert\s*\(|confirm\s*\(|prompt\s*\()/i,
      /(document\.|window\.|eval\s*\()/i,
      
      // Command injection patterns
      /(;\s*ls|;\s*cat|;\s*pwd|;\s*whoami)/i,
      /(\||&&|;|\$\(|\`)/,
      /(curl\s+|wget\s+|nc\s+)/i,
      
      // Path traversal patterns
      /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\\)/i,
      /(\/etc\/passwd|\/etc\/shadow|\/windows\/system32)/i,
      
      // LDAP injection patterns
      /(\(\||\)\(|\*\)|\|\=)/,
      
      // NoSQL injection patterns
      /(\$gt|\$lt|\$ne|\$regex|\$where)/i,
      
      // Template injection patterns
      /(\{\{|\}\}|\[\[|\]\]|<%|%>)/,
    ];

    const requestStr = JSON.stringify({
      body: req.body,
      query: req.query,
      params: req.params,
    });

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(requestStr)) {
        this.logger.warn('Suspicious pattern detected', {
          pattern: pattern.source,
          ip: this.getClientIP(req),
          userAgent: req.headers['user-agent'],
          url: req.url,
          method: req.method,
        });
        break;
      }
    }
  }

  /**
   * Extract client IP address
   */
  private getClientIP(req: Request): string {
    return (
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      (req.headers['x-real-ip'] as string) ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      '0.0.0.0'
    );
  }
}

/**
 * Advanced Input Sanitizer utility class
 */
export class InputSanitizer {
  /**
   * Sanitize email input
   */
  static sanitizeEmail(email: string): string {
    if (!email || typeof email !== 'string') {
      return '';
    }

    // Convert to lowercase and trim
    let sanitized = email.toLowerCase().trim();

    // Remove potentially dangerous characters
    sanitized = sanitized.replace(/[<>'"&]/g, '');

    // Ensure email format
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(sanitized)) {
      return '';
    }

    return sanitized;
  }

  /**
   * Sanitize password input (minimal sanitization to preserve character requirements)
   */
  static sanitizePassword(password: string): string {
    if (!password || typeof password !== 'string') {
      return '';
    }

    // Only remove null bytes and normalize
    let sanitized = password.replace(/\x00/g, '');
    sanitized = sanitized.normalize('NFC');

    // Limit length
    if (sanitized.length > 128) {
      sanitized = sanitized.substring(0, 128);
    }

    return sanitized;
  }

  /**
   * Sanitize name input
   */
  static sanitizeName(name: string): string {
    if (!name || typeof name !== 'string') {
      return '';
    }

    let sanitized = name.trim();

    // Remove HTML tags
    sanitized = sanitized.replace(/<[^>]*>/g, '');

    // Remove script-like content
    sanitized = sanitized.replace(/javascript:/gi, '');
    sanitized = sanitized.replace(/on\w+\s*=/gi, '');

    // Allow Unicode letters, spaces, hyphens, apostrophes
    sanitized = sanitized.replace(/[^\p{L}\p{M}\s\-'\.]/gu, '');

    // Limit length
    if (sanitized.length > 100) {
      sanitized = sanitized.substring(0, 100);
    }

    // Trim again after cleaning
    sanitized = sanitized.trim();

    return sanitized;
  }

  /**
   * Sanitize URL input
   */
  static sanitizeUrl(url: string): string {
    if (!url || typeof url !== 'string') {
      return '';
    }

    let sanitized = url.trim();

    // Remove dangerous protocols
    const dangerousProtocols = /^(javascript|data|vbscript|file|ftp):/i;
    if (dangerousProtocols.test(sanitized)) {
      return '';
    }

    // Ensure valid URL format
    try {
      const urlObj = new URL(sanitized);
      
      // Only allow http and https
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        return '';
      }

      return urlObj.toString();
    } catch {
      return '';
    }
  }

  /**
   * Sanitize file name
   */
  static sanitizeFileName(fileName: string): string {
    if (!fileName || typeof fileName !== 'string') {
      return '';
    }

    let sanitized = fileName.trim();

    // Remove path traversal attempts
    sanitized = sanitized.replace(/\.\./g, '');
    sanitized = sanitized.replace(/[\/\\]/g, '');

    // Remove dangerous characters
    sanitized = sanitized.replace(/[<>:"|?*\x00-\x1f]/g, '');

    // Remove leading dots and spaces
    sanitized = sanitized.replace(/^[\.\s]+/, '');

    // Limit length
    if (sanitized.length > 255) {
      const ext = sanitized.split('.').pop();
      const name = sanitized.substring(0, 255 - (ext ? ext.length + 1 : 0));
      sanitized = ext ? `${name}.${ext}` : name;
    }

    return sanitized;
  }

  /**
   * Sanitize generic text input
   */
  static sanitizeText(text: string, maxLength: number = 1000): string {
    if (!text || typeof text !== 'string') {
      return '';
    }

    let sanitized = text.trim();

    // Remove HTML tags
    sanitized = sanitized.replace(/<[^>]*>/g, '');

    // Remove script content
    sanitized = sanitized.replace(/javascript:/gi, '');
    sanitized = sanitized.replace(/on\w+\s*=/gi, '');

    // Remove null bytes
    sanitized = sanitized.replace(/\x00/g, '');

    // Normalize Unicode
    sanitized = sanitized.normalize('NFC');

    // Limit length
    if (sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }

    return sanitized;
  }

  /**
   * Sanitize phone number
   */
  static sanitizePhoneNumber(phone: string): string {
    if (!phone || typeof phone !== 'string') {
      return '';
    }

    // Remove all non-digit and non-plus characters
    let sanitized = phone.replace(/[^\d+\-\(\)\s]/g, '');

    // Trim
    sanitized = sanitized.trim();

    // Basic phone number validation
    const phoneRegex = /^[\+]?[1-9][\d\-\(\)\s]{7,20}$/;
    if (!phoneRegex.test(sanitized)) {
      return '';
    }

    return sanitized;
  }

  /**
   * Sanitize search query
   */
  static sanitizeSearchQuery(query: string): string {
    if (!query || typeof query !== 'string') {
      return '';
    }

    let sanitized = query.trim();

    // Remove potentially dangerous SQL/NoSQL operators
    sanitized = sanitized.replace(/(\$gt|\$lt|\$ne|\$regex|\$where|union\s+select)/gi, '');

    // Remove script tags and content
    sanitized = sanitized.replace(/<script[\s\S]*?<\/script>/gi, '');
    sanitized = sanitized.replace(/javascript:/gi, '');

    // Limit length
    if (sanitized.length > 500) {
      sanitized = sanitized.substring(0, 500);
    }

    return sanitized;
  }
}