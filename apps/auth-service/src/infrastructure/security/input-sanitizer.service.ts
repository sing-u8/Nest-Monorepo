import { Injectable, Logger } from '@nestjs/common';

/**
 * Input Sanitizer Service
 * 
 * Provides comprehensive input validation and sanitization including:
 * - HTML/XSS prevention
 * - SQL injection prevention
 * - Path traversal prevention
 * - Email validation and sanitization
 * - URL validation and sanitization
 * - File name sanitization
 */
@Injectable()
export class InputSanitizer {
  private readonly logger = new Logger(InputSanitizer.name);

  /**
   * Sanitize string input to prevent XSS
   */
  sanitizeString(input: string, maxLength?: number): string {
    if (!input || typeof input !== 'string') {
      return '';
    }

    let sanitized = input;

    // Remove HTML tags
    sanitized = sanitized.replace(/<[^>]*>/g, '');
    
    // Remove script content
    sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    
    // Remove dangerous characters
    sanitized = sanitized.replace(/[<>'"&]/g, (match) => {
      switch (match) {
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '"': return '&quot;';
        case "'": return '&#x27;';
        case '&': return '&amp;';
        default: return match;
      }
    });

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    // Trim whitespace
    sanitized = sanitized.trim();

    // Apply length limit
    if (maxLength && sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }

    return sanitized;
  }

  /**
   * Sanitize email address
   */
  sanitizeEmail(email: string): string {
    if (!email || typeof email !== 'string') {
      return '';
    }

    // Convert to lowercase
    let sanitized = email.toLowerCase().trim();

    // Remove dangerous characters
    sanitized = sanitized.replace(/[^a-z0-9@._+-]/g, '');

    // Basic email format validation
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(sanitized)) {
      return '';
    }

    return sanitized;
  }

  /**
   * Sanitize URL
   */
  sanitizeUrl(url: string): string {
    if (!url || typeof url !== 'string') {
      return '';
    }

    try {
      const parsed = new URL(url.trim());
      
      // Only allow HTTP and HTTPS protocols
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return '';
      }

      // Rebuild URL to ensure proper encoding
      return parsed.toString();
    } catch (error) {
      this.logger.warn(`Invalid URL provided for sanitization: ${url}`);
      return '';
    }
  }

  /**
   * Sanitize file name
   */
  sanitizeFileName(fileName: string): string {
    if (!fileName || typeof fileName !== 'string') {
      return '';
    }

    let sanitized = fileName;

    // Remove path separators to prevent directory traversal
    sanitized = sanitized.replace(/[\/\\]/g, '');

    // Remove dangerous characters
    sanitized = sanitized.replace(/[<>:"|?*\x00-\x1f]/g, '');

    // Remove leading/trailing dots and spaces
    sanitized = sanitized.replace(/^[.\s]+|[.\s]+$/g, '');

    // Ensure it's not a reserved name (Windows)
    const reservedNames = [
      'CON', 'PRN', 'AUX', 'NUL',
      'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
      'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    ];

    const nameWithoutExt = sanitized.split('.')[0].toUpperCase();
    if (reservedNames.includes(nameWithoutExt)) {
      sanitized = `file_${sanitized}`;
    }

    // Limit length
    if (sanitized.length > 255) {
      const ext = sanitized.substring(sanitized.lastIndexOf('.'));
      const name = sanitized.substring(0, sanitized.lastIndexOf('.'));
      sanitized = name.substring(0, 255 - ext.length) + ext;
    }

    // Ensure not empty
    if (!sanitized) {
      sanitized = 'untitled';
    }

    return sanitized;
  }

  /**
   * Sanitize JSON input
   */
  sanitizeJson(input: any, allowedKeys?: string[]): any {
    if (input === null || input === undefined) {
      return input;
    }

    if (typeof input === 'string') {
      return this.sanitizeString(input);
    }

    if (typeof input === 'number' || typeof input === 'boolean') {
      return input;
    }

    if (Array.isArray(input)) {
      return input.map(item => this.sanitizeJson(item, allowedKeys));
    }

    if (typeof input === 'object') {
      const sanitized: any = {};
      
      for (const [key, value] of Object.entries(input)) {
        // Skip if key is not in allowed list
        if (allowedKeys && !allowedKeys.includes(key)) {
          continue;
        }

        // Sanitize key
        const sanitizedKey = this.sanitizeString(key, 50);
        if (!sanitizedKey) {
          continue;
        }

        // Recursively sanitize value
        sanitized[sanitizedKey] = this.sanitizeJson(value, allowedKeys);
      }

      return sanitized;
    }

    return input;
  }

  /**
   * Validate and sanitize SQL input (for dynamic queries)
   */
  sanitizeSqlInput(input: string): string {
    if (!input || typeof input !== 'string') {
      return '';
    }

    // Remove SQL injection patterns
    let sanitized = input;

    // Remove SQL keywords that could be dangerous
    const dangerousPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|JOIN)\b)/gi,
      /(\b(OR|AND)\s+\d+\s*=\s*\d+)/gi,
      /(--|\/\*|\*\/)/g,
      /(\b(SLEEP|BENCHMARK|WAITFOR)\b)/gi,
      /(\b(LOAD_FILE|INTO\s+OUTFILE|DUMPFILE)\b)/gi,
    ];

    dangerousPatterns.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });

    // Remove dangerous characters
    sanitized = sanitized.replace(/['"`;]/g, '');

    return sanitized.trim();
  }

  /**
   * Validate input against common attack patterns
   */
  validateInput(input: string): ValidationResult {
    if (!input || typeof input !== 'string') {
      return { isValid: true, threats: [] };
    }

    const threats: string[] = [];

    // Check for XSS patterns
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<iframe/gi,
      /<object/gi,
      /<embed/gi,
    ];

    if (xssPatterns.some(pattern => pattern.test(input))) {
      threats.push('XSS');
    }

    // Check for SQL injection patterns
    const sqlPatterns = [
      /(\bUNION\b.*\bSELECT\b)/gi,
      /(\bSELECT\b.*\bFROM\b)/gi,
      /(';|';\s*--)/gi,
      /(\b(OR|AND)\s+\d+\s*=\s*\d+)/gi,
      /(\b(SLEEP|BENCHMARK|WAITFOR)\s*\()/gi,
    ];

    if (sqlPatterns.some(pattern => pattern.test(input))) {
      threats.push('SQL_INJECTION');
    }

    // Check for LDAP injection
    const ldapPatterns = [
      /[()&|!]/g,
    ];

    if (ldapPatterns.some(pattern => pattern.test(input))) {
      threats.push('LDAP_INJECTION');
    }

    // Check for path traversal
    const pathTraversalPatterns = [
      /\.\.[\/\\]/g,
      /\/(etc|proc|sys|var)\//gi,
      /\\(windows|system32)\\/gi,
    ];

    if (pathTraversalPatterns.some(pattern => pattern.test(input))) {
      threats.push('PATH_TRAVERSAL');
    }

    // Check for command injection
    const commandPatterns = [
      /[;&|`$]/g,
      /\b(rm|del|format|shutdown|reboot)\b/gi,
    ];

    if (commandPatterns.some(pattern => pattern.test(input))) {
      threats.push('COMMAND_INJECTION');
    }

    return {
      isValid: threats.length === 0,
      threats,
    };
  }

  /**
   * Sanitize request headers
   */
  sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
    const sanitized: Record<string, string> = {};
    const allowedHeaders = [
      'content-type',
      'authorization',
      'user-agent',
      'accept',
      'accept-language',
      'accept-encoding',
      'x-forwarded-for',
      'x-real-ip',
      'x-device-id',
      'x-client-version',
    ];

    for (const [key, value] of Object.entries(headers)) {
      const normalizedKey = key.toLowerCase();
      
      // Only include allowed headers
      if (allowedHeaders.includes(normalizedKey)) {
        sanitized[normalizedKey] = this.sanitizeString(value, 1000);
      }
    }

    return sanitized;
  }

  /**
   * Generate content security policy nonce
   */
  generateCSPNonce(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let nonce = '';
    for (let i = 0; i < 16; i++) {
      nonce += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return nonce;
  }
}

/**
 * Validation result interface
 */
interface ValidationResult {
  isValid: boolean;
  threats: string[];
}