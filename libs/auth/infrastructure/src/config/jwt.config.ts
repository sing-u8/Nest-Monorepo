/**
 * JWT Configuration
 * 
 * Centralized configuration for JWT token settings.
 * These values should be environment-specific and regularly reviewed for security.
 */
export interface JwtConfig {
  /**
   * JWT signing algorithm
   * Recommended: RS256 for enhanced security with public/private key pairs
   */
  algorithm: 'RS256' | 'HS256';

  /**
   * Token issuer identifier
   * Should identify the service issuing tokens
   */
  issuer: string;

  /**
   * Token audience identifier
   * Should identify the intended recipients of tokens
   */
  audience: string;

  /**
   * Private key for signing tokens (RS256)
   * In production, should be loaded from secure key management
   */
  privateKey?: string;

  /**
   * Public key for verifying tokens (RS256)
   * In production, should be loaded from secure key management
   */
  publicKey?: string;

  /**
   * Secret key for signing/verifying tokens (HS256)
   * In production, should be a strong, randomly generated secret
   */
  secretKey?: string;

  /**
   * Default token expiration times
   */
  defaultExpirations: {
    accessToken: string;
    refreshToken: string;
    resetPasswordToken: string;
    emailVerificationToken: string;
  };

  /**
   * Maximum allowed token lifetime
   * Prevents tokens with excessive expiration times
   */
  maxTokenLifetime: {
    accessToken: string;
    refreshToken: string;
    resetPasswordToken: string;
    emailVerificationToken: string;
  };

  /**
   * Token blacklist settings
   */
  blacklist: {
    /**
     * Whether to enable token blacklisting
     */
    enabled: boolean;
    
    /**
     * Cleanup interval for expired blacklisted tokens (in milliseconds)
     */
    cleanupInterval: number;
    
    /**
     * Maximum number of blacklisted tokens to keep in memory
     */
    maxSize: number;
  };

  /**
   * Security settings
   */
  security: {
    /**
     * Whether to include JTI (JWT ID) in tokens for better tracking
     */
    includeJti: boolean;
    
    /**
     * Whether to validate token not before (nbf) claim
     */
    validateNotBefore: boolean;
    
    /**
     * Clock tolerance in seconds for token validation
     */
    clockTolerance: number;
  };
}

/**
 * Default JWT configuration
 * Secure defaults for production use
 */
export const DEFAULT_JWT_CONFIG: JwtConfig = {
  algorithm: 'RS256',
  issuer: 'auth-service',
  audience: 'auth-client',
  defaultExpirations: {
    accessToken: '15m',
    refreshToken: '7d',
    resetPasswordToken: '1h',
    emailVerificationToken: '24h',
  },
  maxTokenLifetime: {
    accessToken: '1h',
    refreshToken: '30d',
    resetPasswordToken: '24h',
    emailVerificationToken: '7d',
  },
  blacklist: {
    enabled: true,
    cleanupInterval: 60 * 60 * 1000, // 1 hour
    maxSize: 10000,
  },
  security: {
    includeJti: true,
    validateNotBefore: true,
    clockTolerance: 30, // 30 seconds
  },
};

/**
 * Development JWT configuration
 * Relaxed settings for development
 */
export const DEVELOPMENT_JWT_CONFIG: JwtConfig = {
  ...DEFAULT_JWT_CONFIG,
  defaultExpirations: {
    accessToken: '1h',
    refreshToken: '30d',
    resetPasswordToken: '24h',
    emailVerificationToken: '7d',
  },
  blacklist: {
    enabled: false,
    cleanupInterval: 0,
    maxSize: 0,
  },
  security: {
    includeJti: false,
    validateNotBefore: false,
    clockTolerance: 60, // 1 minute tolerance for dev
  },
};

/**
 * Production JWT configuration
 * Enhanced security for production
 */
export const PRODUCTION_JWT_CONFIG: JwtConfig = {
  ...DEFAULT_JWT_CONFIG,
  defaultExpirations: {
    accessToken: '10m',
    refreshToken: '7d',
    resetPasswordToken: '30m',
    emailVerificationToken: '12h',
  },
  maxTokenLifetime: {
    accessToken: '30m',
    refreshToken: '14d',
    resetPasswordToken: '2h',
    emailVerificationToken: '24h',
  },
  blacklist: {
    enabled: true,
    cleanupInterval: 30 * 60 * 1000, // 30 minutes
    maxSize: 50000,
  },
  security: {
    includeJti: true,
    validateNotBefore: true,
    clockTolerance: 15, // 15 seconds
  },
};

/**
 * Test JWT configuration
 * Fast settings for testing
 */
export const TEST_JWT_CONFIG: JwtConfig = {
  ...DEFAULT_JWT_CONFIG,
  algorithm: 'HS256', // Faster for tests
  secretKey: 'test-secret-key-for-testing-only',
  defaultExpirations: {
    accessToken: '1m',
    refreshToken: '5m',
    resetPasswordToken: '5m',
    emailVerificationToken: '5m',
  },
  blacklist: {
    enabled: false,
    cleanupInterval: 0,
    maxSize: 0,
  },
  security: {
    includeJti: false,
    validateNotBefore: false,
    clockTolerance: 300, // 5 minutes for test stability
  },
};

/**
 * Get JWT configuration based on environment
 * @param environment - Current environment (development, production, test)
 * @returns Appropriate configuration for the environment
 */
export function getJwtConfig(environment: string = 'development'): JwtConfig {
  switch (environment.toLowerCase()) {
    case 'production':
    case 'prod':
      return PRODUCTION_JWT_CONFIG;
    
    case 'development':
    case 'dev':
      return DEVELOPMENT_JWT_CONFIG;
    
    case 'test':
    case 'testing':
      return TEST_JWT_CONFIG;
    
    default:
      return DEFAULT_JWT_CONFIG;
  }
}

/**
 * Validate JWT configuration
 * @param config - Configuration to validate
 * @throws Error if configuration is invalid
 */
export function validateJwtConfig(config: JwtConfig): void {
  // Algorithm validation
  if (!['RS256', 'HS256'].includes(config.algorithm)) {
    throw new Error('JWT algorithm must be RS256 or HS256');
  }

  // Key validation
  if (config.algorithm === 'RS256') {
    if (!config.privateKey || !config.publicKey) {
      throw new Error('RS256 algorithm requires both privateKey and publicKey');
    }
  } else if (config.algorithm === 'HS256') {
    if (!config.secretKey) {
      throw new Error('HS256 algorithm requires secretKey');
    }
    if (config.secretKey.length < 32) {
      throw new Error('Secret key must be at least 32 characters long');
    }
  }

  // Issuer and audience validation
  if (!config.issuer || config.issuer.trim().length === 0) {
    throw new Error('Issuer is required and cannot be empty');
  }

  if (!config.audience || config.audience.trim().length === 0) {
    throw new Error('Audience is required and cannot be empty');
  }

  // Expiration validation
  const expirationRegex = /^\d+[smhd]$/;
  Object.entries(config.defaultExpirations).forEach(([key, value]) => {
    if (!expirationRegex.test(value)) {
      throw new Error(`Invalid expiration format for ${key}: ${value}`);
    }
  });

  Object.entries(config.maxTokenLifetime).forEach(([key, value]) => {
    if (!expirationRegex.test(value)) {
      throw new Error(`Invalid max lifetime format for ${key}: ${value}`);
    }
  });

  // Security settings validation
  if (config.security.clockTolerance < 0) {
    throw new Error('Clock tolerance cannot be negative');
  }

  if (config.security.clockTolerance > 300) {
    throw new Error('Clock tolerance should not exceed 5 minutes for security');
  }

  // Blacklist settings validation
  if (config.blacklist.enabled) {
    if (config.blacklist.maxSize <= 0) {
      throw new Error('Blacklist max size must be positive when blacklist is enabled');
    }
    
    if (config.blacklist.cleanupInterval <= 0) {
      throw new Error('Blacklist cleanup interval must be positive when blacklist is enabled');
    }
  }
}

/**
 * Parse expiration string to milliseconds
 * @param expiration - Expiration string (e.g., '15m', '7d')
 * @returns Expiration time in milliseconds
 */
export function parseExpirationToMs(expiration: string): number {
  const match = expiration.match(/^(\d+)([smhd])$/);
  if (!match) {
    throw new Error(`Invalid expiration format: ${expiration}`);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 's':
      return value * 1000;
    case 'm':
      return value * 60 * 1000;
    case 'h':
      return value * 60 * 60 * 1000;
    case 'd':
      return value * 24 * 60 * 60 * 1000;
    default:
      throw new Error(`Invalid expiration unit: ${unit}`);
  }
}