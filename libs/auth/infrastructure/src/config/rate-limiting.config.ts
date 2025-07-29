import { RateLimiterOptions } from '../middleware/rate-limiting.middleware';

export interface RateLimitingConfig {
  // Global rate limiting
  global: RateLimiterOptions;
  
  // Authentication endpoint specific limits
  auth: {
    login: RateLimiterOptions;
    register: RateLimiterOptions;
    refresh: RateLimiterOptions;
    socialAuth: RateLimiterOptions;
  };
  
  // Progressive delays for failed attempts
  progressive: {
    enabled: boolean;
    maxAttempts: number;
    baseDelay: number; // milliseconds
    maxDelay: number; // milliseconds
    resetTime: number; // seconds
  };
  
  // IP-based blocking
  ipBlocking: {
    enabled: boolean;
    maxFailures: number;
    blockDuration: number; // seconds
    whitelist: string[];
  };
  
  // User-based rate limiting
  userBased: {
    enabled: boolean;
    maxAttempts: number;
    windowSize: number; // seconds
    penaltyDuration: number; // seconds
  };
}

/**
 * Get rate limiting configuration based on environment
 */
export function getRateLimitingConfig(): RateLimitingConfig {
  const nodeEnv = process.env['NODE_ENV'] || 'development';
  
  // Base configuration
  const baseConfig: RateLimitingConfig = {
    global: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 1000, // Limit each IP to 1000 requests per windowMs
      message: 'Too many requests from this IP, please try again later.',
      standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
      legacyHeaders: false, // Disable the `X-RateLimit-*` headers
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
    },
    
    auth: {
      login: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        maxRequests: 5, // Limit each IP to 5 login requests per windowMs
        message: 'Too many login attempts, please try again later.',
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: true, // Don't count successful requests
        skipFailedRequests: false,
      },
      
      register: {
        windowMs: 60 * 60 * 1000, // 1 hour
        maxRequests: 3, // Limit each IP to 3 registrations per hour
        message: 'Too many registration attempts, please try again later.',
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: true,
        skipFailedRequests: false,
      },
      
      refresh: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        maxRequests: 50, // Limit each IP to 50 refresh requests per windowMs
        message: 'Too many token refresh requests, please try again later.',
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: true,
        skipFailedRequests: false,
      },
      
      socialAuth: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        maxRequests: 10, // Limit each IP to 10 social auth requests per windowMs
        message: 'Too many social authentication attempts, please try again later.',
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: true,
        skipFailedRequests: false,
      },
    },
    
    progressive: {
      enabled: true,
      maxAttempts: 5,
      baseDelay: 1000, // 1 second
      maxDelay: 30000, // 30 seconds
      resetTime: 900, // 15 minutes
    },
    
    ipBlocking: {
      enabled: true,
      maxFailures: 10,
      blockDuration: 3600, // 1 hour
      whitelist: ['127.0.0.1', '::1'], // localhost
    },
    
    userBased: {
      enabled: true,
      maxAttempts: 5,
      windowSize: 900, // 15 minutes
      penaltyDuration: 1800, // 30 minutes
    },
  };

  // Environment-specific overrides
  switch (nodeEnv) {
    case 'production':
      return {
        ...baseConfig,
        auth: {
          ...baseConfig.auth,
          login: {
            ...baseConfig.auth.login,
            maxRequests: 3, // More restrictive in production
          },
          register: {
            ...baseConfig.auth.register,
            maxRequests: 2, // More restrictive in production
          },
        },
        progressive: {
          ...baseConfig.progressive,
          maxAttempts: 3, // More restrictive in production
          maxDelay: 60000, // 1 minute max delay
        },
        ipBlocking: {
          ...baseConfig.ipBlocking,
          maxFailures: 5, // More restrictive in production
          blockDuration: 7200, // 2 hours
        },
      };
      
    case 'test':
      return {
        ...baseConfig,
        global: {
          ...baseConfig.global,
          windowMs: 1000, // 1 second for testing
          maxRequests: 1000,
        },
        auth: {
          login: {
            ...baseConfig.auth.login,
            windowMs: 1000, // 1 second for testing
            maxRequests: 100,
          },
          register: {
            ...baseConfig.auth.register,
            windowMs: 1000, // 1 second for testing
            maxRequests: 100,
          },
          refresh: {
            ...baseConfig.auth.refresh,
            windowMs: 1000, // 1 second for testing
            maxRequests: 100,
          },
          socialAuth: {
            ...baseConfig.auth.socialAuth,
            windowMs: 1000, // 1 second for testing
            maxRequests: 100,
          },
        },
        progressive: {
          ...baseConfig.progressive,
          baseDelay: 10, // Very short delays for testing
          maxDelay: 100,
          resetTime: 1, // 1 second
        },
        ipBlocking: {
          ...baseConfig.ipBlocking,
          blockDuration: 1, // 1 second for testing
        },
        userBased: {
          ...baseConfig.userBased,
          windowSize: 1, // 1 second for testing
          penaltyDuration: 1, // 1 second for testing
        },
      };
      
    case 'development':
    default:
      return {
        ...baseConfig,
        auth: {
          ...baseConfig.auth,
          login: {
            ...baseConfig.auth.login,
            maxRequests: 10, // More lenient in development
          },
          register: {
            ...baseConfig.auth.register,
            maxRequests: 5, // More lenient in development
          },
        },
        progressive: {
          ...baseConfig.progressive,
          enabled: false, // Disable in development for easier testing
        },
        ipBlocking: {
          ...baseConfig.ipBlocking,
          enabled: false, // Disable in development
        },
      };
  }
}

/**
 * Validate rate limiting configuration
 */
export function validateRateLimitingConfig(config: RateLimitingConfig): void {
  // Validate global config
  if (config.global.windowMs <= 0) {
    throw new Error('Global window size must be positive');
  }
  if (config.global.maxRequests <= 0) {
    throw new Error('Global max requests must be positive');
  }

  // Validate auth configs
  Object.entries(config.auth).forEach(([endpoint, opts]) => {
    if (opts.windowMs <= 0) {
      throw new Error(`${endpoint} window size must be positive`);
    }
    if (opts.maxRequests <= 0) {
      throw new Error(`${endpoint} max requests must be positive`);
    }
  });

  // Validate progressive config
  if (config.progressive.enabled) {
    if (config.progressive.maxAttempts <= 0) {
      throw new Error('Progressive max attempts must be positive');
    }
    if (config.progressive.baseDelay <= 0) {
      throw new Error('Progressive base delay must be positive');
    }
    if (config.progressive.maxDelay <= config.progressive.baseDelay) {
      throw new Error('Progressive max delay must be greater than base delay');
    }
    if (config.progressive.resetTime <= 0) {
      throw new Error('Progressive reset time must be positive');
    }
  }

  // Validate IP blocking config
  if (config.ipBlocking.enabled) {
    if (config.ipBlocking.maxFailures <= 0) {
      throw new Error('IP blocking max failures must be positive');
    }
    if (config.ipBlocking.blockDuration <= 0) {
      throw new Error('IP blocking duration must be positive');
    }
  }

  // Validate user-based config
  if (config.userBased.enabled) {
    if (config.userBased.maxAttempts <= 0) {
      throw new Error('User-based max attempts must be positive');
    }
    if (config.userBased.windowSize <= 0) {
      throw new Error('User-based window size must be positive');
    }
    if (config.userBased.penaltyDuration <= 0) {
      throw new Error('User-based penalty duration must be positive');
    }
  }
}