/**
 * OAuth Configuration
 * 
 * Centralized configuration for OAuth providers (Google and Apple).
 * These values should be environment-specific and securely managed.
 */

export interface GoogleOAuthConfig {
  /**
   * Google OAuth 2.0 client ID
   * Obtained from Google Cloud Console
   */
  clientId: string;

  /**
   * Google OAuth 2.0 client secret
   * Obtained from Google Cloud Console
   */
  clientSecret: string;

  /**
   * Redirect URI for Google OAuth callback
   * Must be registered in Google Cloud Console
   */
  redirectUri: string;

  /**
   * OAuth scopes to request
   */
  scopes: string[];

  /**
   * Additional OAuth parameters
   */
  options: {
    /**
     * Access type for offline access (refresh tokens)
     */
    accessType: 'online' | 'offline';

    /**
     * Prompt parameter for consent screen
     */
    prompt?: 'none' | 'consent' | 'select_account';

    /**
     * Include granted scopes in subsequent requests
     */
    includeGrantedScopes: boolean;
  };
}

export interface AppleOAuthConfig {
  /**
   * Apple Sign In service ID (client ID)
   * Obtained from Apple Developer Console
   */
  clientId: string;

  /**
   * Apple Developer Team ID
   * 10-character team identifier
   */
  teamId: string;

  /**
   * Apple Sign In key ID
   * Key identifier for the private key
   */
  keyId: string;

  /**
   * Apple Sign In private key (PEM format)
   * ES256 private key for signing client secrets
   */
  privateKey: string;

  /**
   * Redirect URI for Apple Sign In callback
   * Must be registered in Apple Developer Console
   */
  redirectUri: string;

  /**
   * OAuth scopes to request
   */
  scopes: string[];

  /**
   * Additional Apple Sign In options
   */
  options: {
    /**
     * Response type for authorization
     */
    responseType: string;

    /**
     * Response mode for handling callback
     */
    responseMode: 'query' | 'form_post';

    /**
     * Client secret expiration time (in seconds)
     */
    clientSecretExpiration: number;
  };
}

export interface OAuthConfig {
  google: GoogleOAuthConfig;
  apple: AppleOAuthConfig;
}

/**
 * Default Google OAuth configuration
 */
export const DEFAULT_GOOGLE_OAUTH_CONFIG: GoogleOAuthConfig = {
  clientId: process.env.GOOGLE_CLIENT_ID || '',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
  redirectUri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback',
  scopes: [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
  ],
  options: {
    accessType: 'offline',
    prompt: 'consent',
    includeGrantedScopes: true,
  },
};

/**
 * Default Apple OAuth configuration
 */
export const DEFAULT_APPLE_OAUTH_CONFIG: AppleOAuthConfig = {
  clientId: process.env.APPLE_CLIENT_ID || '',
  teamId: process.env.APPLE_TEAM_ID || '',
  keyId: process.env.APPLE_KEY_ID || '',
  privateKey: process.env.APPLE_PRIVATE_KEY || '',
  redirectUri: process.env.APPLE_REDIRECT_URI || 'http://localhost:3000/auth/apple/callback',
  scopes: ['name', 'email'],
  options: {
    responseType: 'code id_token',
    responseMode: 'form_post',
    clientSecretExpiration: 3600, // 1 hour
  },
};

/**
 * Default OAuth configuration
 */
export const DEFAULT_OAUTH_CONFIG: OAuthConfig = {
  google: DEFAULT_GOOGLE_OAUTH_CONFIG,
  apple: DEFAULT_APPLE_OAUTH_CONFIG,
};

/**
 * Development OAuth configuration
 * Relaxed settings for development
 */
export const DEVELOPMENT_OAUTH_CONFIG: OAuthConfig = {
  google: {
    ...DEFAULT_GOOGLE_OAUTH_CONFIG,
    redirectUri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback',
  },
  apple: {
    ...DEFAULT_APPLE_OAUTH_CONFIG,
    redirectUri: process.env.APPLE_REDIRECT_URI || 'http://localhost:3000/auth/apple/callback',
    options: {
      ...DEFAULT_APPLE_OAUTH_CONFIG.options,
      clientSecretExpiration: 7200, // 2 hours for development
    },
  },
};

/**
 * Production OAuth configuration
 * Enhanced security for production
 */
export const PRODUCTION_OAUTH_CONFIG: OAuthConfig = {
  google: {
    ...DEFAULT_GOOGLE_OAUTH_CONFIG,
    redirectUri: process.env.GOOGLE_REDIRECT_URI || 'https://your-domain.com/auth/google/callback',
    options: {
      ...DEFAULT_GOOGLE_OAUTH_CONFIG.options,
      prompt: 'consent', // Always show consent screen
    },
  },
  apple: {
    ...DEFAULT_APPLE_OAUTH_CONFIG,
    redirectUri: process.env.APPLE_REDIRECT_URI || 'https://your-domain.com/auth/apple/callback',
    options: {
      ...DEFAULT_APPLE_OAUTH_CONFIG.options,
      clientSecretExpiration: 1800, // 30 minutes for production
    },
  },
};

/**
 * Test OAuth configuration
 * Mock settings for testing
 */
export const TEST_OAUTH_CONFIG: OAuthConfig = {
  google: {
    clientId: 'test-google-client-id.googleusercontent.com',
    clientSecret: 'test-google-client-secret',
    redirectUri: 'http://localhost:3000/auth/google/callback',
    scopes: ['email', 'profile'],
    options: {
      accessType: 'offline',
      includeGrantedScopes: false,
    },
  },
  apple: {
    clientId: 'com.test.app',
    teamId: 'TEST123456',
    keyId: 'TEST987654',
    privateKey: `-----BEGIN EC PRIVATE KEY-----
TEST_PRIVATE_KEY_CONTENT
-----END EC PRIVATE KEY-----`,
    redirectUri: 'http://localhost:3000/auth/apple/callback',
    scopes: ['name', 'email'],
    options: {
      responseType: 'code id_token',
      responseMode: 'form_post',
      clientSecretExpiration: 7200, // 2 hours for tests
    },
  },
};

/**
 * Get OAuth configuration based on environment
 * @param environment - Current environment (development, production, test)
 * @returns Appropriate configuration for the environment
 */
export function getOAuthConfig(environment: string = 'development'): OAuthConfig {
  switch (environment.toLowerCase()) {
    case 'production':
    case 'prod':
      return PRODUCTION_OAUTH_CONFIG;
    
    case 'development':
    case 'dev':
      return DEVELOPMENT_OAUTH_CONFIG;
    
    case 'test':
    case 'testing':
      return TEST_OAUTH_CONFIG;
    
    default:
      return DEFAULT_OAUTH_CONFIG;
  }
}

/**
 * Validate OAuth configuration
 * @param config - Configuration to validate
 * @throws Error if configuration is invalid
 */
export function validateOAuthConfig(config: OAuthConfig): void {
  // Validate Google OAuth configuration
  validateGoogleOAuthConfig(config.google);
  
  // Validate Apple OAuth configuration
  validateAppleOAuthConfig(config.apple);
}

/**
 * Validate Google OAuth configuration
 * @param config - Google OAuth configuration to validate
 * @throws Error if configuration is invalid
 */
export function validateGoogleOAuthConfig(config: GoogleOAuthConfig): void {
  if (!config.clientId || config.clientId.trim().length === 0) {
    throw new Error('Google OAuth client ID is required');
  }

  if (!config.clientId.endsWith('.googleusercontent.com')) {
    throw new Error('Invalid Google OAuth client ID format');
  }

  if (!config.clientSecret || config.clientSecret.trim().length === 0) {
    throw new Error('Google OAuth client secret is required');
  }

  if (!config.redirectUri || config.redirectUri.trim().length === 0) {
    throw new Error('Google OAuth redirect URI is required');
  }

  try {
    new URL(config.redirectUri);
  } catch (error) {
    throw new Error('Invalid Google OAuth redirect URI format');
  }

  if (!config.scopes || config.scopes.length === 0) {
    throw new Error('Google OAuth scopes are required');
  }

  // Validate required scopes
  const requiredScopes = ['email'];
  const hasRequiredScopes = requiredScopes.every(scope => 
    config.scopes.some(configScope => configScope.includes(scope))
  );

  if (!hasRequiredScopes) {
    throw new Error('Google OAuth configuration must include email scope');
  }

  // Validate access type
  if (!['online', 'offline'].includes(config.options.accessType)) {
    throw new Error('Google OAuth access type must be "online" or "offline"');
  }
}

/**
 * Validate Apple OAuth configuration
 * @param config - Apple OAuth configuration to validate
 * @throws Error if configuration is invalid
 */
export function validateAppleOAuthConfig(config: AppleOAuthConfig): void {
  if (!config.clientId || config.clientId.trim().length === 0) {
    throw new Error('Apple OAuth client ID is required');
  }

  if (!config.teamId || config.teamId.trim().length === 0) {
    throw new Error('Apple OAuth team ID is required');
  }

  if (config.teamId.length !== 10) {
    throw new Error('Apple OAuth team ID must be 10 characters long');
  }

  if (!config.keyId || config.keyId.trim().length === 0) {
    throw new Error('Apple OAuth key ID is required');
  }

  if (config.keyId.length !== 10) {
    throw new Error('Apple OAuth key ID must be 10 characters long');
  }

  if (!config.privateKey || config.privateKey.trim().length === 0) {
    throw new Error('Apple OAuth private key is required');
  }

  if (!config.privateKey.includes('BEGIN PRIVATE KEY') && !config.privateKey.includes('BEGIN EC PRIVATE KEY')) {
    throw new Error('Apple OAuth private key must be in PEM format');
  }

  if (!config.redirectUri || config.redirectUri.trim().length === 0) {
    throw new Error('Apple OAuth redirect URI is required');
  }

  try {
    new URL(config.redirectUri);
  } catch (error) {
    throw new Error('Invalid Apple OAuth redirect URI format');
  }

  if (!config.scopes || config.scopes.length === 0) {
    throw new Error('Apple OAuth scopes are required');
  }

  // Validate required scopes
  if (!config.scopes.includes('email')) {
    throw new Error('Apple OAuth configuration must include email scope');
  }

  // Validate response mode
  if (!['query', 'form_post'].includes(config.options.responseMode)) {
    throw new Error('Apple OAuth response mode must be "query" or "form_post"');
  }

  // Validate client secret expiration
  if (config.options.clientSecretExpiration <= 0 || config.options.clientSecretExpiration > 86400) {
    throw new Error('Apple OAuth client secret expiration must be between 1 and 86400 seconds');
  }
}

/**
 * Environment variable validation helper
 * @param environment - Current environment
 * @returns List of missing required environment variables
 */
export function validateOAuthEnvironmentVariables(environment: string = 'development'): string[] {
  const missing: string[] = [];

  if (environment !== 'test') {
    // Google OAuth environment variables
    if (!process.env.GOOGLE_CLIENT_ID) {
      missing.push('GOOGLE_CLIENT_ID');
    }
    if (!process.env.GOOGLE_CLIENT_SECRET) {
      missing.push('GOOGLE_CLIENT_SECRET');
    }

    // Apple OAuth environment variables
    if (!process.env.APPLE_CLIENT_ID) {
      missing.push('APPLE_CLIENT_ID');
    }
    if (!process.env.APPLE_TEAM_ID) {
      missing.push('APPLE_TEAM_ID');
    }
    if (!process.env.APPLE_KEY_ID) {
      missing.push('APPLE_KEY_ID');
    }
    if (!process.env.APPLE_PRIVATE_KEY) {
      missing.push('APPLE_PRIVATE_KEY');
    }
  }

  return missing;
}