/**
 * Password Hashing Configuration
 * 
 * Centralized configuration for password hashing security settings.
 * These values should be environment-specific and regularly reviewed.
 */
export interface PasswordHashingConfig {
  /**
   * Default number of salt rounds for password hashing
   * Higher values provide better security but slower performance
   * Recommended: 12-14 for current security standards
   */
  defaultSaltRounds: number;

  /**
   * Minimum allowed salt rounds
   * Prevents using insecure low values
   */
  minSaltRounds: number;

  /**
   * Maximum allowed salt rounds
   * Prevents performance issues from excessive values
   */
  maxSaltRounds: number;

  /**
   * Whether to automatically rehash passwords with outdated rounds
   * When true, passwords are rehashed on successful login if needed
   */
  autoRehash: boolean;

  /**
   * Maximum password length allowed
   * Prevents DoS attacks through extremely long passwords
   */
  maxPasswordLength: number;
}

/**
 * Default password hashing configuration
 * Based on current security best practices (2024)
 */
export const DEFAULT_PASSWORD_HASHING_CONFIG: PasswordHashingConfig = {
  defaultSaltRounds: 12,
  minSaltRounds: 10,
  maxSaltRounds: 16,
  autoRehash: true,
  maxPasswordLength: 128,
};

/**
 * Development password hashing configuration
 * Lower security for faster development cycles
 */
export const DEVELOPMENT_PASSWORD_HASHING_CONFIG: PasswordHashingConfig = {
  defaultSaltRounds: 10,
  minSaltRounds: 10,
  maxSaltRounds: 12,
  autoRehash: false,
  maxPasswordLength: 128,
};

/**
 * Production password hashing configuration
 * Enhanced security for production environments
 */
export const PRODUCTION_PASSWORD_HASHING_CONFIG: PasswordHashingConfig = {
  defaultSaltRounds: 14,
  minSaltRounds: 12,
  maxSaltRounds: 16,
  autoRehash: true,
  maxPasswordLength: 128,
};

/**
 * Get password hashing configuration based on environment
 * @param environment - Current environment (development, production, test)
 * @returns Appropriate configuration for the environment
 */
export function getPasswordHashingConfig(environment: string = 'development'): PasswordHashingConfig {
  switch (environment.toLowerCase()) {
    case 'production':
    case 'prod':
      return PRODUCTION_PASSWORD_HASHING_CONFIG;
    
    case 'development':
    case 'dev':
      return DEVELOPMENT_PASSWORD_HASHING_CONFIG;
    
    case 'test':
    case 'testing':
      // Use development config for testing (faster execution)
      return DEVELOPMENT_PASSWORD_HASHING_CONFIG;
    
    default:
      return DEFAULT_PASSWORD_HASHING_CONFIG;
  }
}

/**
 * Validate password hashing configuration
 * @param config - Configuration to validate
 * @throws Error if configuration is invalid
 */
export function validatePasswordHashingConfig(config: PasswordHashingConfig): void {
  if (config.defaultSaltRounds < config.minSaltRounds) {
    throw new Error('Default salt rounds cannot be less than minimum salt rounds');
  }

  if (config.defaultSaltRounds > config.maxSaltRounds) {
    throw new Error('Default salt rounds cannot be greater than maximum salt rounds');
  }

  if (config.minSaltRounds < 8) {
    throw new Error('Minimum salt rounds must be at least 8 for basic security');
  }

  if (config.maxSaltRounds > 20) {
    throw new Error('Maximum salt rounds should not exceed 20 for performance reasons');
  }

  if (config.maxPasswordLength < 8) {
    throw new Error('Maximum password length must be at least 8 characters');
  }

  if (config.maxPasswordLength > 1024) {
    throw new Error('Maximum password length should not exceed 1024 characters');
  }
}