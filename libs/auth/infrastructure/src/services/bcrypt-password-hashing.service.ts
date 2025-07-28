import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PasswordHashingService } from '@auth/domain';

/**
 * Bcrypt Password Hashing Service Implementation
 * 
 * Implements the PasswordHashingService port interface using bcrypt for secure password hashing.
 * Provides industry-standard password security with configurable salt rounds.
 */
@Injectable()
export class BcryptPasswordHashingService implements PasswordHashingService {
  private readonly DEFAULT_SALT_ROUNDS = 12;
  private readonly MIN_SALT_ROUNDS = 10;
  private readonly MAX_SALT_ROUNDS = 16;

  /**
   * Hash a plain text password using bcrypt
   * @param plainPassword - Plain text password to hash
   * @param saltRounds - Number of salt rounds (default: 12)
   * @returns Promise resolving to hashed password
   */
  async hash(plainPassword: string, saltRounds?: number): Promise<string> {
    try {
      // Validate input
      this.validatePassword(plainPassword);
      
      // Validate and set salt rounds
      const rounds = this.validateSaltRounds(saltRounds);
      
      // Hash the password with bcrypt
      const hashedPassword = await bcrypt.hash(plainPassword, rounds);
      
      return hashedPassword;
    } catch (error) {
      console.error('Error hashing password:', error);
      throw new Error('Failed to hash password');
    }
  }

  /**
   * Compare a plain text password with a hashed password
   * @param plainPassword - Plain text password to verify
   * @param hashedPassword - Hashed password to compare against
   * @returns Promise resolving to true if passwords match, false otherwise
   */
  async compare(plainPassword: string, hashedPassword: string): Promise<boolean> {
    try {
      // Validate inputs
      this.validatePassword(plainPassword);
      this.validateHashedPassword(hashedPassword);
      
      // Compare passwords using bcrypt
      const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
      
      return isMatch;
    } catch (error) {
      console.error('Error comparing passwords:', error);
      // Return false for security - don't expose comparison errors
      return false;
    }
  }

  /**
   * Generate a secure random salt
   * @param rounds - Number of rounds (default: 12)
   * @returns Promise resolving to generated salt
   */
  async generateSalt(rounds?: number): Promise<string> {
    try {
      // Validate and set salt rounds
      const saltRounds = this.validateSaltRounds(rounds);
      
      // Generate salt with bcrypt
      const salt = await bcrypt.genSalt(saltRounds);
      
      return salt;
    } catch (error) {
      console.error('Error generating salt:', error);
      throw new Error('Failed to generate salt');
    }
  }

  /**
   * Hash a password with a specific salt
   * @param plainPassword - Plain text password to hash
   * @param salt - Salt to use for hashing
   * @returns Promise resolving to hashed password
   */
  async hashWithSalt(plainPassword: string, salt: string): Promise<string> {
    try {
      // Validate inputs
      this.validatePassword(plainPassword);
      this.validateSalt(salt);
      
      // Hash password with provided salt
      const hashedPassword = await bcrypt.hash(plainPassword, salt);
      
      return hashedPassword;
    } catch (error) {
      console.error('Error hashing password with salt:', error);
      throw new Error('Failed to hash password with salt');
    }
  }

  /**
   * Get the number of rounds used in a bcrypt hash
   * @param hashedPassword - Hashed password to analyze
   * @returns Number of rounds used in the hash
   */
  getRounds(hashedPassword: string): number {
    try {
      // Validate hashed password format
      this.validateHashedPassword(hashedPassword);
      
      // Extract rounds from bcrypt hash
      // Bcrypt hash format: $2a$rounds$salthash
      const rounds = bcrypt.getRounds(hashedPassword);
      
      return rounds;
    } catch (error) {
      console.error('Error getting rounds from hash:', error);
      throw new Error('Failed to get rounds from hashed password');
    }
  }

  /**
   * Check if a password needs to be rehashed due to updated security requirements
   * @param hashedPassword - Current hashed password
   * @param currentRounds - Current required rounds
   * @returns True if rehashing is needed, false otherwise
   */
  needsRehash(hashedPassword: string, currentRounds: number): boolean {
    try {
      // Validate inputs
      this.validateHashedPassword(hashedPassword);
      this.validateSaltRounds(currentRounds);
      
      // Get rounds from existing hash
      const existingRounds = this.getRounds(hashedPassword);
      
      // Check if rehashing is needed
      // Rehash if current rounds are higher than existing rounds
      return existingRounds < currentRounds;
    } catch (error) {
      console.error('Error checking rehash requirement:', error);
      // Return true for security - prefer rehashing on error
      return true;
    }
  }

  /**
   * Validate plain text password input
   * @param password - Password to validate
   */
  private validatePassword(password: string): void {
    if (!password) {
      throw new Error('Password is required');
    }

    if (typeof password !== 'string') {
      throw new Error('Password must be a string');
    }

    if (password.length === 0) {
      throw new Error('Password cannot be empty');
    }

    if (password.length > 128) {
      throw new Error('Password length cannot exceed 128 characters');
    }
  }

  /**
   * Validate hashed password format
   * @param hashedPassword - Hashed password to validate
   */
  private validateHashedPassword(hashedPassword: string): void {
    if (!hashedPassword) {
      throw new Error('Hashed password is required');
    }

    if (typeof hashedPassword !== 'string') {
      throw new Error('Hashed password must be a string');
    }

    // Basic bcrypt hash format validation
    // Bcrypt hash should start with $2a$, $2b$, or $2y$ and have proper structure
    const bcryptPattern = /^\$2[aby]\$\d{2}\$.{53}$/;
    if (!bcryptPattern.test(hashedPassword)) {
      throw new Error('Invalid bcrypt hash format');
    }
  }

  /**
   * Validate salt format
   * @param salt - Salt to validate
   */
  private validateSalt(salt: string): void {
    if (!salt) {
      throw new Error('Salt is required');
    }

    if (typeof salt !== 'string') {
      throw new Error('Salt must be a string');
    }

    // Basic bcrypt salt format validation
    // Bcrypt salt should start with $2a$, $2b$, or $2y$ and have rounds info
    const saltPattern = /^\$2[aby]\$\d{2}\$.{22}$/;
    if (!saltPattern.test(salt)) {
      throw new Error('Invalid bcrypt salt format');
    }
  }

  /**
   * Validate and normalize salt rounds
   * @param saltRounds - Salt rounds to validate
   * @returns Validated salt rounds
   */
  private validateSaltRounds(saltRounds?: number): number {
    // Use default if not provided
    if (saltRounds === undefined || saltRounds === null) {
      return this.DEFAULT_SALT_ROUNDS;
    }

    // Validate type
    if (typeof saltRounds !== 'number' || !Number.isInteger(saltRounds)) {
      throw new Error('Salt rounds must be a positive integer');
    }

    // Validate range
    if (saltRounds < this.MIN_SALT_ROUNDS) {
      throw new Error(`Salt rounds must be at least ${this.MIN_SALT_ROUNDS} for security`);
    }

    if (saltRounds > this.MAX_SALT_ROUNDS) {
      throw new Error(`Salt rounds cannot exceed ${this.MAX_SALT_ROUNDS} for performance`);
    }

    return saltRounds;
  }

  /**
   * Get recommended salt rounds for current security standards
   * @returns Recommended salt rounds
   */
  getRecommendedRounds(): number {
    return this.DEFAULT_SALT_ROUNDS;
  }

  /**
   * Check if the service is available and functioning
   * @returns Promise resolving to true if service is healthy
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Perform a quick hash operation to verify bcrypt is working
      const testPassword = 'health-check-test';
      const testHash = await this.hash(testPassword, 10); // Use minimum rounds for speed
      const testResult = await this.compare(testPassword, testHash);
      
      return testResult === true;
    } catch (error) {
      console.error('Password hashing service health check failed:', error);
      return false;
    }
  }

  /**
   * Get service configuration information
   * @returns Service configuration details
   */
  getConfiguration(): {
    defaultRounds: number;
    minRounds: number;
    maxRounds: number;
    algorithm: string;
  } {
    return {
      defaultRounds: this.DEFAULT_SALT_ROUNDS,
      minRounds: this.MIN_SALT_ROUNDS,
      maxRounds: this.MAX_SALT_ROUNDS,
      algorithm: 'bcrypt',
    };
  }
}