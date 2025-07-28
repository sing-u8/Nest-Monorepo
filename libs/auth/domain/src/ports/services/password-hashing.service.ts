/**
 * PasswordHashingService Port Interface
 * 
 * This interface defines the contract for password hashing operations.
 * Infrastructure layer must implement this interface using bcrypt or similar.
 */
export interface PasswordHashingService {
  /**
   * Hash a plain text password
   * @param plainPassword - Plain text password
   * @param saltRounds - Number of salt rounds (default: 12)
   * @returns Hashed password
   */
  hash(plainPassword: string, saltRounds?: number): Promise<string>;

  /**
   * Compare a plain text password with a hashed password
   * @param plainPassword - Plain text password
   * @param hashedPassword - Hashed password to compare against
   * @returns True if passwords match, false otherwise
   */
  compare(plainPassword: string, hashedPassword: string): Promise<boolean>;

  /**
   * Generate a secure random salt
   * @param rounds - Number of rounds (default: 12)
   * @returns Generated salt
   */
  generateSalt(rounds?: number): Promise<string>;

  /**
   * Hash a password with a specific salt
   * @param plainPassword - Plain text password
   * @param salt - Salt to use for hashing
   * @returns Hashed password
   */
  hashWithSalt(plainPassword: string, salt: string): Promise<string>;

  /**
   * Get the number of rounds used in a hash
   * @param hashedPassword - Hashed password
   * @returns Number of rounds used
   */
  getRounds(hashedPassword: string): number;

  /**
   * Check if a password needs to be rehashed (e.g., due to updated security requirements)
   * @param hashedPassword - Current hashed password
   * @param currentRounds - Current required rounds
   * @returns True if rehashing is needed, false otherwise
   */
  needsRehash(hashedPassword: string, currentRounds: number): boolean;
}