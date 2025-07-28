import { Token } from '../../entities/token.entity';
import { TokenType } from '@auth/shared';

/**
 * TokenRepository Port Interface
 * 
 * This interface defines the contract for token data persistence.
 * Infrastructure layer must implement this interface.
 */
export interface TokenRepository {
  /**
   * Find a token by its unique ID
   * @param id - Token's unique identifier
   * @returns Token entity if found, null otherwise
   */
  findById(id: string): Promise<Token | null>;

  /**
   * Find a token by its value
   * @param value - Token value
   * @returns Token entity if found, null otherwise
   */
  findByValue(value: string): Promise<Token | null>;

  /**
   * Find all tokens for a specific user
   * @param userId - User's unique identifier
   * @returns Array of tokens belonging to the user
   */
  findByUserId(userId: string): Promise<Token[]>;

  /**
   * Find tokens by user ID and type
   * @param userId - User's unique identifier
   * @param type - Token type
   * @returns Array of tokens matching the criteria
   */
  findByUserIdAndType(userId: string, type: TokenType): Promise<Token[]>;

  /**
   * Save a new token or update an existing one
   * @param token - Token entity to save
   * @returns Saved token entity
   */
  save(token: Token): Promise<Token>;

  /**
   * Delete a token by its ID
   * @param id - Token's unique identifier
   * @returns True if deleted, false if not found
   */
  delete(id: string): Promise<boolean>;

  /**
   * Delete all tokens for a specific user
   * @param userId - User's unique identifier
   * @returns Number of tokens deleted
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Delete all tokens of a specific type for a user
   * @param userId - User's unique identifier
   * @param type - Token type to delete
   * @returns Number of tokens deleted
   */
  deleteByUserIdAndType(userId: string, type: TokenType): Promise<number>;

  /**
   * Find all expired tokens
   * @returns Array of expired tokens
   */
  findExpired(): Promise<Token[]>;

  /**
   * Delete all expired tokens
   * @returns Number of tokens deleted
   */
  deleteExpired(): Promise<number>;

  /**
   * Revoke a token by its value
   * @param value - Token value to revoke
   * @returns True if revoked, false if not found
   */
  revokeByValue(value: string): Promise<boolean>;

  /**
   * Revoke all tokens for a specific user
   * @param userId - User's unique identifier
   * @returns Number of tokens revoked
   */
  revokeByUserId(userId: string): Promise<number>;

  /**
   * Check if a token exists and is valid
   * @param value - Token value
   * @returns True if token exists and is valid, false otherwise
   */
  isValidToken(value: string): Promise<boolean>;

  /**
   * Count tokens by type
   * @param type - Token type
   * @returns Count of tokens of the specified type
   */
  countByType(type: TokenType): Promise<number>;

  /**
   * Clean up old tokens (expired and revoked)
   * @param olderThan - Date threshold
   * @returns Number of tokens cleaned up
   */
  cleanup(olderThan: Date): Promise<number>;
}