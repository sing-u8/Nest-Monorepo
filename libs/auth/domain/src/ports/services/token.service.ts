import { TokenType, JwtPayload, TokenValidationResult } from '@auth/shared';

/**
 * TokenService Port Interface
 * 
 * This interface defines the contract for JWT token operations.
 * Infrastructure layer must implement this interface using jsonwebtoken or similar.
 */
export interface TokenService {
  /**
   * Generate a JWT token
   * @param payload - Token payload
   * @param type - Token type
   * @param expiresIn - Token expiration time (e.g., '15m', '7d')
   * @returns Generated JWT token
   */
  generateToken(
    payload: JwtPayload,
    type: TokenType,
    expiresIn: string
  ): Promise<string>;

  /**
   * Generate an access token
   * @param userId - User's unique identifier
   * @param email - User's email
   * @param expiresIn - Token expiration time (default: '15m')
   * @returns Generated access token
   */
  generateAccessToken(
    userId: string,
    email: string,
    expiresIn?: string
  ): Promise<string>;

  /**
   * Generate a refresh token
   * @param userId - User's unique identifier
   * @param email - User's email
   * @param expiresIn - Token expiration time (default: '7d')
   * @returns Generated refresh token
   */
  generateRefreshToken(
    userId: string,
    email: string,
    expiresIn?: string
  ): Promise<string>;

  /**
   * Validate and decode a JWT token
   * @param token - JWT token to validate
   * @returns Token validation result with payload if valid
   */
  validateToken(token: string): Promise<TokenValidationResult>;

  /**
   * Decode a JWT token without verification (for inspection purposes)
   * @param token - JWT token to decode
   * @returns Decoded payload or null if invalid format
   */
  decodeToken(token: string): JwtPayload | null;

  /**
   * Get token expiration date
   * @param token - JWT token
   * @returns Expiration date or null if token is invalid
   */
  getTokenExpiration(token: string): Date | null;

  /**
   * Check if a token is expired
   * @param token - JWT token
   * @returns True if expired, false otherwise
   */
  isTokenExpired(token: string): boolean;

  /**
   * Get remaining time until token expiration
   * @param token - JWT token
   * @returns Remaining time in milliseconds, or 0 if expired/invalid
   */
  getTimeUntilExpiration(token: string): number;

  /**
   * Refresh an access token using a refresh token
   * @param refreshToken - Valid refresh token
   * @returns New access token or null if refresh token is invalid
   */
  refreshAccessToken(refreshToken: string): Promise<string | null>;

  /**
   * Blacklist a token (mark as revoked)
   * @param token - JWT token to blacklist
   * @returns True if successfully blacklisted
   */
  blacklistToken(token: string): Promise<boolean>;

  /**
   * Check if a token is blacklisted
   * @param token - JWT token to check
   * @returns True if blacklisted, false otherwise
   */
  isTokenBlacklisted(token: string): Promise<boolean>;

  /**
   * Generate a secure random token for special purposes (reset password, email verification)
   * @param length - Token length (default: 32)
   * @returns Random token string
   */
  generateSecureRandomToken(length?: number): string;

  /**
   * Sign custom data with JWT
   * @param data - Data to sign
   * @param expiresIn - Expiration time
   * @returns Signed JWT token
   */
  signData(data: Record<string, any>, expiresIn: string): Promise<string>;

  /**
   * Verify and extract data from a signed JWT
   * @param token - Signed JWT token
   * @returns Extracted data or null if invalid
   */
  verifyData(token: string): Promise<Record<string, any> | null>;
}