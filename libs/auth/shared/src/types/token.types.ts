/**
 * Token expiration configuration
 */
export interface TokenExpiration {
  access: string;
  refresh: string;
  resetPassword: string;
  emailVerification: string;
}

/**
 * Default token expiration times
 */
export const DEFAULT_TOKEN_EXPIRATION: TokenExpiration = {
  access: '15m',
  refresh: '7d',
  resetPassword: '1h',
  emailVerification: '24h',
};

/**
 * JWT token payload structure
 */
export interface JwtPayload {
  sub: string; // user id
  email: string;
  type: string; // token type
  iat?: number;
  exp?: number;
}

/**
 * Token validation result
 */
export interface TokenValidationResult {
  isValid: boolean;
  payload?: JwtPayload;
  error?: string;
}