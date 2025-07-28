/**
 * Authentication provider types
 */
export enum AuthProvider {
  LOCAL = 'local',
  GOOGLE = 'google',
  APPLE = 'apple',
  MTLS = 'mtls',
}

/**
 * Token types used in the authentication system
 */
export enum TokenType {
  ACCESS = 'access',
  REFRESH = 'refresh',
  RESET_PASSWORD = 'reset_password',
  EMAIL_VERIFICATION = 'email_verification',
}

/**
 * Client information for session tracking
 */
export interface ClientInfo {
  userAgent?: string;
  ipAddress?: string;
  deviceId?: string;
  platform?: string;
}

/**
 * Authentication error codes
 */
export enum AuthErrorCode {
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_DISABLED = 'ACCOUNT_DISABLED',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  TOKEN_INVALID = 'TOKEN_INVALID',
  USER_NOT_FOUND = 'USER_NOT_FOUND',
  DUPLICATE_EMAIL = 'DUPLICATE_EMAIL',
  WEAK_PASSWORD = 'WEAK_PASSWORD',
  INVALID_EMAIL = 'INVALID_EMAIL',
}