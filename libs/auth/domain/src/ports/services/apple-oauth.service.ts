/**
 * Apple OAuth Service Port Interface
 * 
 * This interface defines the contract for Apple Sign In operations.
 * Infrastructure layer must implement this interface using Apple Sign In SDK.
 */

/**
 * Apple user profile data returned from Sign In
 */
export interface AppleUserProfile {
  id: string;
  email: string;
  name?: {
    firstName?: string;
    lastName?: string;
  };
  emailVerified: boolean;
  isPrivateEmail: boolean;
}

/**
 * Apple Sign In configuration
 */
export interface AppleOAuthConfig {
  clientId: string;
  teamId: string;
  keyId: string;
  privateKey: string;
  redirectUri: string;
}

/**
 * Apple identity token payload
 */
export interface AppleIdentityToken {
  iss: string; // issuer
  aud: string; // audience
  exp: number; // expiration time
  iat: number; // issued at
  sub: string; // subject (user identifier)
  email: string;
  email_verified: boolean;
  is_private_email: boolean;
  auth_time: number;
}

export interface AppleOAuthService {
  /**
   * Generate Apple Sign In authorization URL
   * @param state - State parameter for CSRF protection
   * @param scopes - Scopes to request (name, email)
   * @returns Authorization URL
   */
  getAuthorizationUrl(state?: string, scopes?: string[]): string;

  /**
   * Verify and decode Apple identity token
   * @param identityToken - Apple identity token (JWT)
   * @returns Decoded and verified token payload
   */
  verifyIdentityToken(identityToken: string): Promise<AppleIdentityToken>;

  /**
   * Exchange authorization code for tokens
   * @param code - Authorization code from Apple
   * @param state - State parameter for verification
   * @returns Access token, refresh token, and user profile
   */
  exchangeCodeForTokens(
    code: string,
    state?: string
  ): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresIn: number;
    identityToken: string;
    userProfile: AppleUserProfile;
  }>;

  /**
   * Extract user profile from identity token
   * @param identityToken - Apple identity token
   * @param userInfo - Additional user info from authorization (optional)
   * @returns User profile
   */
  extractUserProfile(
    identityToken: string,
    userInfo?: {
      name?: { firstName?: string; lastName?: string };
    }
  ): Promise<AppleUserProfile>;

  /**
   * Refresh Apple access token
   * @param refreshToken - Apple refresh token
   * @returns New access token and expiration
   */
  refreshAccessToken(refreshToken: string): Promise<{
    accessToken: string;
    expiresIn: number;
  }>;

  /**
   * Revoke Apple refresh token
   * @param refreshToken - Apple refresh token to revoke
   * @returns True if successfully revoked
   */
  revokeRefreshToken(refreshToken: string): Promise<boolean>;

  /**
   * Generate client secret for Apple Sign In
   * @returns Signed client secret JWT
   */
  generateClientSecret(): Promise<string>;

  /**
   * Validate Apple identity token structure and signature
   * @param identityToken - Apple identity token
   * @returns True if valid, false otherwise
   */
  validateIdentityToken(identityToken: string): Promise<boolean>;

  /**
   * Get Apple's public keys for token verification
   * @returns Array of Apple's public keys
   */
  getApplePublicKeys(): Promise<{
    keys: Array<{
      kty: string;
      kid: string;
      use: string;
      alg: string;
      n: string;
      e: string;
    }>;
  }>;

  /**
   * Check if user's email is private relay email
   * @param email - User's email address
   * @returns True if private relay email, false otherwise
   */
  isPrivateRelayEmail(email: string): boolean;
}