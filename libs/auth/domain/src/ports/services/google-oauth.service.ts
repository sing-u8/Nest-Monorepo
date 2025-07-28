/**
 * Google OAuth Service Port Interface
 * 
 * This interface defines the contract for Google OAuth operations.
 * Infrastructure layer must implement this interface using Google OAuth2 client.
 */

/**
 * Google user profile data returned from OAuth
 */
export interface GoogleUserProfile {
  id: string;
  email: string;
  name: string;
  firstName?: string;
  lastName?: string;
  picture?: string;
  locale?: string;
  emailVerified: boolean;
}

/**
 * Google OAuth configuration
 */
export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope?: string[];
}

export interface GoogleOAuthService {
  /**
   * Generate Google OAuth authorization URL
   * @param state - State parameter for CSRF protection
   * @param scopes - Additional scopes to request (optional)
   * @returns Authorization URL
   */
  getAuthorizationUrl(state?: string, scopes?: string[]): string;

  /**
   * Exchange authorization code for access token
   * @param code - Authorization code from Google
   * @param state - State parameter for verification
   * @returns Access token and user profile
   */
  exchangeCodeForToken(
    code: string,
    state?: string
  ): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresIn: number;
    userProfile: GoogleUserProfile;
  }>;

  /**
   * Get user profile using access token
   * @param accessToken - Google access token
   * @returns User profile information
   */
  getUserProfile(accessToken: string): Promise<GoogleUserProfile>;

  /**
   * Verify Google ID token
   * @param idToken - Google ID token
   * @returns Verified user profile or null if invalid
   */
  verifyIdToken(idToken: string): Promise<GoogleUserProfile | null>;

  /**
   * Refresh Google access token
   * @param refreshToken - Google refresh token
   * @returns New access token and expiration
   */
  refreshAccessToken(refreshToken: string): Promise<{
    accessToken: string;
    expiresIn: number;
  }>;

  /**
   * Revoke Google access token
   * @param accessToken - Google access token to revoke
   * @returns True if successfully revoked
   */
  revokeToken(accessToken: string): Promise<boolean>;

  /**
   * Validate Google access token
   * @param accessToken - Google access token
   * @returns True if valid, false otherwise
   */
  validateToken(accessToken: string): Promise<boolean>;

  /**
   * Get user's email from Google using access token
   * @param accessToken - Google access token
   * @returns User's email address
   */
  getUserEmail(accessToken: string): Promise<string>;

  /**
   * Check if user has granted specific permissions
   * @param accessToken - Google access token
   * @param scopes - Scopes to check
   * @returns Array of granted scopes
   */
  getGrantedScopes(accessToken: string, scopes: string[]): Promise<string[]>;
}