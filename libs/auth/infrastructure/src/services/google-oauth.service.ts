import { Injectable } from '@nestjs/common';
import { GoogleOAuthService as GoogleOAuthPort, GoogleUserProfile, GoogleOAuthTokens } from '@auth/domain';
import { google, Auth } from 'googleapis';
import { MetricsService } from './metrics.service';
import { InjectMetrics, TrackExternalService } from '../decorators/metrics.decorator';

/**
 * Google OAuth Service Implementation
 * 
 * Implements Google OAuth 2.0 authentication using Google APIs.
 * Supports both authorization code flow and ID token validation.
 */
@Injectable()
export class GoogleOAuthService implements GoogleOAuthPort {
  private readonly oauth2Client: Auth.OAuth2Client;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly redirectUri: string;

  constructor(
    @InjectMetrics()
    private readonly metricsService: MetricsService,
  ) {
    // Load configuration from environment variables
    this.clientId = process.env.GOOGLE_CLIENT_ID || '';
    this.clientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
    this.redirectUri = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback';

    // Validate required configuration
    this.validateConfiguration();

    // Initialize OAuth2 client
    this.oauth2Client = new google.auth.OAuth2(
      this.clientId,
      this.clientSecret,
      this.redirectUri
    );
  }

  /**
   * Generate Google OAuth authorization URL
   * @param state - Optional state parameter for CSRF protection
   * @returns Authorization URL for redirecting users
   */
  async generateAuthUrl(state?: string): Promise<string> {
    try {
      const scopes = [
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
      ];

      const authUrl = this.oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: scopes,
        include_granted_scopes: true,
        state: state || this.generateRandomState(),
        prompt: 'consent', // Force consent screen to get refresh token
      });

      return authUrl;
    } catch (error) {
      throw new Error(`Failed to generate Google auth URL: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Exchange authorization code for access tokens
   * @param authorizationCode - Authorization code from Google callback
   * @returns Google OAuth tokens
   */
  async exchangeCodeForTokens(authorizationCode: string): Promise<GoogleOAuthTokens> {
    try {
      this.validateAuthorizationCode(authorizationCode);

      const { tokens } = await this.oauth2Client.getToken(authorizationCode);

      if (!tokens.access_token) {
        throw new Error('No access token received from Google');
      }

      return {
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token || null,
        idToken: tokens.id_token || null,
        expiryDate: tokens.expiry_date ? new Date(tokens.expiry_date) : null,
        tokenType: tokens.token_type || 'Bearer',
        scope: tokens.scope || null,
      };
    } catch (error) {
      if (error instanceof Error && error.message.includes('invalid_grant')) {
        throw new Error('Invalid or expired authorization code');
      }
      throw new Error(`Failed to exchange authorization code: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get user profile information using access token
   * @param accessToken - Google access token
   * @returns User profile information
   */
  async getUserProfile(accessToken: string): Promise<GoogleUserProfile> {
    try {
      this.validateAccessToken(accessToken);

      // Set access token for the OAuth2 client
      this.oauth2Client.setCredentials({
        access_token: accessToken,
      });

      // Get user info using Google+ API
      const oauth2 = google.oauth2({ version: 'v2', auth: this.oauth2Client });
      const { data } = await oauth2.userinfo.get();

      if (!data.id || !data.email) {
        throw new Error('Incomplete user profile data received from Google');
      }

      return {
        id: data.id,
        email: data.email,
        emailVerified: data.verified_email || false,
        name: data.name || null,
        givenName: data.given_name || null,
        familyName: data.family_name || null,
        picture: data.picture || null,
        locale: data.locale || null,
        hostedDomain: data.hd || null,
      };
    } catch (error) {
      if (error instanceof Error && error.message.includes('Invalid Credentials')) {
        throw new Error('Invalid or expired access token');
      }
      throw new Error(`Failed to get user profile: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Validate Google ID token and extract user information
   * @param idToken - Google ID token (JWT)
   * @returns User profile information from ID token
   */
  async validateIdToken(idToken: string): Promise<GoogleUserProfile> {
    try {
      this.validateIdToken(idToken);

      const ticket = await this.oauth2Client.verifyIdToken({
        idToken,
        audience: this.clientId,
      });

      const payload = ticket.getPayload();
      if (!payload) {
        throw new Error('Invalid ID token payload');
      }

      if (!payload.sub || !payload.email) {
        throw new Error('Incomplete user data in ID token');
      }

      return {
        id: payload.sub,
        email: payload.email,
        emailVerified: payload.email_verified || false,
        name: payload.name || null,
        givenName: payload.given_name || null,
        familyName: payload.family_name || null,
        picture: payload.picture || null,
        locale: payload.locale || null,
        hostedDomain: payload.hd || null,
      };
    } catch (error) {
      if (error instanceof Error && error.message.includes('Token used too late')) {
        throw new Error('ID token has expired');
      }
      if (error instanceof Error && error.message.includes('Invalid token signature')) {
        throw new Error('Invalid ID token signature');
      }
      throw new Error(`Failed to validate ID token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Refresh access token using refresh token
   * @param refreshToken - Google refresh token
   * @returns New access token information
   */
  async refreshAccessToken(refreshToken: string): Promise<GoogleOAuthTokens> {
    try {
      this.validateRefreshToken(refreshToken);

      this.oauth2Client.setCredentials({
        refresh_token: refreshToken,
      });

      const { credentials } = await this.oauth2Client.refreshAccessToken();

      if (!credentials.access_token) {
        throw new Error('No access token received from refresh');
      }

      return {
        accessToken: credentials.access_token,
        refreshToken: credentials.refresh_token || refreshToken, // Keep original if not provided
        idToken: credentials.id_token || null,
        expiryDate: credentials.expiry_date ? new Date(credentials.expiry_date) : null,
        tokenType: credentials.token_type || 'Bearer',
        scope: credentials.scope || null,
      };
    } catch (error) {
      if (error instanceof Error && error.message.includes('invalid_grant')) {
        throw new Error('Invalid or expired refresh token');
      }
      throw new Error(`Failed to refresh access token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Revoke Google access or refresh token
   * @param token - Token to revoke (access or refresh token)
   * @returns True if revocation was successful
   */
  async revokeToken(token: string): Promise<boolean> {
    try {
      this.validateToken(token);

      await this.oauth2Client.revokeToken(token);
      return true;
    } catch (error) {
      // Token revocation failures are not critical
      console.warn(`Failed to revoke Google token: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return false;
    }
  }

  /**
   * Get service configuration information
   * @returns Service configuration details
   */
  getConfiguration(): {
    clientId: string;
    redirectUri: string;
    scopes: string[];
    provider: string;
  } {
    return {
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      scopes: [
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
      ],
      provider: 'google',
    };
  }

  /**
   * Health check for Google OAuth service
   * @returns True if service is operational
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Test OAuth2 client configuration
      const testUrl = this.oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: ['https://www.googleapis.com/auth/userinfo.email'],
        state: 'health-check',
      });

      return testUrl.includes('accounts.google.com') && testUrl.includes(this.clientId);
    } catch (error) {
      console.error('Google OAuth service health check failed:', error);
      return false;
    }
  }

  // Private validation methods

  private validateConfiguration(): void {
    if (!this.clientId || this.clientId.length === 0) {
      throw new Error('Google OAuth client ID is required');
    }

    if (!this.clientSecret || this.clientSecret.length === 0) {
      throw new Error('Google OAuth client secret is required');
    }

    if (!this.redirectUri || this.redirectUri.length === 0) {
      throw new Error('Google OAuth redirect URI is required');
    }

    // Validate client ID format (should end with .googleusercontent.com)
    if (!this.clientId.endsWith('.googleusercontent.com')) {
      throw new Error('Invalid Google OAuth client ID format');
    }

    // Validate redirect URI format
    try {
      new URL(this.redirectUri);
    } catch (error) {
      throw new Error('Invalid Google OAuth redirect URI format');
    }
  }

  private validateAuthorizationCode(authorizationCode: string): void {
    if (!authorizationCode || authorizationCode.trim().length === 0) {
      throw new Error('Authorization code is required and cannot be empty');
    }

    if (authorizationCode.length < 10) {
      throw new Error('Invalid authorization code format');
    }
  }

  private validateAccessToken(accessToken: string): void {
    if (!accessToken || accessToken.trim().length === 0) {
      throw new Error('Access token is required and cannot be empty');
    }

    if (accessToken.length < 20) {
      throw new Error('Invalid access token format');
    }
  }

  private validateIdToken(idToken: string): void {
    if (!idToken || idToken.trim().length === 0) {
      throw new Error('ID token is required and cannot be empty');
    }

    // Basic JWT format validation (3 parts separated by dots)
    const parts = idToken.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid ID token format - must be a valid JWT');
    }
  }

  private validateRefreshToken(refreshToken: string): void {
    if (!refreshToken || refreshToken.trim().length === 0) {
      throw new Error('Refresh token is required and cannot be empty');
    }

    if (refreshToken.length < 20) {
      throw new Error('Invalid refresh token format');
    }
  }

  private validateToken(token: string): void {
    if (!token || token.trim().length === 0) {
      throw new Error('Token is required and cannot be empty');
    }

    if (token.length < 20) {
      throw new Error('Invalid token format');
    }
  }

  private generateRandomState(length: number = 32): string {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    
    return result;
  }
}