import { Injectable } from '@nestjs/common';
import { AppleOAuthService as AppleOAuthPort, AppleUserProfile, AppleIdTokenClaims } from '@auth/domain';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';

/**
 * Apple OAuth Service Implementation
 * 
 * Implements Apple Sign In authentication using Apple's Identity Services.
 * Supports ID token validation and user profile extraction.
 * 
 * Note: Apple Sign In primarily uses ID tokens rather than traditional OAuth flow.
 */
@Injectable()
export class AppleOAuthService implements AppleOAuthPort {
  private readonly clientId: string;
  private readonly teamId: string;
  private readonly keyId: string;
  private readonly privateKey: string;
  private readonly redirectUri: string;

  // Apple's public keys for ID token verification (cached)
  private applePublicKeys: { [kid: string]: string } = {};
  private publicKeysLastFetch = 0;
  private readonly publicKeysCacheDuration = 60 * 60 * 1000; // 1 hour

  constructor() {
    // Load configuration from environment variables
    this.clientId = process.env.APPLE_CLIENT_ID || '';
    this.teamId = process.env.APPLE_TEAM_ID || '';
    this.keyId = process.env.APPLE_KEY_ID || '';
    this.privateKey = process.env.APPLE_PRIVATE_KEY || '';
    this.redirectUri = process.env.APPLE_REDIRECT_URI || 'http://localhost:3000/auth/apple/callback';

    // Validate required configuration
    this.validateConfiguration();
  }

  /**
   * Generate Apple Sign In authorization URL
   * @param state - State parameter for CSRF protection
   * @param nonce - Nonce for ID token validation
   * @returns Authorization URL for Apple Sign In
   */
  async generateAuthUrl(state?: string, nonce?: string): Promise<string> {
    try {
      const baseUrl = 'https://appleid.apple.com/auth/authorize';
      const params = new URLSearchParams({
        client_id: this.clientId,
        redirect_uri: this.redirectUri,
        response_type: 'code id_token',
        scope: 'name email',
        response_mode: 'form_post',
        state: state || this.generateRandomState(),
        nonce: nonce || this.generateRandomNonce(),
      });

      return `${baseUrl}?${params.toString()}`;
    } catch (error) {
      throw new Error(`Failed to generate Apple auth URL: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Validate Apple ID token and extract user information
   * @param idToken - Apple ID token (JWT)
   * @param nonce - Original nonce used in authorization request
   * @returns User profile information from ID token
   */
  async validateIdToken(idToken: string, nonce?: string): Promise<AppleUserProfile> {
    try {
      this.validateIdTokenFormat(idToken);

      // Decode token header to get key ID
      const decodedHeader = jwt.decode(idToken, { complete: true })?.header;
      if (!decodedHeader || !decodedHeader.kid) {
        throw new Error('Invalid ID token header or missing key ID');
      }

      // Get Apple's public key for verification
      const publicKey = await this.getApplePublicKey(decodedHeader.kid);

      // Verify and decode the ID token
      const payload = jwt.verify(idToken, publicKey, {
        issuer: 'https://appleid.apple.com',
        audience: this.clientId,
        algorithms: ['RS256'],
      }) as AppleIdTokenClaims;

      // Validate nonce if provided
      if (nonce && payload.nonce !== nonce) {
        throw new Error('Nonce mismatch in ID token');
      }

      // Validate required claims
      if (!payload.sub || !payload.email) {
        throw new Error('Incomplete user data in Apple ID token');
      }

      return {
        id: payload.sub,
        email: payload.email,
        emailVerified: payload.email_verified === 'true' || payload.email_verified === true,
        name: this.extractNameFromClaims(payload),
        isPrivateEmail: payload.is_private_email === 'true' || payload.is_private_email === true,
        realUserStatus: this.mapRealUserStatus(payload.real_user_status),
      };
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Apple ID token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid Apple ID token signature or format');
      }
      throw new Error(`Failed to validate Apple ID token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Exchange authorization code for tokens (if needed for server-to-server)
   * @param authorizationCode - Authorization code from Apple
   * @returns Client secret and any additional data
   */
  async exchangeCodeForTokens(authorizationCode: string): Promise<{
    clientSecret: string;
    accessToken?: string;
    refreshToken?: string;
  }> {
    try {
      this.validateAuthorizationCode(authorizationCode);

      // Generate client secret for Apple
      const clientSecret = await this.generateClientSecret();

      // Apple Sign In primarily uses ID tokens, but we can exchange for access token if needed
      const tokenEndpoint = 'https://appleid.apple.com/auth/token';
      const params = new URLSearchParams({
        client_id: this.clientId,
        client_secret: clientSecret,
        code: authorizationCode,
        grant_type: 'authorization_code',
        redirect_uri: this.redirectUri,
      });

      const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString(),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`Apple token exchange failed: ${errorData.error || response.statusText}`);
      }

      const tokenData = await response.json();

      return {
        clientSecret,
        accessToken: tokenData.access_token || undefined,
        refreshToken: tokenData.refresh_token || undefined,
      };
    } catch (error) {
      throw new Error(`Failed to exchange authorization code: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Generate client secret JWT for Apple Sign In
   * @returns Signed client secret JWT
   */
  async generateClientSecret(): Promise<string> {
    try {
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        iss: this.teamId,
        iat: now,
        exp: now + 3600, // 1 hour
        aud: 'https://appleid.apple.com',
        sub: this.clientId,
      };

      const header = {
        alg: 'ES256',
        kid: this.keyId,
      };

      return jwt.sign(payload, this.privateKey, {
        algorithm: 'ES256',
        header,
      });
    } catch (error) {
      throw new Error(`Failed to generate Apple client secret: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Revoke Apple refresh token
   * @param refreshToken - Apple refresh token to revoke
   * @returns True if revocation was successful
   */
  async revokeToken(refreshToken: string): Promise<boolean> {
    try {
      this.validateRefreshToken(refreshToken);

      const clientSecret = await this.generateClientSecret();
      const revokeEndpoint = 'https://appleid.apple.com/auth/revoke';
      
      const params = new URLSearchParams({
        client_id: this.clientId,
        client_secret: clientSecret,
        token: refreshToken,
        token_type_hint: 'refresh_token',
      });

      const response = await fetch(revokeEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString(),
      });

      return response.ok;
    } catch (error) {
      // Token revocation failures are not critical
      console.warn(`Failed to revoke Apple token: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return false;
    }
  }

  /**
   * Get service configuration information
   * @returns Service configuration details
   */
  getConfiguration(): {
    clientId: string;
    teamId: string;
    keyId: string;
    redirectUri: string;
    scopes: string[];
    provider: string;
  } {
    return {
      clientId: this.clientId,
      teamId: this.teamId,
      keyId: this.keyId,
      redirectUri: this.redirectUri,
      scopes: ['name', 'email'],
      provider: 'apple',
    };
  }

  /**
   * Health check for Apple OAuth service
   * @returns True if service is operational
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Test client secret generation
      const clientSecret = await this.generateClientSecret();
      if (!clientSecret || clientSecret.split('.').length !== 3) {
        return false;
      }

      // Test public key fetching
      await this.fetchApplePublicKeys();

      return true;
    } catch (error) {
      console.error('Apple OAuth service health check failed:', error);
      return false;
    }
  }

  // Private methods

  private validateConfiguration(): void {
    if (!this.clientId || this.clientId.length === 0) {
      throw new Error('Apple OAuth client ID is required');
    }

    if (!this.teamId || this.teamId.length === 0) {
      throw new Error('Apple OAuth team ID is required');
    }

    if (!this.keyId || this.keyId.length === 0) {
      throw new Error('Apple OAuth key ID is required');
    }

    if (!this.privateKey || this.privateKey.length === 0) {
      throw new Error('Apple OAuth private key is required');
    }

    if (!this.redirectUri || this.redirectUri.length === 0) {
      throw new Error('Apple OAuth redirect URI is required');
    }

    // Validate team ID format (should be 10 characters)
    if (this.teamId.length !== 10) {
      throw new Error('Invalid Apple OAuth team ID format');
    }

    // Validate key ID format (should be 10 characters)
    if (this.keyId.length !== 10) {
      throw new Error('Invalid Apple OAuth key ID format');
    }

    // Validate private key format (should contain PEM headers)
    if (!this.privateKey.includes('BEGIN PRIVATE KEY') && !this.privateKey.includes('BEGIN EC PRIVATE KEY')) {
      throw new Error('Invalid Apple OAuth private key format');
    }
  }

  private validateIdTokenFormat(idToken: string): void {
    if (!idToken || idToken.trim().length === 0) {
      throw new Error('Apple ID token is required and cannot be empty');
    }

    // Basic JWT format validation (3 parts separated by dots)
    const parts = idToken.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid Apple ID token format - must be a valid JWT');
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

  private validateRefreshToken(refreshToken: string): void {
    if (!refreshToken || refreshToken.trim().length === 0) {
      throw new Error('Refresh token is required and cannot be empty');
    }

    if (refreshToken.length < 20) {
      throw new Error('Invalid refresh token format');
    }
  }

  private async getApplePublicKey(keyId: string): Promise<string> {
    // Check if we have cached keys and they're still valid
    const now = Date.now();
    if (now - this.publicKeysLastFetch < this.publicKeysCacheDuration && this.applePublicKeys[keyId]) {
      return this.applePublicKeys[keyId];
    }

    // Fetch fresh public keys
    await this.fetchApplePublicKeys();

    if (!this.applePublicKeys[keyId]) {
      throw new Error(`Apple public key not found for key ID: ${keyId}`);
    }

    return this.applePublicKeys[keyId];
  }

  private async fetchApplePublicKeys(): Promise<void> {
    try {
      const response = await fetch('https://appleid.apple.com/auth/keys');
      if (!response.ok) {
        throw new Error(`Failed to fetch Apple public keys: ${response.statusText}`);
      }

      const data = await response.json();
      if (!data.keys || !Array.isArray(data.keys)) {
        throw new Error('Invalid Apple public keys response format');
      }

      // Convert JWK format to PEM format
      this.applePublicKeys = {};
      for (const key of data.keys) {
        if (key.kty === 'RSA' && key.kid && key.n && key.e) {
          this.applePublicKeys[key.kid] = this.jwkToPem(key);
        }
      }

      this.publicKeysLastFetch = Date.now();
    } catch (error) {
      throw new Error(`Failed to fetch Apple public keys: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private jwkToPem(jwk: any): string {
    // Convert JWK to PEM format for RSA keys
    const modulus = Buffer.from(jwk.n, 'base64');
    const exponent = Buffer.from(jwk.e, 'base64');

    // Create ASN.1 structure for RSA public key
    const modulusLength = modulus.length;
    const exponentLength = exponent.length;

    const sequenceLength = modulusLength + exponentLength + 4;
    const buffer = Buffer.alloc(sequenceLength + 4);

    let offset = 0;
    buffer.writeUInt8(0x30, offset++); // SEQUENCE
    buffer.writeUInt8(0x82, offset++); // LENGTH (long form)
    buffer.writeUInt16BE(sequenceLength, offset);
    offset += 2;

    // Modulus
    buffer.writeUInt8(0x02, offset++); // INTEGER
    buffer.writeUInt8(0x82, offset++); // LENGTH (long form)
    buffer.writeUInt16BE(modulusLength, offset);
    offset += 2;
    modulus.copy(buffer, offset);
    offset += modulusLength;

    // Exponent
    buffer.writeUInt8(0x02, offset++); // INTEGER
    buffer.writeUInt8(exponentLength, offset++); // LENGTH
    exponent.copy(buffer, offset);

    const base64 = buffer.toString('base64');
    const pem = `-----BEGIN RSA PUBLIC KEY-----\n${base64.match(/.{1,64}/g)?.join('\n')}\n-----END RSA PUBLIC KEY-----`;
    
    return pem;
  }

  private extractNameFromClaims(payload: AppleIdTokenClaims): string | null {
    // Apple includes name in the first sign-in only
    if (payload.name) {
      if (typeof payload.name === 'string') {
        return payload.name;
      }
      
      // Name might be an object with firstName and lastName
      if (typeof payload.name === 'object' && payload.name !== null) {
        const nameObj = payload.name as any;
        const firstName = nameObj.firstName || nameObj.givenName || '';
        const lastName = nameObj.lastName || nameObj.familyName || '';
        return `${firstName} ${lastName}`.trim() || null;
      }
    }

    return null;
  }

  private mapRealUserStatus(status: string | number | undefined): 'unsupported' | 'unknown' | 'likelyReal' {
    if (status === undefined || status === null) {
      return 'unsupported';
    }

    const statusNum = typeof status === 'string' ? parseInt(status, 10) : status;

    switch (statusNum) {
      case 0:
        return 'unsupported';
      case 1:
        return 'unknown';
      case 2:
        return 'likelyReal';
      default:
        return 'unsupported';
    }
  }

  private generateRandomState(length: number = 32): string {
    return crypto.randomBytes(length / 2).toString('hex');
  }

  private generateRandomNonce(length: number = 32): string {
    return crypto.randomBytes(length / 2).toString('hex');
  }
}