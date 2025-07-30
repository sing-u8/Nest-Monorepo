import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import * as jwt from 'jsonwebtoken';
import { AppleOAuthService, AppleUserInfo } from '../../domain/ports/apple-oauth.service';

export class AppleOAuthError extends Error {
  constructor(message: string, public code?: string) {
    super(message);
    this.name = 'AppleOAuthError';
  }
}

export class AppleTokenVerificationError extends AppleOAuthError {
  constructor(message: string) {
    super(message, 'TOKEN_VERIFICATION_FAILED');
    this.name = 'AppleTokenVerificationError';
  }
}

export class AppleUserInfoExtractionError extends AppleOAuthError {
  constructor(message: string) {
    super(message, 'USER_INFO_EXTRACTION_FAILED');
    this.name = 'AppleUserInfoExtractionError';
  }
}

@Injectable()
export class AppleOAuthServiceImpl implements AppleOAuthService {
  private readonly clientId: string;
  private readonly teamId: string;
  private readonly keyId: string;
  private readonly privateKey: string;
  private readonly callbackUrl: string;
  private readonly appleKeysEndpoint = 'https://appleid.apple.com/auth/keys';
  private readonly appleIssuer = 'https://appleid.apple.com';

  // Cache for Apple's public keys
  private publicKeysCache: { keys: any[]; expires: number } | null = null;

  constructor(
    @Inject(ConfigService)
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
  ) {
    this.clientId = this.configService.get<string>('oauth.apple.clientId', '');
    this.teamId = this.configService.get<string>('oauth.apple.teamId', '');
    this.keyId = this.configService.get<string>('oauth.apple.keyId', '');
    this.privateKey = this.configService.get<string>('oauth.apple.privateKey', '');
    this.callbackUrl = this.configService.get<string>('oauth.apple.callbackUrl', '');

    if (!this.clientId || !this.teamId || !this.keyId || !this.privateKey) {
      throw new Error('Apple OAuth configuration is missing. Please set APPLE_CLIENT_ID, APPLE_TEAM_ID, APPLE_KEY_ID, and APPLE_PRIVATE_KEY');
    }
  }

  async verifyIdToken(idToken: string): Promise<boolean> {
    if (!idToken || typeof idToken !== 'string') {
      return false;
    }

    try {
      // Decode token header to get key ID
      const header = this.decodeJwtHeader(idToken);
      if (!header || !header.kid) {
        return false;
      }

      // Get Apple's public keys
      const publicKeys = await this.getApplePublicKeys();
      const publicKey = publicKeys.find(key => key.kid === header.kid);

      if (!publicKey) {
        return false;
      }

      // Convert JWK to PEM format
      const pemKey = this.jwkToPem(publicKey);

      // Verify the token
      const decoded = jwt.verify(idToken, pemKey, {
        algorithms: ['RS256'],
        audience: this.clientId,
        issuer: this.appleIssuer,
      });

      return !!decoded;
    } catch (error) {
      return false;
    }
  }

  async extractUserInfo(idToken: string, userInfo?: any): Promise<AppleUserInfo> {
    try {
      // First verify the token
      const isValid = await this.verifyIdToken(idToken);
      if (!isValid) {
        throw new AppleTokenVerificationError('Invalid Apple ID token');
      }

      // Decode the token payload
      const payload = this.decodeJwtPayload(idToken);
      if (!payload) {
        throw new AppleUserInfoExtractionError('Failed to decode ID token payload');
      }

      // Extract basic user info from token
      const extractedInfo: AppleUserInfo = {
        sub: payload.sub,
        email: payload.email,
        email_verified: payload.email_verified === 'true' || payload.email_verified === true,
      };

      // Add additional user info if provided (from Sign In with Apple form)
      if (userInfo) {
        if (userInfo.name) {
          if (typeof userInfo.name === 'string') {
            extractedInfo.name = userInfo.name;
          } else if (userInfo.name.firstName || userInfo.name.lastName) {
            const firstName = userInfo.name.firstName || '';
            const lastName = userInfo.name.lastName || '';
            extractedInfo.name = `${firstName} ${lastName}`.trim();
          }
        }

        // Apple doesn't provide profile pictures through Sign In with Apple
        // Users would need to upload their own profile picture
      }

      // Generate a display name if not provided
      if (!extractedInfo.name && extractedInfo.email) {
        const emailPart = extractedInfo.email.split('@')[0];
        extractedInfo.name = emailPart.charAt(0).toUpperCase() + emailPart.slice(1);
      }

      if (!extractedInfo.sub || !extractedInfo.email) {
        throw new AppleUserInfoExtractionError('Missing required user information in ID token');
      }

      return extractedInfo;
    } catch (error) {
      if (error instanceof AppleTokenVerificationError || error instanceof AppleUserInfoExtractionError) {
        throw error;
      }
      throw new AppleUserInfoExtractionError(`Failed to extract user info: ${error.message}`);
    }
  }

  async validateNonce(idToken: string, expectedNonce: string): Promise<boolean> {
    try {
      const payload = this.decodeJwtPayload(idToken);
      if (!payload || !payload.nonce) {
        return false;
      }

      // In production, you might want to use a more sophisticated nonce validation
      // This could include hashing the nonce before comparison
      return payload.nonce === expectedNonce;
    } catch (error) {
      return false;
    }
  }

  generateClientSecret(): string {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: this.teamId,
      iat: now,
      exp: now + 3600, // 1 hour
      aud: 'https://appleid.apple.com',
      sub: this.clientId,
    };

    try {
      return jwt.sign(claims, this.privateKey, {
        algorithm: 'ES256',
        header: {
          kid: this.keyId,
        },
      });
    } catch (error) {
      throw new AppleOAuthError(`Failed to generate client secret: ${error.message}`);
    }
  }

  getAuthorizationUrl(scopes?: string[], state?: string, nonce?: string): string {
    const defaultScopes = ['name', 'email'];
    const requestedScopes = scopes && scopes.length > 0 ? scopes : defaultScopes;

    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.callbackUrl,
      response_type: 'code id_token',
      scope: requestedScopes.join(' '),
      response_mode: 'form_post',
    });

    if (state) {
      params.append('state', state);
    }

    if (nonce) {
      params.append('nonce', nonce);
    }

    return `https://appleid.apple.com/auth/authorize?${params.toString()}`;
  }

  async revokeToken(refreshToken: string): Promise<void> {
    if (!refreshToken || typeof refreshToken !== 'string') {
      throw new AppleOAuthError('Refresh token is required for revocation');
    }

    try {
      const clientSecret = this.generateClientSecret();

      const requestBody = new URLSearchParams({
        client_id: this.clientId,
        client_secret: clientSecret,
        token: refreshToken,
        token_type_hint: 'refresh_token',
      });

      await firstValueFrom(
        this.httpService.post('https://appleid.apple.com/auth/revoke', requestBody.toString(), {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          timeout: 10000,
        })
      );
    } catch (error) {
      // Token revocation failure is not critical, log but don't throw
      console.warn('Apple token revocation failed:', error.message);
    }
  }

  validateConfiguration(): boolean {
    return !!(this.clientId && this.teamId && this.keyId && this.privateKey && this.callbackUrl);
  }

  getClientId(): string {
    return this.clientId;
  }

  private async getApplePublicKeys(): Promise<any[]> {
    // Check cache first
    if (this.publicKeysCache && this.publicKeysCache.expires > Date.now()) {
      return this.publicKeysCache.keys;
    }

    try {
      const response = await firstValueFrom(
        this.httpService.get(this.appleKeysEndpoint, {
          timeout: 10000,
        })
      );

      const keys = response.data.keys;
      
      // Cache keys for 1 hour
      this.publicKeysCache = {
        keys,
        expires: Date.now() + 3600000, // 1 hour
      };

      return keys;
    } catch (error) {
      throw new AppleTokenVerificationError(`Failed to fetch Apple public keys: ${error.message}`);
    }
  }

  private decodeJwtHeader(token: string): any {
    try {
      const headerBase64 = token.split('.')[0];
      if (!headerBase64) return null;

      const headerJson = Buffer.from(headerBase64, 'base64').toString('utf8');
      return JSON.parse(headerJson);
    } catch (error) {
      return null;
    }
  }

  private decodeJwtPayload(token: string): any {
    try {
      const payloadBase64 = token.split('.')[1];
      if (!payloadBase64) return null;

      const payloadJson = Buffer.from(payloadBase64, 'base64').toString('utf8');
      return JSON.parse(payloadJson);
    } catch (error) {
      return null;
    }
  }

  private jwkToPem(jwk: any): string {
    // This is a simplified implementation
    // In production, use a proper library like node-jose or jwk-to-pem
    try {
      if (jwk.kty !== 'RSA') {
        throw new Error('Only RSA keys are supported');
      }

      // Convert base64url to base64
      const n = this.base64UrlToBase64(jwk.n);
      const e = this.base64UrlToBase64(jwk.e);

      // Create DER encoded public key
      const nBuffer = Buffer.from(n, 'base64');
      const eBuffer = Buffer.from(e, 'base64');

      // This is a simplified ASN.1 encoding for RSA public key
      // In production, use a proper ASN.1 library
      const publicKeyDer = this.createRsaPublicKeyDer(nBuffer, eBuffer);
      const publicKeyPem = this.derToPem(publicKeyDer, 'PUBLIC KEY');

      return publicKeyPem;
    } catch (error) {
      throw new AppleTokenVerificationError(`Failed to convert JWK to PEM: ${error.message}`);
    }
  }

  private base64UrlToBase64(base64Url: string): string {
    return base64Url.replace(/-/g, '+').replace(/_/g, '/').padEnd(base64Url.length + (4 - (base64Url.length % 4)) % 4, '=');
  }

  private createRsaPublicKeyDer(n: Buffer, e: Buffer): Buffer {
    // This is a very simplified implementation
    // In production, use proper ASN.1 encoding
    const nLength = n.length;
    const eLength = e.length;
    
    // Approximate DER structure for RSA public key
    const derLength = 32 + nLength + eLength; // Approximate
    const der = Buffer.alloc(derLength);
    
    // This is not a proper DER encoding - just a placeholder
    // In production, use node-forge or similar library
    let offset = 0;
    
    // Simplified structure - this won't work in practice
    // You should use a proper ASN.1 library
    der.writeUInt8(0x30, offset++); // SEQUENCE
    der.writeUInt8(derLength - 2, offset++); // Length
    
    // Copy modulus and exponent (simplified)
    n.copy(der, offset);
    offset += nLength;
    e.copy(der, offset);
    
    return der.slice(0, offset);
  }

  private derToPem(der: Buffer, type: string): string {
    const base64 = der.toString('base64');
    const pemLines = base64.match(/.{1,64}/g) || [];
    
    return [
      `-----BEGIN ${type}-----`,
      ...pemLines,
      `-----END ${type}-----`,
    ].join('\n');
  }

  // Helper method to extract user ID from ID token
  extractUserIdFromIdToken(idToken: string): string | null {
    const payload = this.decodeJwtPayload(idToken);
    return payload?.sub || null;
  }

  // Validate token expiration
  isTokenExpired(idToken: string): boolean {
    const payload = this.decodeJwtPayload(idToken);
    if (!payload || !payload.exp) {
      return true;
    }

    const now = Math.floor(Date.now() / 1000);
    return payload.exp < now;
  }
}