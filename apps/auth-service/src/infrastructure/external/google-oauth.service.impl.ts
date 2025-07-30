import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { GoogleOAuthService, GoogleTokens, GoogleUserInfo } from '../../domain/ports/google-oauth.service';

export class GoogleOAuthError extends Error {
  constructor(message: string, public code?: string) {
    super(message);
    this.name = 'GoogleOAuthError';
  }
}

export class GoogleTokenExchangeError extends GoogleOAuthError {
  constructor(message: string) {
    super(message, 'TOKEN_EXCHANGE_FAILED');
    this.name = 'GoogleTokenExchangeError';
  }
}

export class GoogleUserInfoError extends GoogleOAuthError {
  constructor(message: string) {
    super(message, 'USER_INFO_FAILED');
    this.name = 'GoogleUserInfoError';
  }
}

@Injectable()
export class GoogleOAuthServiceImpl implements GoogleOAuthService {
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly callbackUrl: string;
  private readonly tokenEndpoint = 'https://oauth2.googleapis.com/token';
  private readonly userInfoEndpoint = 'https://www.googleapis.com/oauth2/v2/userinfo';
  private readonly tokenInfoEndpoint = 'https://oauth2.googleapis.com/tokeninfo';

  constructor(
    @Inject(ConfigService)
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
  ) {
    this.clientId = this.configService.get<string>('oauth.google.clientId', '');
    this.clientSecret = this.configService.get<string>('oauth.google.clientSecret', '');
    this.callbackUrl = this.configService.get<string>('oauth.google.callbackUrl', '');

    if (!this.clientId || !this.clientSecret) {
      throw new Error('Google OAuth configuration is missing. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET');
    }
  }

  async exchangeCodeForTokens(code: string): Promise<GoogleTokens> {
    if (!code || typeof code !== 'string') {
      throw new GoogleTokenExchangeError('Authorization code is required');
    }

    try {
      const requestBody = new URLSearchParams({
        code,
        client_id: this.clientId,
        client_secret: this.clientSecret,
        redirect_uri: this.callbackUrl,
        grant_type: 'authorization_code',
      });

      const response = await firstValueFrom(
        this.httpService.post(this.tokenEndpoint, requestBody.toString(), {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          timeout: 10000, // 10 seconds timeout
        })
      );

      const tokens = response.data;

      if (!tokens.access_token) {
        throw new GoogleTokenExchangeError('No access token received from Google');
      }

      return {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        token_type: tokens.token_type || 'Bearer',
        scope: tokens.scope,
        id_token: tokens.id_token,
      };
    } catch (error) {
      if (error instanceof GoogleTokenExchangeError) {
        throw error;
      }

      if (error.response) {
        const errorData = error.response.data;
        const errorMessage = errorData.error_description || errorData.error || 'Token exchange failed';
        throw new GoogleTokenExchangeError(`Google token exchange failed: ${errorMessage}`);
      }

      if (error.code === 'ECONNABORTED') {
        throw new GoogleTokenExchangeError('Google token exchange timed out');
      }

      throw new GoogleTokenExchangeError(`Google token exchange failed: ${error.message}`);
    }
  }

  async getUserInfo(accessToken: string): Promise<GoogleUserInfo> {
    if (!accessToken || typeof accessToken !== 'string') {
      throw new GoogleUserInfoError('Access token is required');
    }

    try {
      const response = await firstValueFrom(
        this.httpService.get(this.userInfoEndpoint, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
          timeout: 10000, // 10 seconds timeout
        })
      );

      const userInfo = response.data;

      if (!userInfo.id || !userInfo.email) {
        throw new GoogleUserInfoError('Invalid user info received from Google');
      }

      return {
        id: userInfo.id,
        email: userInfo.email,
        verified_email: userInfo.verified_email || false,
        name: userInfo.name,
        given_name: userInfo.given_name,
        family_name: userInfo.family_name,
        picture: userInfo.picture,
        locale: userInfo.locale,
      };
    } catch (error) {
      if (error instanceof GoogleUserInfoError) {
        throw error;
      }

      if (error.response) {
        const status = error.response.status;
        if (status === 401) {
          throw new GoogleUserInfoError('Invalid or expired access token');
        }
        if (status === 403) {
          throw new GoogleUserInfoError('Insufficient permissions to access user info');
        }

        const errorData = error.response.data;
        const errorMessage = errorData.error_description || errorData.error || 'User info request failed';
        throw new GoogleUserInfoError(`Google user info request failed: ${errorMessage}`);
      }

      if (error.code === 'ECONNABORTED') {
        throw new GoogleUserInfoError('Google user info request timed out');
      }

      throw new GoogleUserInfoError(`Google user info request failed: ${error.message}`);
    }
  }

  async refreshTokens(refreshToken: string): Promise<GoogleTokens> {
    if (!refreshToken || typeof refreshToken !== 'string') {
      throw new GoogleTokenExchangeError('Refresh token is required');
    }

    try {
      const requestBody = new URLSearchParams({
        refresh_token: refreshToken,
        client_id: this.clientId,
        client_secret: this.clientSecret,
        grant_type: 'refresh_token',
      });

      const response = await firstValueFrom(
        this.httpService.post(this.tokenEndpoint, requestBody.toString(), {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          timeout: 10000,
        })
      );

      const tokens = response.data;

      if (!tokens.access_token) {
        throw new GoogleTokenExchangeError('No access token received during refresh');
      }

      return {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token || refreshToken, // Keep old refresh token if new one not provided
        expires_in: tokens.expires_in,
        token_type: tokens.token_type || 'Bearer',
        scope: tokens.scope,
        id_token: tokens.id_token,
      };
    } catch (error) {
      if (error instanceof GoogleTokenExchangeError) {
        throw error;
      }

      if (error.response) {
        const errorData = error.response.data;
        if (errorData.error === 'invalid_grant') {
          throw new GoogleTokenExchangeError('Refresh token is invalid or expired');
        }

        const errorMessage = errorData.error_description || errorData.error || 'Token refresh failed';
        throw new GoogleTokenExchangeError(`Google token refresh failed: ${errorMessage}`);
      }

      throw new GoogleTokenExchangeError(`Google token refresh failed: ${error.message}`);
    }
  }

  async verifyIdToken(idToken: string): Promise<boolean> {
    if (!idToken || typeof idToken !== 'string') {
      return false;
    }

    try {
      const response = await firstValueFrom(
        this.httpService.get(`${this.tokenInfoEndpoint}?id_token=${encodeURIComponent(idToken)}`, {
          timeout: 10000,
        })
      );

      const tokenInfo = response.data;

      // Verify the token is for our application
      if (tokenInfo.aud !== this.clientId) {
        return false;
      }

      // Verify the token hasn't expired
      const now = Math.floor(Date.now() / 1000);
      if (tokenInfo.exp && tokenInfo.exp < now) {
        return false;
      }

      // Verify the issuer
      const validIssuers = ['accounts.google.com', 'https://accounts.google.com'];
      if (!validIssuers.includes(tokenInfo.iss)) {
        return false;
      }

      return true;
    } catch (error) {
      // If verification fails, return false
      return false;
    }
  }

  async revokeToken(token: string): Promise<void> {
    if (!token || typeof token !== 'string') {
      throw new GoogleOAuthError('Token is required for revocation');
    }

    try {
      await firstValueFrom(
        this.httpService.post(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(token)}`, null, {
          timeout: 10000,
        })
      );
    } catch (error) {
      // Token revocation failure is not critical, log but don't throw
      console.warn('Google token revocation failed:', error.message);
    }
  }

  getAuthorizationUrl(scopes?: string[], state?: string): string {
    const defaultScopes = ['openid', 'email', 'profile'];
    const requestedScopes = scopes && scopes.length > 0 ? scopes : defaultScopes;

    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.callbackUrl,
      response_type: 'code',
      scope: requestedScopes.join(' '),
      access_type: 'offline', // Request refresh token
      prompt: 'consent', // Force consent screen to get refresh token
    });

    if (state) {
      params.append('state', state);
    }

    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  }

  validateConfiguration(): boolean {
    return !!(this.clientId && this.clientSecret && this.callbackUrl);
  }

  getClientId(): string {
    return this.clientId;
  }

  private extractUserIdFromIdToken(idToken: string): string | null {
    try {
      // Simple JWT decode (for production, use a proper JWT library)
      const payload = idToken.split('.')[1];
      if (!payload) return null;

      const decoded = JSON.parse(Buffer.from(payload, 'base64').toString());
      return decoded.sub || null;
    } catch (error) {
      return null;
    }
  }

  async validateTokensAndGetUserInfo(tokens: GoogleTokens): Promise<GoogleUserInfo> {
    // Verify ID token if available
    if (tokens.id_token) {
      const isValidIdToken = await this.verifyIdToken(tokens.id_token);
      if (!isValidIdToken) {
        throw new GoogleOAuthError('Invalid ID token');
      }
    }

    // Get user info using access token
    return await this.getUserInfo(tokens.access_token);
  }
}