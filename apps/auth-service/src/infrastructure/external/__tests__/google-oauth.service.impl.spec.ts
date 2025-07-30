import { Test, TestingModule } from '@nestjs/testing';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { of, throwError } from 'rxjs';
import { AxiosResponse } from 'axios';
import { GoogleOAuthServiceImpl } from '../google-oauth.service.impl';
import { GoogleTokens, GoogleUserInfo } from '../../domain/ports/google-oauth.service';

describe('GoogleOAuthServiceImpl', () => {
  let service: GoogleOAuthServiceImpl;
  let httpService: jest.Mocked<HttpService>;
  let configService: jest.Mocked<ConfigService>;

  const mockConfig = {
    'oauth.google.clientId': 'test-client-id',
    'oauth.google.clientSecret': 'test-client-secret',
    'oauth.google.callbackUrl': 'http://localhost:3000/auth/google/callback',
  };

  beforeEach(async () => {
    const mockHttpService = {
      post: jest.fn(),
      get: jest.fn(),
    };

    const mockConfigService = {
      get: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        GoogleOAuthServiceImpl,
        { provide: HttpService, useValue: mockHttpService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    service = module.get<GoogleOAuthServiceImpl>(GoogleOAuthServiceImpl);
    httpService = module.get(HttpService);
    configService = module.get(ConfigService);

    // Setup config mock
    configService.get.mockImplementation((key: string, defaultValue?: any) => {
      return mockConfig[key] || defaultValue;
    });
  });

  describe('constructor', () => {
    it('should initialize with valid configuration', () => {
      expect(service).toBeDefined();
      expect(service.validateConfiguration()).toBe(true);
    });

    it('should throw error with missing configuration', () => {
      // Mock missing config
      configService.get.mockReturnValue('');

      expect(() => {
        new GoogleOAuthServiceImpl(configService, httpService);
      }).toThrow('Google OAuth configuration is missing');
    });
  });

  describe('exchangeCodeForTokens', () => {
    const mockTokenResponse: GoogleTokens = {
      access_token: 'access_token_123',
      refresh_token: 'refresh_token_123',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'openid email profile',
      id_token: 'id_token_123',
    };

    it('should exchange authorization code for tokens', async () => {
      // Arrange
      const code = 'auth_code_123';
      const axiosResponse: AxiosResponse = {
        data: mockTokenResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.post.mockReturnValue(of(axiosResponse));

      // Act
      const result = await service.exchangeCodeForTokens(code);

      // Assert
      expect(result).toEqual(mockTokenResponse);
      expect(httpService.post).toHaveBeenCalledWith(
        'https://oauth2.googleapis.com/token',
        expect.stringContaining('code=auth_code_123'),
        expect.objectContaining({
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 10000,
        })
      );
    });

    it('should throw error for empty authorization code', async () => {
      await expect(service.exchangeCodeForTokens('')).rejects.toThrow(
        'Authorization code is required'
      );
    });

    it('should throw error for non-string authorization code', async () => {
      await expect(service.exchangeCodeForTokens(null as any)).rejects.toThrow(
        'Authorization code is required'
      );
    });

    it('should handle Google API error response', async () => {
      // Arrange
      const code = 'invalid_code';
      const errorResponse = {
        response: {
          data: {
            error: 'invalid_grant',
            error_description: 'Invalid authorization code',
          },
        },
      };
      httpService.post.mockReturnValue(throwError(() => errorResponse));

      // Act & Assert
      await expect(service.exchangeCodeForTokens(code)).rejects.toThrow(
        'Google token exchange failed: Invalid authorization code'
      );
    });

    it('should handle network timeout', async () => {
      // Arrange
      const code = 'timeout_code';
      const timeoutError = { code: 'ECONNABORTED' };
      httpService.post.mockReturnValue(throwError(() => timeoutError));

      // Act & Assert
      await expect(service.exchangeCodeForTokens(code)).rejects.toThrow(
        'Google token exchange timed out'
      );
    });

    it('should throw error when no access token received', async () => {
      // Arrange
      const code = 'code_without_token';
      const axiosResponse: AxiosResponse = {
        data: { token_type: 'Bearer' }, // Missing access_token
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.post.mockReturnValue(of(axiosResponse));

      // Act & Assert
      await expect(service.exchangeCodeForTokens(code)).rejects.toThrow(
        'No access token received from Google'
      );
    });
  });

  describe('getUserInfo', () => {
    const mockUserInfo: GoogleUserInfo = {
      id: 'google_user_123',
      email: 'test@example.com',
      verified_email: true,
      name: 'Test User',
      given_name: 'Test',
      family_name: 'User',
      picture: 'https://example.com/avatar.jpg',
      locale: 'en',
    };

    it('should get user info with valid access token', async () => {
      // Arrange
      const accessToken = 'valid_access_token';
      const axiosResponse: AxiosResponse = {
        data: mockUserInfo,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.get.mockReturnValue(of(axiosResponse));

      // Act
      const result = await service.getUserInfo(accessToken);

      // Assert
      expect(result).toEqual(mockUserInfo);
      expect(httpService.get).toHaveBeenCalledWith(
        'https://www.googleapis.com/oauth2/v2/userinfo',
        expect.objectContaining({
          headers: { Authorization: 'Bearer valid_access_token' },
          timeout: 10000,
        })
      );
    });

    it('should throw error for empty access token', async () => {
      await expect(service.getUserInfo('')).rejects.toThrow(
        'Access token is required'
      );
    });

    it('should throw error for non-string access token', async () => {
      await expect(service.getUserInfo(null as any)).rejects.toThrow(
        'Access token is required'
      );
    });

    it('should handle invalid access token (401)', async () => {
      // Arrange
      const accessToken = 'invalid_token';
      const errorResponse = {
        response: {
          status: 401,
          data: { error: 'invalid_token' },
        },
      };
      httpService.get.mockReturnValue(throwError(() => errorResponse));

      // Act & Assert
      await expect(service.getUserInfo(accessToken)).rejects.toThrow(
        'Invalid or expired access token'
      );
    });

    it('should handle insufficient permissions (403)', async () => {
      // Arrange
      const accessToken = 'limited_token';
      const errorResponse = {
        response: {
          status: 403,
          data: { error: 'insufficient_permissions' },
        },
      };
      httpService.get.mockReturnValue(throwError(() => errorResponse));

      // Act & Assert
      await expect(service.getUserInfo(accessToken)).rejects.toThrow(
        'Insufficient permissions to access user info'
      );
    });

    it('should throw error when user info is invalid', async () => {
      // Arrange
      const accessToken = 'valid_token';
      const axiosResponse: AxiosResponse = {
        data: { name: 'Test User' }, // Missing required id and email
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.get.mockReturnValue(of(axiosResponse));

      // Act & Assert
      await expect(service.getUserInfo(accessToken)).rejects.toThrow(
        'Invalid user info received from Google'
      );
    });

    it('should handle network timeout', async () => {
      // Arrange
      const accessToken = 'timeout_token';
      const timeoutError = { code: 'ECONNABORTED' };
      httpService.get.mockReturnValue(throwError(() => timeoutError));

      // Act & Assert
      await expect(service.getUserInfo(accessToken)).rejects.toThrow(
        'Google user info request timed out'
      );
    });
  });

  describe('refreshTokens', () => {
    const mockRefreshResponse: GoogleTokens = {
      access_token: 'new_access_token',
      refresh_token: 'new_refresh_token',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'openid email profile',
      id_token: 'new_id_token',
    };

    it('should refresh tokens with valid refresh token', async () => {
      // Arrange
      const refreshToken = 'valid_refresh_token';
      const axiosResponse: AxiosResponse = {
        data: mockRefreshResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.post.mockReturnValue(of(axiosResponse));

      // Act
      const result = await service.refreshTokens(refreshToken);

      // Assert
      expect(result).toEqual(mockRefreshResponse);
      expect(httpService.post).toHaveBeenCalledWith(
        'https://oauth2.googleapis.com/token',
        expect.stringContaining('refresh_token=valid_refresh_token'),
        expect.objectContaining({
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 10000,
        })
      );
    });

    it('should keep old refresh token when new one not provided', async () => {
      // Arrange
      const refreshToken = 'old_refresh_token';
      const responseWithoutRefreshToken = {
        access_token: 'new_access_token',
        expires_in: 3600,
        token_type: 'Bearer',
        scope: 'openid email profile',
      };
      const axiosResponse: AxiosResponse = {
        data: responseWithoutRefreshToken,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.post.mockReturnValue(of(axiosResponse));

      // Act
      const result = await service.refreshTokens(refreshToken);

      // Assert
      expect(result.refresh_token).toBe('old_refresh_token');
    });

    it('should throw error for empty refresh token', async () => {
      await expect(service.refreshTokens('')).rejects.toThrow(
        'Refresh token is required'
      );
    });

    it('should handle invalid refresh token', async () => {
      // Arrange
      const refreshToken = 'invalid_refresh_token';
      const errorResponse = {
        response: {
          data: {
            error: 'invalid_grant',
            error_description: 'Invalid refresh token',
          },
        },
      };
      httpService.post.mockReturnValue(throwError(() => errorResponse));

      // Act & Assert
      await expect(service.refreshTokens(refreshToken)).rejects.toThrow(
        'Refresh token is invalid or expired'
      );
    });
  });

  describe('verifyIdToken', () => {
    it('should verify valid ID token', async () => {
      // Arrange
      const idToken = 'valid_id_token';
      const tokenInfo = {
        aud: 'test-client-id',
        iss: 'accounts.google.com',
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
        sub: 'user_123',
        email: 'test@example.com',
      };
      const axiosResponse: AxiosResponse = {
        data: tokenInfo,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.get.mockReturnValue(of(axiosResponse));

      // Act
      const result = await service.verifyIdToken(idToken);

      // Assert
      expect(result).toBe(true);
      expect(httpService.get).toHaveBeenCalledWith(
        `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`,
        expect.objectContaining({ timeout: 10000 })
      );
    });

    it('should return false for empty ID token', async () => {
      const result = await service.verifyIdToken('');
      expect(result).toBe(false);
    });

    it('should return false for wrong audience', async () => {
      // Arrange
      const idToken = 'token_with_wrong_audience';
      const tokenInfo = {
        aud: 'wrong-client-id',
        iss: 'accounts.google.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      const axiosResponse: AxiosResponse = {
        data: tokenInfo,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.get.mockReturnValue(of(axiosResponse));

      // Act
      const result = await service.verifyIdToken(idToken);

      // Assert
      expect(result).toBe(false);
    });

    it('should return false for expired token', async () => {
      // Arrange
      const idToken = 'expired_token';
      const tokenInfo = {
        aud: 'test-client-id',
        iss: 'accounts.google.com',
        exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
      };
      const axiosResponse: AxiosResponse = {
        data: tokenInfo,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.get.mockReturnValue(of(axiosResponse));

      // Act
      const result = await service.verifyIdToken(idToken);

      // Assert
      expect(result).toBe(false);
    });

    it('should return false for invalid issuer', async () => {
      // Arrange
      const idToken = 'token_with_invalid_issuer';
      const tokenInfo = {
        aud: 'test-client-id',
        iss: 'malicious.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      const axiosResponse: AxiosResponse = {
        data: tokenInfo,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.get.mockReturnValue(of(axiosResponse));

      // Act
      const result = await service.verifyIdToken(idToken);

      // Assert
      expect(result).toBe(false);
    });

    it('should return false when verification fails', async () => {
      // Arrange
      const idToken = 'invalid_token';
      httpService.get.mockReturnValue(throwError(() => new Error('Verification failed')));

      // Act
      const result = await service.verifyIdToken(idToken);

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('revokeToken', () => {
    it('should revoke token successfully', async () => {
      // Arrange
      const token = 'token_to_revoke';
      const axiosResponse: AxiosResponse = {
        data: {},
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.post.mockReturnValue(of(axiosResponse));

      // Act
      await service.revokeToken(token);

      // Assert
      expect(httpService.post).toHaveBeenCalledWith(
        `https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(token)}`,
        null,
        expect.objectContaining({ timeout: 10000 })
      );
    });

    it('should throw error for empty token', async () => {
      await expect(service.revokeToken('')).rejects.toThrow('Token is required for revocation');
    });

    it('should not throw error when revocation fails', async () => {
      // Arrange
      const token = 'failing_token';
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      httpService.post.mockReturnValue(throwError(() => new Error('Revocation failed')));

      // Act
      await service.revokeToken(token);

      // Assert
      expect(consoleSpy).toHaveBeenCalledWith('Google token revocation failed:', 'Revocation failed');
      consoleSpy.mockRestore();
    });
  });

  describe('getAuthorizationUrl', () => {
    it('should generate authorization URL with default scopes', () => {
      // Act
      const url = service.getAuthorizationUrl();

      // Assert
      expect(url).toContain('https://accounts.google.com/o/oauth2/v2/auth');
      expect(url).toContain('client_id=test-client-id');
      expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fgoogle%2Fcallback');
      expect(url).toContain('response_type=code');
      expect(url).toContain('scope=openid%20email%20profile');
      expect(url).toContain('access_type=offline');
      expect(url).toContain('prompt=consent');
    });

    it('should generate authorization URL with custom scopes', () => {
      // Arrange
      const customScopes = ['openid', 'email'];

      // Act
      const url = service.getAuthorizationUrl(customScopes);

      // Assert
      expect(url).toContain('scope=openid%20email');
    });

    it('should include state parameter when provided', () => {
      // Arrange
      const state = 'random_state_value';

      // Act
      const url = service.getAuthorizationUrl(undefined, state);

      // Assert
      expect(url).toContain(`state=${state}`);
    });
  });

  describe('validateConfiguration', () => {
    it('should return true for valid configuration', () => {
      expect(service.validateConfiguration()).toBe(true);
    });

    it('should return false for missing configuration', () => {
      // Create service with missing config
      configService.get.mockReturnValue('');
      const invalidService = new GoogleOAuthServiceImpl(configService, httpService);
      
      expect(invalidService.validateConfiguration()).toBe(false);
    });
  });

  describe('getClientId', () => {
    it('should return configured client ID', () => {
      expect(service.getClientId()).toBe('test-client-id');
    });
  });

  describe('validateTokensAndGetUserInfo', () => {
    const mockTokens: GoogleTokens = {
      access_token: 'access_token_123',
      refresh_token: 'refresh_token_123',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'openid email profile',
      id_token: 'id_token_123',
    };

    const mockUserInfo: GoogleUserInfo = {
      id: 'google_user_123',
      email: 'test@example.com',
      verified_email: true,
      name: 'Test User',
      given_name: 'Test',
      family_name: 'User',
      picture: 'https://example.com/avatar.jpg',
      locale: 'en',
    };

    it('should validate tokens and return user info', async () => {
      // Arrange
      const tokenInfo = {
        aud: 'test-client-id',
        iss: 'accounts.google.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      httpService.get
        .mockReturnValueOnce(of({ data: tokenInfo } as AxiosResponse)) // verifyIdToken
        .mockReturnValueOnce(of({ data: mockUserInfo } as AxiosResponse)); // getUserInfo

      // Act
      const result = await service.validateTokensAndGetUserInfo(mockTokens);

      // Assert
      expect(result).toEqual(mockUserInfo);
    });

    it('should skip ID token verification when not provided', async () => {
      // Arrange
      const tokensWithoutIdToken = { ...mockTokens, id_token: undefined };
      httpService.get.mockReturnValueOnce(of({ data: mockUserInfo } as AxiosResponse));

      // Act
      const result = await service.validateTokensAndGetUserInfo(tokensWithoutIdToken);

      // Assert
      expect(result).toEqual(mockUserInfo);
      expect(httpService.get).toHaveBeenCalledTimes(1); // Only getUserInfo called
    });

    it('should throw error for invalid ID token', async () => {
      // Arrange
      httpService.get.mockReturnValueOnce(throwError(() => new Error('Invalid token')));

      // Act & Assert
      await expect(service.validateTokensAndGetUserInfo(mockTokens)).rejects.toThrow('Invalid ID token');
    });
  });
});