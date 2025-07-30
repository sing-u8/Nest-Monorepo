import { Test, TestingModule } from '@nestjs/testing';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { of, throwError } from 'rxjs';
import { AxiosResponse } from 'axios';
import { AppleOAuthServiceImpl } from '../apple-oauth.service.impl';
import { AppleUserInfo } from '../../domain/ports/apple-oauth.service';

describe('AppleOAuthServiceImpl', () => {
  let service: AppleOAuthServiceImpl;
  let httpService: jest.Mocked<HttpService>;
  let configService: jest.Mocked<ConfigService>;

  const mockConfig = {
    'oauth.apple.clientId': 'com.example.app',
    'oauth.apple.teamId': 'TEAM123ABC',
    'oauth.apple.keyId': 'KEY123ABC',
    'oauth.apple.privateKey': '-----BEGIN PRIVATE KEY-----\nMOCK_PRIVATE_KEY\n-----END PRIVATE KEY-----',
    'oauth.apple.callbackUrl': 'http://localhost:3000/auth/apple/callback',
  };

  const mockAppleKeys = {
    keys: [
      {
        kty: 'RSA',
        kid: 'YuyXoY',
        use: 'sig',
        alg: 'RS256',
        n: 'mock_modulus_value',
        e: 'AQAB',
      },
      {
        kty: 'RSA',
        kid: 'W6WcOKB',
        use: 'sig',
        alg: 'RS256',
        n: 'another_mock_modulus',
        e: 'AQAB',
      },
    ],
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
        AppleOAuthServiceImpl,
        { provide: HttpService, useValue: mockHttpService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    service = module.get<AppleOAuthServiceImpl>(AppleOAuthServiceImpl);
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
        new AppleOAuthServiceImpl(configService, httpService);
      }).toThrow('Apple OAuth configuration is missing');
    });
  });

  describe('verifyIdToken', () => {
    const mockIdToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IllXNWhZbUZ1WjJWeUlEQkJNekEwTmpBME56QTJORGN4TWpJM1ptVXhNV1F5';

    beforeEach(() => {
      // Mock Apple keys endpoint
      const axiosResponse: AxiosResponse = {
        data: mockAppleKeys,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.get.mockReturnValue(of(axiosResponse));
    });

    it('should return false for empty token', async () => {
      const result = await service.verifyIdToken('');
      expect(result).toBe(false);
    });

    it('should return false for non-string token', async () => {
      const result = await service.verifyIdToken(null as any);
      expect(result).toBe(false);
    });

    it('should return false for malformed token', async () => {
      const result = await service.verifyIdToken('invalid.token');
      expect(result).toBe(false);
    });

    it('should return false when Apple keys fetch fails', async () => {
      // Arrange
      httpService.get.mockReturnValue(throwError(() => new Error('Network error')));

      // Act
      const result = await service.verifyIdToken(mockIdToken);

      // Assert
      expect(result).toBe(false);
    });

    it('should cache Apple public keys', async () => {
      // Arrange
      const axiosResponse: AxiosResponse = {
        data: mockAppleKeys,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.get.mockReturnValue(of(axiosResponse));

      // Act - Call twice
      await service.verifyIdToken(mockIdToken);
      await service.verifyIdToken(mockIdToken);

      // Assert - Should only fetch keys once
      expect(httpService.get).toHaveBeenCalledTimes(1);
      expect(httpService.get).toHaveBeenCalledWith(
        'https://appleid.apple.com/auth/keys',
        expect.objectContaining({ timeout: 10000 })
      );
    });
  });

  describe('extractUserInfo', () => {
    const mockValidIdToken = 'valid.id.token';
    const mockUserData = {
      name: {
        firstName: 'John',
        lastName: 'Doe',
      },
    };

    beforeEach(() => {
      // Mock token verification to return true
      jest.spyOn(service, 'verifyIdToken').mockResolvedValue(true);
      
      // Mock token payload decoding
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue({
        sub: 'apple_user_123',
        email: 'john.doe@example.com',
        email_verified: 'true',
      });
    });

    it('should extract user info from valid ID token', async () => {
      // Act
      const result = await service.extractUserInfo(mockValidIdToken);

      // Assert
      expect(result).toEqual({
        sub: 'apple_user_123',
        email: 'john.doe@example.com',
        email_verified: true,
        name: 'John.doe',
      });
    });

    it('should extract user info with additional user data', async () => {
      // Act
      const result = await service.extractUserInfo(mockValidIdToken, mockUserData);

      // Assert
      expect(result).toEqual({
        sub: 'apple_user_123',
        email: 'john.doe@example.com',
        email_verified: true,
        name: 'John Doe',
      });
    });

    it('should handle string name in user data', async () => {
      // Arrange
      const userDataWithStringName = { name: 'Jane Smith' };

      // Act
      const result = await service.extractUserInfo(mockValidIdToken, userDataWithStringName);

      // Assert
      expect(result.name).toBe('Jane Smith');
    });

    it('should generate display name from email when name not provided', async () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue({
        sub: 'apple_user_456',
        email: 'testuser@example.com',
        email_verified: 'true',
      });

      // Act
      const result = await service.extractUserInfo(mockValidIdToken);

      // Assert
      expect(result.name).toBe('Testuser');
    });

    it('should throw error for invalid ID token', async () => {
      // Arrange
      jest.spyOn(service, 'verifyIdToken').mockResolvedValue(false);

      // Act & Assert
      await expect(service.extractUserInfo('invalid.token')).rejects.toThrow(
        'Invalid Apple ID token'
      );
    });

    it('should throw error when payload decoding fails', async () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue(null);

      // Act & Assert
      await expect(service.extractUserInfo(mockValidIdToken)).rejects.toThrow(
        'Failed to decode ID token payload'
      );
    });

    it('should throw error when required user info is missing', async () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue({
        sub: 'apple_user_123',
        // Missing email
      });

      // Act & Assert
      await expect(service.extractUserInfo(mockValidIdToken)).rejects.toThrow(
        'Missing required user information in ID token'
      );
    });
  });

  describe('validateNonce', () => {
    const mockIdToken = 'token.with.nonce';
    const expectedNonce = 'test_nonce_123';

    it('should return true for matching nonce', async () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue({
        nonce: expectedNonce,
      });

      // Act
      const result = await service.validateNonce(mockIdToken, expectedNonce);

      // Assert
      expect(result).toBe(true);
    });

    it('should return false for mismatched nonce', async () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue({
        nonce: 'different_nonce',
      });

      // Act
      const result = await service.validateNonce(mockIdToken, expectedNonce);

      // Assert
      expect(result).toBe(false);
    });

    it('should return false when nonce is missing from token', async () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue({
        sub: 'user_123',
        // No nonce field
      });

      // Act
      const result = await service.validateNonce(mockIdToken, expectedNonce);

      // Assert
      expect(result).toBe(false);
    });

    it('should return false when payload decoding fails', async () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue(null);

      // Act
      const result = await service.validateNonce(mockIdToken, expectedNonce);

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('generateClientSecret', () => {
    it('should generate a valid client secret JWT', () => {
      // Act
      const clientSecret = service.generateClientSecret();

      // Assert
      expect(clientSecret).toBeDefined();
      expect(typeof clientSecret).toBe('string');
      expect(clientSecret.split('.')).toHaveLength(3); // JWT format
    });

    it('should throw error when JWT signing fails', () => {
      // Arrange
      // Create service with invalid private key
      configService.get.mockImplementation((key: string) => {
        if (key === 'oauth.apple.privateKey') return 'invalid_key';
        return mockConfig[key];
      });

      // Act & Assert
      expect(() => {
        const invalidService = new AppleOAuthServiceImpl(configService, httpService);
        invalidService.generateClientSecret();
      }).toThrow('Failed to generate client secret');
    });
  });

  describe('getAuthorizationUrl', () => {
    it('should generate authorization URL with default scopes', () => {
      // Act
      const url = service.getAuthorizationUrl();

      // Assert
      expect(url).toContain('https://appleid.apple.com/auth/authorize');
      expect(url).toContain('client_id=com.example.app');
      expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fapple%2Fcallback');
      expect(url).toContain('response_type=code%20id_token');
      expect(url).toContain('scope=name%20email');
      expect(url).toContain('response_mode=form_post');
    });

    it('should generate authorization URL with custom scopes', () => {
      // Arrange
      const customScopes = ['email'];

      // Act
      const url = service.getAuthorizationUrl(customScopes);

      // Assert
      expect(url).toContain('scope=email');
    });

    it('should include state parameter when provided', () => {
      // Arrange
      const state = 'random_state_value';

      // Act
      const url = service.getAuthorizationUrl(undefined, state);

      // Assert
      expect(url).toContain(`state=${state}`);
    });

    it('should include nonce parameter when provided', () => {
      // Arrange
      const nonce = 'random_nonce_value';

      // Act
      const url = service.getAuthorizationUrl(undefined, undefined, nonce);

      // Assert
      expect(url).toContain(`nonce=${nonce}`);
    });
  });

  describe('revokeToken', () => {
    it('should revoke token successfully', async () => {
      // Arrange
      const refreshToken = 'token_to_revoke';
      const axiosResponse: AxiosResponse = {
        data: {},
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };
      httpService.post.mockReturnValue(of(axiosResponse));

      // Act
      await service.revokeToken(refreshToken);

      // Assert
      expect(httpService.post).toHaveBeenCalledWith(
        'https://appleid.apple.com/auth/revoke',
        expect.stringContaining('token=token_to_revoke'),
        expect.objectContaining({
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 10000,
        })
      );
    });

    it('should throw error for empty refresh token', async () => {
      await expect(service.revokeToken('')).rejects.toThrow(
        'Refresh token is required for revocation'
      );
    });

    it('should throw error for non-string refresh token', async () => {
      await expect(service.revokeToken(null as any)).rejects.toThrow(
        'Refresh token is required for revocation'
      );
    });

    it('should not throw error when revocation fails', async () => {
      // Arrange
      const refreshToken = 'failing_token';
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      httpService.post.mockReturnValue(throwError(() => new Error('Revocation failed')));

      // Act
      await service.revokeToken(refreshToken);

      // Assert
      expect(consoleSpy).toHaveBeenCalledWith('Apple token revocation failed:', 'Revocation failed');
      consoleSpy.mockRestore();
    });
  });

  describe('validateConfiguration', () => {
    it('should return true for valid configuration', () => {
      expect(service.validateConfiguration()).toBe(true);
    });

    it('should return false for missing configuration', () => {
      // Create service with missing config
      configService.get.mockImplementation((key: string) => {
        if (key === 'oauth.apple.clientId') return '';
        return mockConfig[key];
      });
      
      expect(() => {
        new AppleOAuthServiceImpl(configService, httpService);
      }).toThrow('Apple OAuth configuration is missing');
    });
  });

  describe('getClientId', () => {
    it('should return configured client ID', () => {
      expect(service.getClientId()).toBe('com.example.app');
    });
  });

  describe('extractUserIdFromIdToken', () => {
    it('should extract user ID from ID token', () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue({
        sub: 'apple_user_123',
        email: 'test@example.com',
      });

      // Act
      const userId = service.extractUserIdFromIdToken('valid.token');

      // Assert
      expect(userId).toBe('apple_user_123');
    });

    it('should return null for invalid token', () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue(null);

      // Act
      const userId = service.extractUserIdFromIdToken('invalid.token');

      // Assert
      expect(userId).toBeNull();
    });

    it('should return null when sub is missing', () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue({
        email: 'test@example.com',
        // Missing sub
      });

      // Act
      const userId = service.extractUserIdFromIdToken('token.without.sub');

      // Assert
      expect(userId).toBeNull();
    });
  });

  describe('isTokenExpired', () => {
    it('should return false for valid token', () => {
      // Arrange
      const futureExp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue({
        exp: futureExp,
      });

      // Act
      const isExpired = service.isTokenExpired('valid.token');

      // Assert
      expect(isExpired).toBe(false);
    });

    it('should return true for expired token', () => {
      // Arrange
      const pastExp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue({
        exp: pastExp,
      });

      // Act
      const isExpired = service.isTokenExpired('expired.token');

      // Assert
      expect(isExpired).toBe(true);
    });

    it('should return true when exp is missing', () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue({
        sub: 'user_123',
        // Missing exp
      });

      // Act
      const isExpired = service.isTokenExpired('token.without.exp');

      // Assert
      expect(isExpired).toBe(true);
    });

    it('should return true for invalid token', () => {
      // Arrange
      jest.spyOn(service as any, 'decodeJwtPayload').mockReturnValue(null);

      // Act
      const isExpired = service.isTokenExpired('invalid.token');

      // Assert
      expect(isExpired).toBe(true);
    });
  });

  describe('private methods', () => {
    describe('decodeJwtHeader', () => {
      it('should decode JWT header', () => {
        // Arrange
        const mockHeader = { alg: 'RS256', kid: 'YuyXoY' };
        const encodedHeader = Buffer.from(JSON.stringify(mockHeader)).toString('base64');
        const token = `${encodedHeader}.payload.signature`;

        // Act
        const result = (service as any).decodeJwtHeader(token);

        // Assert
        expect(result).toEqual(mockHeader);
      });

      it('should return null for invalid token format', () => {
        // Act
        const result = (service as any).decodeJwtHeader('invalid.token');

        // Assert
        expect(result).toBeNull();
      });
    });

    describe('decodeJwtPayload', () => {
      it('should decode JWT payload', () => {
        // Arrange
        const mockPayload = { sub: 'user_123', email: 'test@example.com' };
        const encodedPayload = Buffer.from(JSON.stringify(mockPayload)).toString('base64');
        const token = `header.${encodedPayload}.signature`;

        // Act
        const result = (service as any).decodeJwtPayload(token);

        // Assert
        expect(result).toEqual(mockPayload);
      });

      it('should return null for invalid token format', () => {
        // Act
        const result = (service as any).decodeJwtPayload('invalid');

        // Assert
        expect(result).toBeNull();
      });
    });

    describe('base64UrlToBase64', () => {
      it('should convert base64url to base64', () => {
        // Arrange
        const base64Url = 'SGVsbG8tV29ybGQ';

        // Act
        const result = (service as any).base64UrlToBase64(base64Url);

        // Assert
        expect(result).toBe('SGVsbG8tV29ybGQ=');
      });

      it('should handle padding correctly', () => {
        // Arrange
        const base64Url = 'SGVsbG8';

        // Act
        const result = (service as any).base64UrlToBase64(base64Url);

        // Assert
        expect(result).toBe('SGVsbG8=');
      });
    });
  });
});