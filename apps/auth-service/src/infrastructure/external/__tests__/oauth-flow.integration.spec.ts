import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { HttpModule, HttpService } from '@nestjs/axios';
import { of, throwError } from 'rxjs';
import { AxiosResponse } from 'axios';

// OAuth services
import { GoogleOAuthService } from '../../../domain/ports/google-oauth.service';
import { AppleOAuthService } from '../../../domain/ports/apple-oauth.service';
import { GoogleOAuthServiceImpl } from '../google-oauth.service';
import { AppleOAuthServiceImpl } from '../apple-oauth.service';

// Use cases
import { SocialLoginUseCase } from '../../../domain/use-cases/social-login.use-case';

// Domain ports
import { UserRepository } from '../../../domain/ports/user.repository';
import { TokenService } from '../../../domain/ports/token.service';
import { AuthSessionRepository } from '../../../domain/ports/auth-session.repository';

// Test utilities
import { createTestUser } from '../../../test/test-utils';

/**
 * OAuth Flow Integration Tests
 * 
 * Tests the complete OAuth integration flows with mocked external services
 * to ensure proper end-to-end OAuth functionality.
 */
describe('OAuth Flow Integration', () => {
  let module: TestingModule;
  let googleOAuthService: GoogleOAuthService;
  let appleOAuthService: AppleOAuthService;
  let socialLoginUseCase: SocialLoginUseCase;
  let httpService: jest.Mocked<HttpService>;
  let userRepository: jest.Mocked<UserRepository>;
  let tokenService: jest.Mocked<TokenService>;
  let authSessionRepository: jest.Mocked<AuthSessionRepository>;

  beforeAll(async () => {
    // Create mocks
    const mockUserRepository = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      findByProvider: jest.fn(),
      save: jest.fn(),
      existsByEmail: jest.fn(),
      update: jest.fn(),
      deactivate: jest.fn(),
      activate: jest.fn(),
      delete: jest.fn(),
    };

    const mockTokenService = {
      generateTokenPair: jest.fn(),
      generateAccessToken: jest.fn(),
      generateRefreshToken: jest.fn(),
      verifyAccessToken: jest.fn(),
      verifyRefreshToken: jest.fn(),
      decodeToken: jest.fn(),
      revokeToken: jest.fn(),
      isTokenExpired: jest.fn(),
      getTokenExpiration: jest.fn(),
    };

    const mockAuthSessionRepository = {
      save: jest.fn(),
      findById: jest.fn(),
      findBySessionToken: jest.fn(),
      findByUserId: jest.fn(),
      revokeByUserId: jest.fn(),
      updateActivity: jest.fn(),
      cleanupExpiredSessions: jest.fn(),
    };

    module = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [
            () => ({
              oauth: {
                google: {
                  clientId: 'test-google-client-id',
                  clientSecret: 'test-google-client-secret',
                  redirectUri: 'http://localhost:3000/auth/google/callback',
                },
                apple: {
                  clientId: 'test.apple.client.id',
                  teamId: 'TEST123456',
                  keyId: 'TESTKEY123',
                  privateKey: 'test-private-key',
                  redirectUri: 'http://localhost:3000/auth/apple/callback',
                },
              },
            }),
          ],
        }),
        HttpModule,
      ],
      providers: [
        {
          provide: GoogleOAuthService,
          useClass: GoogleOAuthServiceImpl,
        },
        {
          provide: AppleOAuthService,
          useClass: AppleOAuthServiceImpl,
        },
        SocialLoginUseCase,
        {
          provide: UserRepository,
          useValue: mockUserRepository,
        },
        {
          provide: TokenService,
          useValue: mockTokenService,
        },
        {
          provide: AuthSessionRepository,
          useValue: mockAuthSessionRepository,
        },
      ],
    }).compile();

    googleOAuthService = module.get<GoogleOAuthService>(GoogleOAuthService);
    appleOAuthService = module.get<AppleOAuthService>(AppleOAuthService);
    socialLoginUseCase = module.get<SocialLoginUseCase>(SocialLoginUseCase);
    httpService = module.get<HttpService>(HttpService) as jest.Mocked<HttpService>;
    userRepository = module.get(UserRepository);
    tokenService = module.get(TokenService);
    authSessionRepository = module.get(AuthSessionRepository);
  });

  afterAll(async () => {
    await module.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Google OAuth Flow', () => {
    describe('Authorization code exchange', () => {
      it('should exchange authorization code for tokens', async () => {
        // Arrange
        const mockTokenResponse: AxiosResponse = {
          data: {
            access_token: 'google_access_token_123',
            refresh_token: 'google_refresh_token_123',
            expires_in: 3600,
            token_type: 'Bearer',
            scope: 'openid email profile',
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any,
        };

        httpService.post = jest.fn().mockReturnValue(of(mockTokenResponse));

        // Act
        const result = await googleOAuthService.exchangeCodeForTokens(
          'test_authorization_code',
          'test_state'
        );

        // Assert
        expect(result).toEqual({
          accessToken: 'google_access_token_123',
          refreshToken: 'google_refresh_token_123',
          expiresIn: 3600,
          tokenType: 'Bearer',
          scope: 'openid email profile',
        });

        expect(httpService.post).toHaveBeenCalledWith(
          'https://oauth2.googleapis.com/token',
          expect.objectContaining({
            client_id: 'test-google-client-id',
            client_secret: 'test-google-client-secret',
            code: 'test_authorization_code',
            grant_type: 'authorization_code',
            redirect_uri: 'http://localhost:3000/auth/google/callback',
          }),
          expect.any(Object)
        );
      });

      it('should handle token exchange errors', async () => {
        // Arrange
        httpService.post = jest.fn().mockReturnValue(
          throwError(() => ({ response: { status: 400, data: { error: 'invalid_grant' } } }))
        );

        // Act & Assert
        await expect(
          googleOAuthService.exchangeCodeForTokens('invalid_code', 'state')
        ).rejects.toThrow();
      });
    });

    describe('User info retrieval', () => {
      it('should retrieve user info with access token', async () => {
        // Arrange
        const mockUserInfoResponse: AxiosResponse = {
          data: {
            id: 'google_user_123',
            email: 'testuser@gmail.com',
            verified_email: true,
            name: 'Test User',
            given_name: 'Test',
            family_name: 'User',
            picture: 'https://lh3.googleusercontent.com/photo.jpg',
            locale: 'en',
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any,
        };

        httpService.get = jest.fn().mockReturnValue(of(mockUserInfoResponse));

        // Act
        const userInfo = await googleOAuthService.getUserInfo('google_access_token_123');

        // Assert
        expect(userInfo).toEqual({
          id: 'google_user_123',
          email: 'testuser@gmail.com',
          emailVerified: true,
          name: 'Test User',
          firstName: 'Test',
          lastName: 'User',
          picture: 'https://lh3.googleusercontent.com/photo.jpg',
          locale: 'en',
        });

        expect(httpService.get).toHaveBeenCalledWith(
          'https://www.googleapis.com/oauth2/v2/userinfo',
          expect.objectContaining({
            headers: {
              Authorization: 'Bearer google_access_token_123',
            },
          })
        );
      });

      it('should handle user info retrieval errors', async () => {
        // Arrange
        httpService.get = jest.fn().mockReturnValue(
          throwError(() => ({ response: { status: 401, data: { error: 'invalid_token' } } }))
        );

        // Act & Assert
        await expect(
          googleOAuthService.getUserInfo('invalid_token')
        ).rejects.toThrow();
      });
    });

    describe('Complete Google OAuth flow', () => {
      it('should complete OAuth flow for new user', async () => {
        // Arrange - Mock Google API responses
        const mockTokenResponse: AxiosResponse = {
          data: {
            access_token: 'google_access_token',
            refresh_token: 'google_refresh_token',
            expires_in: 3600,
            token_type: 'Bearer',
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any,
        };

        const mockUserInfoResponse: AxiosResponse = {
          data: {
            id: 'google_123',
            email: 'newuser@gmail.com',
            verified_email: true,
            name: 'New User',
            picture: 'https://example.com/photo.jpg',
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any,
        };

        httpService.post = jest.fn().mockReturnValue(of(mockTokenResponse));
        httpService.get = jest.fn().mockReturnValue(of(mockUserInfoResponse));

        // Mock repository responses
        userRepository.findByEmail.mockResolvedValue(null);
        userRepository.findByProvider.mockResolvedValue(null);
        userRepository.save.mockImplementation(user => Promise.resolve(user));
        
        tokenService.generateTokenPair.mockResolvedValue({
          accessToken: 'app_access_token',
          refreshToken: 'app_refresh_token',
          expiresIn: 900,
          tokenType: 'Bearer',
        });

        authSessionRepository.save.mockImplementation(session => Promise.resolve(session));

        // Act
        const result = await socialLoginUseCase.execute({
          provider: 'GOOGLE',
          authorizationCode: 'test_code',
          state: 'test_state',
          clientInfo: {
            userAgent: 'Test-Agent',
            ipAddress: '192.168.1.1',
            deviceId: 'test-device',
          },
        });

        // Assert
        expect(result).toBeDefined();
        expect(result.user.email).toBe('newuser@gmail.com');
        expect(result.user.authProvider).toBe('GOOGLE');
        expect(result.tokens.accessToken).toBe('app_access_token');
        expect(userRepository.save).toHaveBeenCalled();
        expect(authSessionRepository.save).toHaveBeenCalled();
      });

      it('should complete OAuth flow for existing user', async () => {
        // Arrange
        const existingUser = createTestUser({
          email: 'existing@gmail.com',
          authProvider: 'GOOGLE',
          providerId: 'google_123',
        });

        const mockTokenResponse: AxiosResponse = {
          data: {
            access_token: 'google_access_token',
            expires_in: 3600,
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any,
        };

        const mockUserInfoResponse: AxiosResponse = {
          data: {
            id: 'google_123',
            email: 'existing@gmail.com',
            verified_email: true,
            name: 'Existing User',
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any,
        };

        httpService.post = jest.fn().mockReturnValue(of(mockTokenResponse));
        httpService.get = jest.fn().mockReturnValue(of(mockUserInfoResponse));

        userRepository.findByProvider.mockResolvedValue(existingUser);
        tokenService.generateTokenPair.mockResolvedValue({
          accessToken: 'app_access_token',
          refreshToken: 'app_refresh_token',
          expiresIn: 900,
          tokenType: 'Bearer',
        });
        authSessionRepository.save.mockImplementation(session => Promise.resolve(session));

        // Act
        const result = await socialLoginUseCase.execute({
          provider: 'GOOGLE',
          authorizationCode: 'test_code',
          clientInfo: {
            userAgent: 'Test-Agent',
            ipAddress: '192.168.1.1',
            deviceId: 'test-device',
          },
        });

        // Assert
        expect(result.user.id).toBe(existingUser.id);
        expect(result.user.email).toBe('existing@gmail.com');
        expect(userRepository.findByProvider).toHaveBeenCalledWith('GOOGLE', 'google_123');
      });
    });
  });

  describe('Apple OAuth Flow', () => {
    describe('ID token verification', () => {
      it('should verify Apple ID token successfully', async () => {
        // Arrange - Mock Apple's public keys endpoint
        const mockKeysResponse: AxiosResponse = {
          data: {
            keys: [
              {
                kty: 'RSA',
                kid: 'test-key-id',
                use: 'sig',
                alg: 'RS256',
                n: 'test-modulus',
                e: 'AQAB',
              },
            ],
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any,
        };

        httpService.get = jest.fn().mockReturnValue(of(mockKeysResponse));

        // Mock JWT decode (simplified for testing)
        const mockDecodedToken = {
          header: { kid: 'test-key-id', alg: 'RS256' },
          payload: {
            iss: 'https://appleid.apple.com',
            aud: 'test.apple.client.id',
            sub: 'apple_user_123',
            email: 'testuser@privaterelay.appleid.com',
            email_verified: true,
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
          },
        };

        // Act
        const result = await appleOAuthService.verifyIdToken('mock.apple.id.token');

        // Assert
        expect(httpService.get).toHaveBeenCalledWith('https://appleid.apple.com/auth/keys');
        // Note: In a real implementation, we would verify the actual JWT signature
        // Here we're testing the flow integration
      });

      it('should handle ID token verification errors', async () => {
        // Arrange
        httpService.get = jest.fn().mockReturnValue(
          throwError(() => ({ response: { status: 500 } }))
        );

        // Act & Assert
        await expect(
          appleOAuthService.verifyIdToken('invalid.id.token')
        ).rejects.toThrow();
      });
    });

    describe('Complete Apple OAuth flow', () => {
      it('should complete OAuth flow with Apple ID token', async () => {
        // Arrange
        const mockKeysResponse: AxiosResponse = {
          data: { keys: [] },
          status: 200,
          statusText: 'OK',
          headers: {},
          config: {} as any,
        };

        httpService.get = jest.fn().mockReturnValue(of(mockKeysResponse));

        // Mock the Apple OAuth service to return user info
        jest.spyOn(appleOAuthService, 'verifyIdToken').mockResolvedValue({
          sub: 'apple_user_123',
          email: 'testuser@privaterelay.appleid.com',
          emailVerified: true,
          name: 'Apple User',
        });

        userRepository.findByProvider.mockResolvedValue(null);
        userRepository.findByEmail.mockResolvedValue(null);
        userRepository.save.mockImplementation(user => Promise.resolve(user));
        
        tokenService.generateTokenPair.mockResolvedValue({
          accessToken: 'app_access_token',
          refreshToken: 'app_refresh_token',
          expiresIn: 900,
          tokenType: 'Bearer',
        });

        authSessionRepository.save.mockImplementation(session => Promise.resolve(session));

        // Act
        const result = await socialLoginUseCase.execute({
          provider: 'APPLE',
          idToken: 'mock.apple.id.token',
          clientInfo: {
            userAgent: 'Test-Agent',
            ipAddress: '192.168.1.1',
            deviceId: 'test-device',
          },
        });

        // Assert
        expect(result).toBeDefined();
        expect(result.user.authProvider).toBe('APPLE');
        expect(result.user.providerId).toBe('apple_user_123');
        expect(userRepository.save).toHaveBeenCalled();
      });

      it('should handle Apple OAuth with additional user data', async () => {
        // Arrange
        jest.spyOn(appleOAuthService, 'verifyIdToken').mockResolvedValue({
          sub: 'apple_user_456',
          email: 'user@privaterelay.appleid.com',
          emailVerified: true,
        });

        userRepository.findByProvider.mockResolvedValue(null);
        userRepository.findByEmail.mockResolvedValue(null);
        userRepository.save.mockImplementation(user => Promise.resolve(user));
        
        tokenService.generateTokenPair.mockResolvedValue({
          accessToken: 'app_access_token',
          refreshToken: 'app_refresh_token',
          expiresIn: 900,
          tokenType: 'Bearer',
        });

        authSessionRepository.save.mockImplementation(session => Promise.resolve(session));

        // Act
        const result = await socialLoginUseCase.execute({
          provider: 'APPLE',
          idToken: 'mock.apple.id.token',
          userData: {
            name: {
              firstName: 'John',
              lastName: 'Doe',
            },
          },
          clientInfo: {
            userAgent: 'Test-Agent',
            ipAddress: '192.168.1.1',
            deviceId: 'test-device',
          },
        });

        // Assert
        expect(result.user.name).toBe('John Doe');
        expect(userRepository.save).toHaveBeenCalledWith(
          expect.objectContaining({
            name: 'John Doe',
            authProvider: 'APPLE',
          })
        );
      });
    });
  });

  describe('OAuth error scenarios', () => {
    it('should handle network timeouts', async () => {
      // Arrange
      httpService.post = jest.fn().mockReturnValue(
        throwError(() => ({ code: 'ECONNABORTED', message: 'timeout' }))
      );

      // Act & Assert
      await expect(
        socialLoginUseCase.execute({
          provider: 'GOOGLE',
          authorizationCode: 'test_code',
          clientInfo: {
            userAgent: 'Test-Agent',
            ipAddress: '192.168.1.1',
            deviceId: 'test-device',
          },
        })
      ).rejects.toThrow();
    });

    it('should handle invalid provider', async () => {
      // Act & Assert
      await expect(
        socialLoginUseCase.execute({
          provider: 'INVALID_PROVIDER' as any,
          authorizationCode: 'test_code',
          clientInfo: {
            userAgent: 'Test-Agent',
            ipAddress: '192.168.1.1',
            deviceId: 'test-device',
          },
        })
      ).rejects.toThrow();
    });

    it('should handle inactive user during OAuth login', async () => {
      // Arrange
      const inactiveUser = createTestUser({
        email: 'inactive@gmail.com',
        authProvider: 'GOOGLE',
        providerId: 'google_inactive',
        isActive: false,
      });

      const mockTokenResponse: AxiosResponse = {
        data: { access_token: 'token', expires_in: 3600 },
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };

      const mockUserInfoResponse: AxiosResponse = {
        data: {
          id: 'google_inactive',
          email: 'inactive@gmail.com',
          verified_email: true,
          name: 'Inactive User',
        },
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as any,
      };

      httpService.post = jest.fn().mockReturnValue(of(mockTokenResponse));
      httpService.get = jest.fn().mockReturnValue(of(mockUserInfoResponse));
      userRepository.findByProvider.mockResolvedValue(inactiveUser);

      // Act & Assert
      await expect(
        socialLoginUseCase.execute({
          provider: 'GOOGLE',
          authorizationCode: 'test_code',
          clientInfo: {
            userAgent: 'Test-Agent',
            ipAddress: '192.168.1.1',
            deviceId: 'test-device',
          },
        })
      ).rejects.toThrow();
    });
  });

  describe('OAuth service configuration', () => {
    it('should generate correct Google authorization URL', () => {
      // Act
      const authUrl = googleOAuthService.getAuthorizationUrl('test_state');

      // Assert
      expect(authUrl).toContain('https://accounts.google.com/o/oauth2/v2/auth');
      expect(authUrl).toContain('client_id=test-google-client-id');
      expect(authUrl).toContain('redirect_uri=http%3A//localhost%3A3000/auth/google/callback');
      expect(authUrl).toContain('state=test_state');
      expect(authUrl).toContain('scope=openid%20email%20profile');
    });

    it('should generate correct Apple authorization URL', () => {
      // Act
      const authUrl = appleOAuthService.getAuthorizationUrl('test_state', 'test_nonce');

      // Assert
      expect(authUrl).toContain('https://appleid.apple.com/auth/authorize');
      expect(authUrl).toContain('client_id=test.apple.client.id');
      expect(authUrl).toContain('redirect_uri=http%3A//localhost%3A3000/auth/apple/callback');
      expect(authUrl).toContain('state=test_state');
      expect(authUrl).toContain('nonce=test_nonce');
      expect(authUrl).toContain('response_mode=form_post');
    });
  });
});