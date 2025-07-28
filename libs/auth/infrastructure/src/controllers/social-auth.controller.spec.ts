import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, UnauthorizedException, InternalServerErrorException } from '@nestjs/common';
import { Request, Response } from 'express';
import { SocialAuthController } from './social-auth.controller';
import { SocialLoginUseCase, AuthPresenter } from '@auth/domain';
import { GoogleOAuthService, AppleOAuthService } from '../services';
import { GoogleCallbackQuery, AppleCallbackRequest } from '@auth/shared';

describe('SocialAuthController', () => {
  let controller: SocialAuthController;
  let socialLoginUseCase: jest.Mocked<SocialLoginUseCase>;
  let authPresenter: jest.Mocked<AuthPresenter>;
  let googleOAuthService: jest.Mocked<GoogleOAuthService>;
  let appleOAuthService: jest.Mocked<AppleOAuthService>;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;

  beforeEach(async () => {
    // Create mocked use case and services
    socialLoginUseCase = {
      execute: jest.fn(),
    } as any;

    authPresenter = {
      presentSocialLoginSuccess: jest.fn(),
      presentOAuthError: jest.fn(),
      presentValidationError: jest.fn(),
      presentInternalError: jest.fn(),
    } as any;

    googleOAuthService = {
      generateAuthUrl: jest.fn(),
      exchangeCodeForTokens: jest.fn(),
      getUserProfile: jest.fn(),
      getConfiguration: jest.fn(),
    } as any;

    appleOAuthService = {
      generateAuthUrl: jest.fn(),
      validateIdToken: jest.fn(),
      getConfiguration: jest.fn(),
    } as any;

    // Create mock Express objects
    mockRequest = {
      headers: {
        'user-agent': 'Mozilla/5.0 Test Browser',
        'x-forwarded-for': '192.168.1.1',
      },
      connection: {
        remoteAddress: '192.168.1.1',
      },
    } as any;

    mockResponse = {
      redirect: jest.fn(),
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      controllers: [SocialAuthController],
      providers: [
        {
          provide: 'SocialLoginUseCase',
          useValue: socialLoginUseCase,
        },
        {
          provide: 'AuthPresenter',
          useValue: authPresenter,
        },
        {
          provide: GoogleOAuthService,
          useValue: googleOAuthService,
        },
        {
          provide: AppleOAuthService,
          useValue: appleOAuthService,
        },
      ],
    }).compile();

    controller = module.get<SocialAuthController>(SocialAuthController);

    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('initiateGoogleAuth', () => {
    it('should redirect to Google OAuth URL', async () => {
      const mockAuthUrl = 'https://accounts.google.com/oauth/authorize?client_id=test&state=state123';
      googleOAuthService.generateAuthUrl.mockResolvedValue(mockAuthUrl);

      await controller.initiateGoogleAuth('state123', undefined, mockResponse as Response);

      expect(googleOAuthService.generateAuthUrl).toHaveBeenCalledWith('state123');
      expect(mockResponse.redirect).toHaveBeenCalledWith(mockAuthUrl);
    });

    it('should generate secure state if not provided', async () => {
      const mockAuthUrl = 'https://accounts.google.com/oauth/authorize?client_id=test';
      googleOAuthService.generateAuthUrl.mockResolvedValue(mockAuthUrl);

      await controller.initiateGoogleAuth(undefined, undefined, mockResponse as Response);

      expect(googleOAuthService.generateAuthUrl).toHaveBeenCalledWith(expect.any(String));
      expect(mockResponse.redirect).toHaveBeenCalledWith(mockAuthUrl);
    });

    it('should encode redirect URI in state', async () => {
      const mockAuthUrl = 'https://accounts.google.com/oauth/authorize?client_id=test';
      const redirectUri = 'https://app.com/dashboard';
      googleOAuthService.generateAuthUrl.mockResolvedValue(mockAuthUrl);

      await controller.initiateGoogleAuth('state123', redirectUri, mockResponse as Response);

      const expectedState = `state123|${Buffer.from(redirectUri).toString('base64')}`;
      expect(googleOAuthService.generateAuthUrl).toHaveBeenCalledWith(expectedState);
    });

    it('should handle OAuth service errors', async () => {
      googleOAuthService.generateAuthUrl.mockRejectedValue(new Error('OAuth service error'));
      authPresenter.presentOAuthError.mockReturnValue({
        success: false,
        error: 'OAUTH_ERROR',
        message: 'Failed to initiate Google OAuth flow',
      });

      await expect(
        controller.initiateGoogleAuth('state123', undefined, mockResponse as Response)
      ).rejects.toThrow(InternalServerErrorException);

      expect(authPresenter.presentOAuthError).toHaveBeenCalledWith('Failed to initiate Google OAuth flow');
    });
  });

  describe('handleGoogleCallback', () => {
    const mockQuery: GoogleCallbackQuery = {
      code: 'auth-code-123',
      state: 'state123',
    };

    const mockTokens = {
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      idToken: 'id-token',
      expiryDate: new Date(),
      tokenType: 'Bearer',
      scope: 'email profile',
    };

    const mockUserProfile = {
      id: 'google-user-123',
      email: 'user@gmail.com',
      emailVerified: true,
      name: 'John Doe',
      givenName: 'John',
      familyName: 'Doe',
      picture: 'https://example.com/avatar.jpg',
      locale: 'en',
      hostedDomain: null,
    };

    const mockSocialLoginResult = {
      user: {
        id: 'user-123',
        email: 'user@gmail.com',
        name: 'John Doe',
        provider: 'google',
        isNewUser: false,
      },
      tokens: {
        accessToken: 'jwt-access-token',
        refreshToken: 'jwt-refresh-token',
        expiresIn: 900,
        tokenType: 'Bearer',
      },
      session: {
        id: 'session-123',
        expiresAt: new Date(),
      },
    };

    it('should handle Google OAuth callback successfully', async () => {
      const mockResponse = {
        success: true,
        message: 'Google authentication successful',
        data: mockSocialLoginResult,
      };

      googleOAuthService.exchangeCodeForTokens.mockResolvedValue(mockTokens);
      googleOAuthService.getUserProfile.mockResolvedValue(mockUserProfile);
      socialLoginUseCase.execute.mockResolvedValue(mockSocialLoginResult);
      authPresenter.presentSocialLoginSuccess.mockReturnValue(mockResponse);

      const result = await controller.handleGoogleCallback(
        mockQuery,
        mockRequest as Request
      );

      expect(googleOAuthService.exchangeCodeForTokens).toHaveBeenCalledWith('auth-code-123');
      expect(googleOAuthService.getUserProfile).toHaveBeenCalledWith('access-token');
      expect(socialLoginUseCase.execute).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: 'google',
          authorizationCode: 'auth-code-123',
          idToken: 'id-token',
          profile: expect.objectContaining({
            id: 'google-user-123',
            email: 'user@gmail.com',
            name: 'John Doe',
          }),
          clientInfo: expect.objectContaining({
            userAgent: 'Mozilla/5.0 Test Browser',
            ipAddress: '192.168.1.1',
          }),
        })
      );
      expect(result).toEqual(mockResponse);
    });

    it('should handle OAuth error responses', async () => {
      const errorQuery = {
        ...mockQuery,
        error: 'access_denied',
      };

      authPresenter.presentOAuthError.mockReturnValue({
        success: false,
        error: 'OAUTH_ERROR',
        message: 'User denied access to Google account',
      });

      await expect(
        controller.handleGoogleCallback(errorQuery, mockRequest as Request)
      ).rejects.toThrow(UnauthorizedException);

      expect(authPresenter.presentOAuthError).toHaveBeenCalledWith('User denied access to Google account');
    });

    it('should handle missing required parameters', async () => {
      const invalidQuery = {
        state: 'state123',
        // Missing code
      };

      authPresenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Missing required OAuth parameters',
      });

      await expect(
        controller.handleGoogleCallback(invalidQuery as any, mockRequest as Request)
      ).rejects.toThrow(BadRequestException);

      expect(authPresenter.presentValidationError).toHaveBeenCalledWith('Missing required OAuth parameters');
    });

    it('should handle redirect URI from state', async () => {
      const redirectUri = 'https://app.com/dashboard';
      const stateWithRedirect = `state123|${Buffer.from(redirectUri).toString('base64')}`;
      const queryWithRedirect = {
        ...mockQuery,
        state: stateWithRedirect,
      };

      googleOAuthService.exchangeCodeForTokens.mockResolvedValue(mockTokens);
      googleOAuthService.getUserProfile.mockResolvedValue(mockUserProfile);
      socialLoginUseCase.execute.mkResolvedValue(mockSocialLoginResult);

      await controller.handleGoogleCallback(
        queryWithRedirect,
        mockRequest as Request,
        mockResponse as Response
      );

      expect(mockResponse.redirect).toHaveBeenCalledWith(
        expect.stringContaining(redirectUri)
      );
      expect(mockResponse.redirect).toHaveBeenCalledWith(
        expect.stringContaining('token=')
      );
    });

    it('should handle token exchange errors', async () => {
      googleOAuthService.exchangeCodeForTokens.mockRejectedValue(new Error('Token exchange failed'));
      authPresenter.presentInternalError.mockReturnValue({
        success: false,
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      });

      await expect(
        controller.handleGoogleCallback(mockQuery, mockRequest as Request)
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('initiateAppleAuth', () => {
    it('should redirect to Apple Sign In URL', async () => {
      const mockAuthUrl = 'https://appleid.apple.com/auth/authorize?client_id=test&state=state123';
      appleOAuthService.generateAuthUrl.mockResolvedValue(mockAuthUrl);

      await controller.initiateAppleAuth('state123', undefined, mockResponse as Response);

      expect(appleOAuthService.generateAuthUrl).toHaveBeenCalledWith(
        expect.stringContaining('state123'),
        expect.any(String) // nonce
      );
      expect(mockResponse.redirect).toHaveBeenCalledWith(mockAuthUrl);
    });

    it('should generate secure state and nonce if not provided', async () => {
      const mockAuthUrl = 'https://appleid.apple.com/auth/authorize?client_id=test';
      appleOAuthService.generateAuthUrl.mockResolvedValue(mockAuthUrl);

      await controller.initiateAppleAuth(undefined, undefined, mockResponse as Response);

      expect(appleOAuthService.generateAuthUrl).toHaveBeenCalledWith(
        expect.any(String), // state with nonce
        expect.any(String)  // nonce
      );
      expect(mockResponse.redirect).toHaveBeenCalledWith(mockAuthUrl);
    });

    it('should encode redirect URI and nonce in state', async () => {
      const mockAuthUrl = 'https://appleid.apple.com/auth/authorize?client_id=test';
      const redirectUri = 'https://app.com/dashboard';
      appleOAuthService.generateAuthUrl.mockResolvedValue(mockAuthUrl);

      await controller.initiateAppleAuth('state123', redirectUri, mockResponse as Response);

      expect(appleOAuthService.generateAuthUrl).toHaveBeenCalledWith(
        expect.stringContaining('state123'),
        expect.any(String)
      );
    });

    it('should handle OAuth service errors', async () => {
      appleOAuthService.generateAuthUrl.mockRejectedValue(new Error('OAuth service error'));
      authPresenter.presentOAuthError.mockReturnValue({
        success: false,
        error: 'OAUTH_ERROR',
        message: 'Failed to initiate Apple Sign In flow',
      });

      await expect(
        controller.initiateAppleAuth('state123', undefined, mockResponse as Response)
      ).rejects.toThrow(InternalServerErrorException);

      expect(authPresenter.presentOAuthError).toHaveBeenCalledWith('Failed to initiate Apple Sign In flow');
    });
  });

  describe('handleAppleCallback', () => {
    const mockBody: AppleCallbackRequest = {
      code: 'apple-auth-code',
      id_token: 'apple.id.token',
      state: 'state123||nonce456',
      user: JSON.stringify({
        email: 'user@privaterelay.appleid.com',
        name: { firstName: 'John', lastName: 'Doe' }
      }),
    };

    const mockUserProfile = {
      id: 'apple-user-123',
      email: 'user@privaterelay.appleid.com',
      emailVerified: true,
      name: 'John Doe',
      isPrivateEmail: true,
      realUserStatus: 'likelyReal' as const,
    };

    const mockSocialLoginResult = {
      user: {
        id: 'user-123',
        email: 'user@privaterelay.appleid.com',
        name: 'John Doe',
        provider: 'apple',
        isNewUser: false,
      },
      tokens: {
        accessToken: 'jwt-access-token',
        refreshToken: 'jwt-refresh-token',
        expiresIn: 900,
        tokenType: 'Bearer',
      },
      session: {
        id: 'session-123',
        expiresAt: new Date(),
      },
    };

    it('should handle Apple Sign In callback successfully', async () => {
      const mockResponse = {
        success: true,
        message: 'Apple authentication successful',
        data: mockSocialLoginResult,
      };

      appleOAuthService.validateIdToken.mockResolvedValue(mockUserProfile);
      socialLoginUseCase.execute.mockResolvedValue(mockSocialLoginResult);
      authPresenter.presentSocialLoginSuccess.mockReturnValue(mockResponse);

      const result = await controller.handleAppleCallback(
        mockBody,
        mockRequest as Request
      );

      expect(appleOAuthService.validateIdToken).toHaveBeenCalledWith('apple.id.token', 'nonce456');
      expect(socialLoginUseCase.execute).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: 'apple',
          authorizationCode: 'apple-auth-code',
          idToken: 'apple.id.token',
          profile: expect.objectContaining({
            id: 'apple-user-123',
            email: 'user@privaterelay.appleid.com',
            name: 'John Doe',
            isPrivateEmail: true,
            realUserStatus: 'likelyReal',
          }),
          clientInfo: expect.objectContaining({
            userAgent: 'Mozilla/5.0 Test Browser',
            ipAddress: '192.168.1.1',
          }),
        })
      );
      expect(result).toEqual(mockResponse);
    });

    it('should handle missing required parameters', async () => {
      const invalidBody = {
        code: 'apple-auth-code',
        // Missing id_token
        state: 'state123||nonce456',
      };

      authPresenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Missing required Apple callback parameters',
      });

      await expect(
        controller.handleAppleCallback(invalidBody as any, mockRequest as Request)
      ).rejects.toThrow(BadRequestException);

      expect(authPresenter.presentValidationError).toHaveBeenCalledWith('Missing required Apple callback parameters');
    });

    it('should extract Apple user name from additional data', async () => {
      appleOAuthService.validateIdToken.mockResolvedValue({
        ...mockUserProfile,
        name: null, // No name in ID token
      });
      socialLoginUseCase.execute.mockResolvedValue(mockSocialLoginResult);
      authPresenter.presentSocialLoginSuccess.mockReturnValue({} as any);

      await controller.handleAppleCallback(mockBody, mockRequest as Request);

      expect(socialLoginUseCase.execute).toHaveBeenCalledWith(
        expect.objectContaining({
          profile: expect.objectContaining({
            name: 'John Doe', // Extracted from user data
          }),
        })
      );
    });

    it('should handle redirect URI from state', async () => {
      const redirectUri = 'https://app.com/dashboard';
      const stateWithRedirect = `state123|${Buffer.from(redirectUri).toString('base64')}|nonce456`;
      const bodyWithRedirect = {
        ...mockBody,
        state: stateWithRedirect,
      };

      appleOAuthService.validateIdToken.mockResolvedValue(mockUserProfile);
      socialLoginUseCase.execute.mockResolvedValue(mockSocialLoginResult);

      await controller.handleAppleCallback(
        bodyWithRedirect,
        mockRequest as Request,
        mockResponse as Response
      );

      expect(mockResponse.redirect).toHaveBeenCalledWith(
        expect.stringContaining(redirectUri)
      );
      expect(mockResponse.redirect).toHaveBeenCalledWith(
        expect.stringContaining('token=')
      );
    });

    it('should handle ID token validation errors', async () => {
      appleOAuthService.validateIdToken.mockRejectedValue(new Error('Invalid ID token'));
      authPresenter.presentInternalError.mockReturnValue({
        success: false,
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      });

      await expect(
        controller.handleAppleCallback(mockBody, mockRequest as Request)
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('getOAuthConfig', () => {
    it('should return OAuth configuration', async () => {
      const mockGoogleConfig = {
        clientId: 'google-client-id',
        redirectUri: 'https://app.com/auth/google/callback',
        scopes: ['email', 'profile'],
        provider: 'google',
      };

      const mockAppleConfig = {
        clientId: 'com.app.service',
        redirectUri: 'https://app.com/auth/apple/callback',
        scopes: ['name', 'email'],
        provider: 'apple',
      };

      googleOAuthService.getConfiguration.mockReturnValue(mockGoogleConfig);
      appleOAuthService.getConfiguration.mockReturnValue(mockAppleConfig);

      const result = await controller.getOAuthConfig();

      expect(result).toEqual({
        success: true,
        data: {
          google: {
            clientId: 'google-client-id',
            redirectUri: 'https://app.com/auth/google/callback',
            scopes: ['email', 'profile'],
          },
          apple: {
            clientId: 'com.app.service',
            redirectUri: 'https://app.com/auth/apple/callback',
            scopes: ['name', 'email'],
          },
        },
      });
    });

    it('should handle configuration errors', async () => {
      googleOAuthService.getConfiguration.mockImplementation(() => {
        throw new Error('Configuration error');
      });
      authPresenter.presentInternalError.mockReturnValue({
        success: false,
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      });

      await expect(controller.getOAuthConfig()).rejects.toThrow(InternalServerErrorException);
      expect(authPresenter.presentInternalError).toHaveBeenCalled();
    });
  });

  describe('helper methods', () => {
    it('should extract client IP from various headers', () => {
      const testCases = [
        {
          headers: { 'x-forwarded-for': '203.0.113.1,192.168.1.1' },
          expected: '203.0.113.1',
        },
        {
          headers: { 'x-real-ip': '203.0.113.2' },
          expected: '203.0.113.2',
        },
        {
          headers: {},
          connection: { remoteAddress: '203.0.113.3' },
          expected: '203.0.113.3',
        },
      ];

      for (const testCase of testCases) {
        const req = {
          headers: testCase.headers,
          connection: testCase.connection || {},
          socket: {},
        } as Request;

        // Test through a public method that uses extractClientIP
        const query: GoogleCallbackQuery = { code: 'test', state: 'test' };
        
        googleOAuthService.exchangeCodeForTokens.mockResolvedValue({
          accessToken: 'token',
          refreshToken: 'refresh',
          tokenType: 'Bearer',
        } as any);
        
        googleOAuthService.getUserProfile.mockResolvedValue({
          id: 'test',
          email: 'test@example.com',
          emailVerified: true,
        } as any);
        
        socialLoginUseCase.execute.mockResolvedValue({} as any);
        authPresenter.presentSocialLoginSuccess.mockReturnValue({} as any);

        controller.handleGoogleCallback(query, req);

        expect(socialLoginUseCase.execute).toHaveBeenCalledWith(
          expect.objectContaining({
            clientInfo: expect.objectContaining({
              ipAddress: testCase.expected,
            }),
          })
        );

        jest.clearAllMocks();
      }
    });
  });
});