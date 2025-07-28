import { SocialLoginUseCase } from './social-login.use-case';
import { User } from '../entities/user.entity';
import { Token } from '../entities/token.entity';
import { AuthSession } from '../entities/auth-session.entity';
import { UserRepository } from '../ports/repositories/user.repository';
import { TokenRepository } from '../ports/repositories/token.repository';
import { AuthSessionRepository } from '../ports/repositories/auth-session.repository';
import { TokenService } from '../ports/services/token.service';
import { GoogleOAuthService, GoogleUserProfile } from '../ports/services/google-oauth.service';
import { AppleOAuthService, AppleUserProfile } from '../ports/services/apple-oauth.service';
import { AuthPresenter } from '../ports/presenters/auth.presenter';
import { SocialLoginRequest, AuthProvider, UserStatus } from '@auth/shared';

describe('SocialLoginUseCase', () => {
  let useCase: SocialLoginUseCase;
  let userRepository: jest.Mocked<UserRepository>;
  let tokenRepository: jest.Mocked<TokenRepository>;
  let sessionRepository: jest.Mocked<AuthSessionRepository>;
  let tokenService: jest.Mocked<TokenService>;
  let googleOAuthService: jest.Mocked<GoogleOAuthService>;
  let appleOAuthService: jest.Mocked<AppleOAuthService>;
  let presenter: jest.Mocked<AuthPresenter>;

  const validGoogleRequest: SocialLoginRequest = {
    provider: AuthProvider.GOOGLE,
    code: 'google_auth_code',
    clientInfo: {
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0 (Test Browser)',
    },
  };

  const validAppleRequest: SocialLoginRequest = {
    provider: AuthProvider.APPLE,
    idToken: 'apple.id.token.jwt',
    clientInfo: {
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0 (Test Browser)',
    },
  };

  const googleUserProfile: GoogleUserProfile = {
    id: 'google123',
    email: 'user@gmail.com',
    name: 'John Doe',
    picture: 'https://example.com/picture.jpg',
    emailVerified: true,
  };

  const appleUserProfile: AppleUserProfile = {
    id: 'apple123',
    email: 'user@icloud.com',
    name: { firstName: 'Jane', lastName: 'Smith' },
    email_verified: true,
  };

  beforeEach(() => {
    // Create mocked dependencies
    userRepository = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      findByProviderId: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
      existsByEmail: jest.fn(),
      findAll: jest.fn(),
      count: jest.fn(),
      findByStatus: jest.fn(),
      updateLastLogin: jest.fn(),
    };

    tokenRepository = {
      findById: jest.fn(),
      findByValue: jest.fn(),
      findByUserId: jest.fn(),
      findByUserIdAndType: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
      deleteByUserId: jest.fn(),
      deleteByUserIdAndType: jest.fn(),
      findExpired: jest.fn(),
      deleteExpired: jest.fn(),
      revokeByValue: jest.fn(),
      revokeByUserId: jest.fn(),
      isValidToken: jest.fn(),
      countByType: jest.fn(),
      cleanup: jest.fn(),
    };

    sessionRepository = {
      findById: jest.fn(),
      findByToken: jest.fn(),
      findByUserId: jest.fn(),
      findActiveByUserId: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
      deleteByUserId: jest.fn(),
      invalidateByToken: jest.fn(),
      invalidateByUserId: jest.fn(),
      findExpired: jest.fn(),
      deleteExpired: jest.fn(),
      findIdle: jest.fn(),
      updateActivity: jest.fn(),
      findByDeviceId: jest.fn(),
      findByIpAddress: jest.fn(),
      countActiveByUserId: jest.fn(),
      cleanup: jest.fn(),
      isValidSession: jest.fn(),
    };

    tokenService = {
      generateToken: jest.fn(),
      generateAccessToken: jest.fn(),
      generateRefreshToken: jest.fn(),
      validateToken: jest.fn(),
      decodeToken: jest.fn(),
      getTokenExpiration: jest.fn(),
      isTokenExpired: jest.fn(),
      getTimeUntilExpiration: jest.fn(),
      refreshAccessToken: jest.fn(),
      blacklistToken: jest.fn(),
      isTokenBlacklisted: jest.fn(),
      generateSecureRandomToken: jest.fn(),
      signData: jest.fn(),
      verifyData: jest.fn(),
    };

    googleOAuthService = {
      exchangeCodeForTokens: jest.fn(),
      getUserProfile: jest.fn(),
      verifyIdToken: jest.fn(),
      extractUserProfile: jest.fn(),
      refreshAccessToken: jest.fn(),
      revokeToken: jest.fn(),
      getAuthorizationUrl: jest.fn(),
      validateState: jest.fn(),
    };

    appleOAuthService = {
      exchangeCodeForTokens: jest.fn(),
      extractUserProfile: jest.fn(),
      verifyIdToken: jest.fn(),
      validateClientSecret: jest.fn(),
      getPublicKeys: jest.fn(),
      generateClientSecret: jest.fn(),
    };

    presenter = {
      presentRegistrationSuccess: jest.fn(),
      presentDuplicateEmail: jest.fn(),
      presentRegistrationValidationError: jest.fn(),
      presentLoginSuccess: jest.fn(),
      presentInvalidCredentials: jest.fn(),
      presentAccountLocked: jest.fn(),
      presentSocialLoginSuccess: jest.fn(),
      presentSocialLoginFailure: jest.fn(),
      presentTokenRefreshSuccess: jest.fn(),
      presentTokenRefreshFailure: jest.fn(),
      presentLogoutSuccess: jest.fn(),
      presentLogoutFailure: jest.fn(),
      presentTokenValidation: jest.fn(),
      presentRateLimitExceeded: jest.fn(),
      presentAuthenticationError: jest.fn(),
      presentServerError: jest.fn(),
    };

    useCase = new SocialLoginUseCase(
      userRepository,
      tokenRepository,
      sessionRepository,
      tokenService,
      googleOAuthService,
      appleOAuthService,
      presenter
    );
  });

  describe('execute', () => {
    describe('Google OAuth Flow', () => {
      it('should successfully handle Google OAuth with authorization code for new user', async () => {
        // Arrange
        const accessToken = 'access.token.jwt';
        const refreshToken = 'refresh.token.jwt';

        googleOAuthService.exchangeCodeForTokens.mockResolvedValue({
          accessToken: 'google_access_token',
          refreshToken: 'google_refresh_token',
          idToken: 'google_id_token',
          expiresIn: 3600,
        });
        googleOAuthService.getUserProfile.mockResolvedValue(googleUserProfile);
        userRepository.findByEmail.mockResolvedValue(null);
        userRepository.findByProviderId.mockResolvedValue(null);
        tokenService.generateAccessToken.mockResolvedValue(accessToken);
        tokenService.generateRefreshToken.mockResolvedValue(refreshToken);
        tokenRepository.save.mockResolvedValue({} as Token);
        sessionRepository.save.mockResolvedValue({} as AuthSession);
        userRepository.updateLastLogin.mockResolvedValue();

        const savedUser = User.createFromSocialProvider({
          id: 'user123',
          email: googleUserProfile.email,
          name: googleUserProfile.name,
          provider: AuthProvider.GOOGLE,
          providerId: googleUserProfile.id,
          profilePicture: googleUserProfile.picture,
          emailVerified: true,
        });
        userRepository.save.mockResolvedValue(savedUser);

        // Act
        await useCase.execute(validGoogleRequest);

        // Assert
        expect(googleOAuthService.exchangeCodeForTokens).toHaveBeenCalledWith(
          validGoogleRequest.code,
          'state'
        );
        expect(googleOAuthService.getUserProfile).toHaveBeenCalledWith('google_access_token');
        expect(userRepository.findByEmail).toHaveBeenCalledWith(googleUserProfile.email);
        expect(userRepository.findByProviderId).toHaveBeenCalledWith(AuthProvider.GOOGLE, googleUserProfile.id);
        expect(userRepository.save).toHaveBeenCalled();
        expect(tokenService.generateAccessToken).toHaveBeenCalledWith(savedUser.id, savedUser.email, '15m');
        expect(tokenService.generateRefreshToken).toHaveBeenCalledWith(savedUser.id, savedUser.email, '7d');
        expect(presenter.presentSocialLoginSuccess).toHaveBeenCalledWith({
          user: {
            id: savedUser.id,
            email: savedUser.email,
            name: savedUser.name,
            profilePicture: savedUser.profilePicture,
            provider: savedUser.provider,
            isNewUser: true,
          },
          tokens: {
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresIn: 15 * 60,
          },
          session: expect.objectContaining({
            id: expect.any(String),
            expiresAt: expect.any(Date),
          }),
        });
      });

      it('should successfully handle Google OAuth with ID token for existing user', async () => {
        // Arrange
        const accessToken = 'access.token.jwt';
        const refreshToken = 'refresh.token.jwt';

        const googleRequestWithIdToken = {
          ...validGoogleRequest,
          code: undefined,
          idToken: 'google.id.token.jwt',
        };

        const existingUser = User.createFromSocialProvider({
          id: 'existing_user123',
          email: googleUserProfile.email,
          name: googleUserProfile.name,
          provider: AuthProvider.GOOGLE,
          providerId: googleUserProfile.id,
          profilePicture: googleUserProfile.picture,
          emailVerified: true,
        });

        googleOAuthService.verifyIdToken.mockResolvedValue({ sub: 'google123' });
        googleOAuthService.extractUserProfile.mockResolvedValue(googleUserProfile);
        userRepository.findByEmail.mockResolvedValue(existingUser);
        tokenService.generateAccessToken.mockResolvedValue(accessToken);
        tokenService.generateRefreshToken.mockResolvedValue(refreshToken);
        tokenRepository.save.mockResolvedValue({} as Token);
        sessionRepository.save.mockResolvedValue({} as AuthSession);
        userRepository.updateLastLogin.mockResolvedValue();

        // Act
        await useCase.execute(googleRequestWithIdToken);

        // Assert
        expect(googleOAuthService.verifyIdToken).toHaveBeenCalledWith(googleRequestWithIdToken.idToken);
        expect(googleOAuthService.extractUserProfile).toHaveBeenCalled();
        expect(userRepository.findByEmail).toHaveBeenCalledWith(googleUserProfile.email);
        expect(userRepository.save).not.toHaveBeenCalled(); // Should not create new user
        expect(presenter.presentSocialLoginSuccess).toHaveBeenCalledWith(
          expect.objectContaining({
            user: expect.objectContaining({
              isNewUser: false,
            }),
          })
        );
      });

      it('should handle Google OAuth failures', async () => {
        // Arrange
        googleOAuthService.exchangeCodeForTokens.mockRejectedValue(new Error('Google OAuth failed'));

        // Act
        await useCase.execute(validGoogleRequest);

        // Assert
        expect(presenter.presentSocialLoginFailure).toHaveBeenCalledWith(
          AuthProvider.GOOGLE,
          'Google authentication failed. Please try again.'
        );
      });
    });

    describe('Apple OAuth Flow', () => {
      it('should successfully handle Apple OAuth with ID token for new user', async () => {
        // Arrange
        const accessToken = 'access.token.jwt';
        const refreshToken = 'refresh.token.jwt';

        appleOAuthService.extractUserProfile.mockResolvedValue(appleUserProfile);
        userRepository.findByEmail.mockResolvedValue(null);
        userRepository.findByProviderId.mockResolvedValue(null);
        tokenService.generateAccessToken.mockResolvedValue(accessToken);
        tokenService.generateRefreshToken.mockResolvedValue(refreshToken);
        tokenRepository.save.mockResolvedValue({} as Token);
        sessionRepository.save.mockResolvedValue({} as AuthSession);
        userRepository.updateLastLogin.mockResolvedValue();

        const savedUser = User.createFromSocialProvider({
          id: 'user123',
          email: appleUserProfile.email,
          name: 'Jane Smith',
          provider: AuthProvider.APPLE,
          providerId: appleUserProfile.id,
          profilePicture: undefined,
          emailVerified: true,
        });
        userRepository.save.mockResolvedValue(savedUser);

        // Act
        await useCase.execute(validAppleRequest);

        // Assert
        expect(appleOAuthService.extractUserProfile).toHaveBeenCalledWith(
          validAppleRequest.idToken,
          validAppleRequest.userInfo
        );
        expect(userRepository.findByEmail).toHaveBeenCalledWith(appleUserProfile.email);
        expect(userRepository.save).toHaveBeenCalled();
        expect(presenter.presentSocialLoginSuccess).toHaveBeenCalledWith(
          expect.objectContaining({
            user: expect.objectContaining({
              isNewUser: true,
              provider: AuthProvider.APPLE,
            }),
          })
        );
      });

      it('should successfully handle Apple OAuth with authorization code', async () => {
        // Arrange
        const appleRequestWithCode = {
          ...validAppleRequest,
          idToken: undefined,
          code: 'apple_auth_code',
        };

        const tokenResponse = {
          accessToken: 'apple_access_token',
          refreshToken: 'apple_refresh_token',
          idToken: 'apple_id_token',
          userProfile: appleUserProfile,
        };

        const accessToken = 'access.token.jwt';
        const refreshToken = 'refresh.token.jwt';

        appleOAuthService.exchangeCodeForTokens.mockResolvedValue(tokenResponse);
        userRepository.findByEmail.mockResolvedValue(null);
        userRepository.findByProviderId.mockResolvedValue(null);
        tokenService.generateAccessToken.mockResolvedValue(accessToken);
        tokenService.generateRefreshToken.mockResolvedValue(refreshToken);
        tokenRepository.save.mockResolvedValue({} as Token);
        sessionRepository.save.mockResolvedValue({} as AuthSession);
        userRepository.updateLastLogin.mockResolvedValue();

        const savedUser = User.createFromSocialProvider({
          id: 'user123',
          email: appleUserProfile.email,
          name: 'Jane Smith',
          provider: AuthProvider.APPLE,
          providerId: appleUserProfile.id,
          profilePicture: undefined,
          emailVerified: true,
        });
        userRepository.save.mockResolvedValue(savedUser);

        // Act
        await useCase.execute(appleRequestWithCode);

        // Assert
        expect(appleOAuthService.exchangeCodeForTokens).toHaveBeenCalledWith(
          appleRequestWithCode.code,
          'state'
        );
        expect(presenter.presentSocialLoginSuccess).toHaveBeenCalled();
      });

      it('should handle Apple OAuth failures', async () => {
        // Arrange
        appleOAuthService.extractUserProfile.mockRejectedValue(new Error('Apple OAuth failed'));

        // Act
        await useCase.execute(validAppleRequest);

        // Assert
        expect(presenter.presentSocialLoginFailure).toHaveBeenCalledWith(
          AuthProvider.APPLE,
          'Apple authentication failed. Please try again.'
        );
      });
    });

    describe('Validation', () => {
      it('should reject request without provider', async () => {
        // Arrange
        const invalidRequest = { ...validGoogleRequest, provider: undefined as any };

        // Act
        await useCase.execute(invalidRequest);

        // Assert
        expect(presenter.presentSocialLoginFailure).toHaveBeenCalledWith(
          'undefined',
          'OAuth provider is required'
        );
      });

      it('should reject unsupported provider', async () => {
        // Arrange
        const invalidRequest = { ...validGoogleRequest, provider: 'FACEBOOK' as any };

        // Act
        await useCase.execute(invalidRequest);

        // Assert
        expect(presenter.presentSocialLoginFailure).toHaveBeenCalledWith(
          'FACEBOOK',
          'Unsupported OAuth provider'
        );
      });

      it('should reject Google request without code or idToken', async () => {
        // Arrange
        const invalidRequest = { ...validGoogleRequest, code: undefined, idToken: undefined };

        // Act
        await useCase.execute(invalidRequest);

        // Assert
        expect(presenter.presentSocialLoginFailure).toHaveBeenCalledWith(
          AuthProvider.GOOGLE,
          'Authorization code or ID token is required for Google OAuth'
        );
      });

      it('should reject Apple request without idToken', async () => {
        // Arrange
        const invalidRequest = { ...validAppleRequest, idToken: undefined };

        // Act
        await useCase.execute(invalidRequest);

        // Assert
        expect(presenter.presentSocialLoginFailure).toHaveBeenCalledWith(
          AuthProvider.APPLE,
          'Identity token is required for Apple Sign In'
        );
      });
    });

    describe('Account Status Validation', () => {
      it('should reject inactive user account', async () => {
        // Arrange
        const inactiveUser = User.createFromSocialProvider({
          id: 'inactive_user',
          email: googleUserProfile.email,
          name: googleUserProfile.name,
          provider: AuthProvider.GOOGLE,
          providerId: googleUserProfile.id,
          profilePicture: googleUserProfile.picture,
          emailVerified: true,
        });
        inactiveUser.deactivate();

        googleOAuthService.exchangeCodeForTokens.mockResolvedValue({
          accessToken: 'google_access_token',
          refreshToken: 'google_refresh_token',
          idToken: 'google_id_token',
          expiresIn: 3600,
        });
        googleOAuthService.getUserProfile.mockResolvedValue(googleUserProfile);
        userRepository.findByEmail.mockResolvedValue(inactiveUser);

        // Act
        await useCase.execute(validGoogleRequest);

        // Assert
        expect(presenter.presentAccountLocked).toHaveBeenCalledWith(
          'Account is inactive. Please contact support to activate your account.'
        );
      });

      it('should reject suspended user account', async () => {
        // Arrange
        const suspendedUser = User.createFromSocialProvider({
          id: 'suspended_user',
          email: googleUserProfile.email,
          name: googleUserProfile.name,
          provider: AuthProvider.GOOGLE,
          providerId: googleUserProfile.id,
          profilePicture: googleUserProfile.picture,
          emailVerified: true,
        });
        suspendedUser.suspend();

        googleOAuthService.exchangeCodeForTokens.mockResolvedValue({
          accessToken: 'google_access_token',
          refreshToken: 'google_refresh_token',
          idToken: 'google_id_token',
          expiresIn: 3600,
        });
        googleOAuthService.getUserProfile.mockResolvedValue(googleUserProfile);
        userRepository.findByEmail.mockResolvedValue(suspendedUser);

        // Act
        await useCase.execute(validGoogleRequest);

        // Assert
        expect(presenter.presentAccountLocked).toHaveBeenCalledWith(
          'Account has been suspended. Please contact support for assistance.'
        );
      });
    });

    describe('Account Linking Scenarios', () => {
      it('should reject account linking when user exists with different provider', async () => {
        // Arrange
        const existingLocalUser = User.create({
          id: 'local_user',
          email: googleUserProfile.email,
          password: 'HashedPassword123!',
          name: 'Existing User',
          provider: AuthProvider.LOCAL,
        });

        googleOAuthService.exchangeCodeForTokens.mockResolvedValue({
          accessToken: 'google_access_token',
          refreshToken: 'google_refresh_token',
          idToken: 'google_id_token',
          expiresIn: 3600,
        });
        googleOAuthService.getUserProfile.mockResolvedValue(googleUserProfile);
        userRepository.findByEmail.mockResolvedValue(existingLocalUser);

        // Act
        await useCase.execute(validGoogleRequest);

        // Assert
        expect(presenter.presentSocialLoginFailure).toHaveBeenCalledWith(
          AuthProvider.GOOGLE,
          'An account with this email already exists with a different sign-in method. Please use your original sign-in method.'
        );
      });
    });

    describe('Name Extraction', () => {
      it('should extract name from Google profile', async () => {
        // Arrange
        const googleProfileWithName = { ...googleUserProfile, name: 'John Doe' };
        
        googleOAuthService.exchangeCodeForTokens.mockResolvedValue({
          accessToken: 'google_access_token',
          refreshToken: 'google_refresh_token',
          idToken: 'google_id_token',
          expiresIn: 3600,
        });
        googleOAuthService.getUserProfile.mockResolvedValue(googleProfileWithName);
        userRepository.findByEmail.mockResolvedValue(null);
        userRepository.findByProviderId.mockResolvedValue(null);
        tokenService.generateAccessToken.mockResolvedValue('access.token');
        tokenService.generateRefreshToken.mockResolvedValue('refresh.token');
        tokenRepository.save.mockResolvedValue({} as Token);
        sessionRepository.save.mockResolvedValue({} as AuthSession);
        userRepository.updateLastLogin.mockResolvedValue();

        const savedUser = User.createFromSocialProvider({
          id: 'user123',
          email: googleProfileWithName.email,
          name: googleProfileWithName.name,
          provider: AuthProvider.GOOGLE,
          providerId: googleProfileWithName.id,
          profilePicture: googleProfileWithName.picture,
          emailVerified: true,
        });
        userRepository.save.mockResolvedValue(savedUser);

        // Act
        await useCase.execute(validGoogleRequest);

        // Assert
        expect(presenter.presentSocialLoginSuccess).toHaveBeenCalledWith(
          expect.objectContaining({
            user: expect.objectContaining({
              name: 'John Doe',
            }),
          })
        );
      });

      it('should fallback to email username when name is not available', async () => {
        // Arrange
        const profileWithoutName = { ...googleUserProfile, name: undefined };
        
        googleOAuthService.exchangeCodeForTokens.mockResolvedValue({
          accessToken: 'google_access_token',
          refreshToken: 'google_refresh_token',
          idToken: 'google_id_token',
          expiresIn: 3600,
        });
        googleOAuthService.getUserProfile.mockResolvedValue(profileWithoutName as any);
        userRepository.findByEmail.mockResolvedValue(null);
        userRepository.findByProviderId.mockResolvedValue(null);
        tokenService.generateAccessToken.mockResolvedValue('access.token');
        tokenService.generateRefreshToken.mockResolvedValue('refresh.token');
        tokenRepository.save.mockResolvedValue({} as Token);
        sessionRepository.save.mockResolvedValue({} as AuthSession);
        userRepository.updateLastLogin.mockResolvedValue();

        const savedUser = User.createFromSocialProvider({
          id: 'user123',
          email: profileWithoutName.email,
          name: 'user', // Should be extracted from email
          provider: AuthProvider.GOOGLE,
          providerId: profileWithoutName.id,
          profilePicture: profileWithoutName.picture,
          emailVerified: true,
        });
        userRepository.save.mockResolvedValue(savedUser);

        // Act
        await useCase.execute(validGoogleRequest);

        // Assert
        expect(presenter.presentSocialLoginSuccess).toHaveBeenCalledWith(
          expect.objectContaining({
            user: expect.objectContaining({
              name: 'user', // Should be extracted from email part before @
            }),
          })
        );
      });
    });

    describe('Error Handling', () => {
      it('should handle unexpected errors during social login', async () => {
        // Arrange
        googleOAuthService.exchangeCodeForTokens.mockRejectedValue(new Error('Unexpected error'));

        // Act
        await useCase.execute(validGoogleRequest);

        // Assert
        expect(presenter.presentSocialLoginFailure).toHaveBeenCalledWith(
          AuthProvider.GOOGLE,
          'Google authentication failed. Please try again.'
        );
      });

      it('should work without client info provided', async () => {
        // Arrange
        const requestWithoutClientInfo = {
          provider: AuthProvider.GOOGLE,
          code: 'google_auth_code',
        };

        const accessToken = 'access.token.jwt';
        const refreshToken = 'refresh.token.jwt';

        googleOAuthService.exchangeCodeForTokens.mockResolvedValue({
          accessToken: 'google_access_token',
          refreshToken: 'google_refresh_token',
          idToken: 'google_id_token',
          expiresIn: 3600,
        });
        googleOAuthService.getUserProfile.mockResolvedValue(googleUserProfile);
        userRepository.findByEmail.mockResolvedValue(null);
        userRepository.findByProviderId.mockResolvedValue(null);
        tokenService.generateAccessToken.mockResolvedValue(accessToken);
        tokenService.generateRefreshToken.mockResolvedValue(refreshToken);
        tokenRepository.save.mockResolvedValue({} as Token);
        sessionRepository.save.mockResolvedValue({} as AuthSession);
        userRepository.updateLastLogin.mockResolvedValue();

        const savedUser = User.createFromSocialProvider({
          id: 'user123',
          email: googleUserProfile.email,
          name: googleUserProfile.name,
          provider: AuthProvider.GOOGLE,
          providerId: googleUserProfile.id,
          profilePicture: googleUserProfile.picture,
          emailVerified: true,
        });
        userRepository.save.mockResolvedValue(savedUser);

        // Act
        await useCase.execute(requestWithoutClientInfo);

        // Assert
        expect(presenter.presentSocialLoginSuccess).toHaveBeenCalledWith(
          expect.objectContaining({
            session: expect.objectContaining({
              id: expect.any(String),
            }),
          })
        );
      });
    });
  });
});