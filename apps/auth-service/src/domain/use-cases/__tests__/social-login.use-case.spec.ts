import { Test, TestingModule } from '@nestjs/testing';
import { SocialLoginUseCase, UnsupportedProviderError, OAuthAuthorizationError, OAuthUserInfoError } from '../social-login.use-case';
import { UserRepository } from '../../ports/user.repository';
import { TokenRepository } from '../../ports/token.repository';
import { AuthSessionRepository } from '../../ports/auth-session.repository';
import { TokenService } from '../../ports/token.service';
import { GoogleOAuthService } from '../../ports/google-oauth.service';
import { AppleOAuthService } from '../../ports/apple-oauth.service';
import { User } from '../../entities/user.entity';
import { Token } from '../../entities/token.entity';
import { AuthSession } from '../../entities/auth-session.entity';
import { AuthProvider, TokenType, ClientInfo } from '@auth/shared/types/auth.types';

describe('SocialLoginUseCase', () => {
  let useCase: SocialLoginUseCase;
  let userRepository: jest.Mocked<UserRepository>;
  let tokenRepository: jest.Mocked<TokenRepository>;
  let authSessionRepository: jest.Mocked<AuthSessionRepository>;
  let tokenService: jest.Mocked<TokenService>;
  let googleOAuthService: jest.Mocked<GoogleOAuthService>;
  let appleOAuthService: jest.Mocked<AppleOAuthService>;

  const mockClientInfo: ClientInfo = {
    userAgent: 'Mozilla/5.0 Test Browser',
    ipAddress: '192.168.1.1',
    deviceId: 'test-device-123',
  };

  const mockGoogleUserInfo = {
    id: 'google_123',
    email: 'user@example.com',
    name: 'Google User',
    given_name: 'Google',
    family_name: 'User',
    picture: 'https://example.com/avatar.jpg',
  };

  const mockAppleUserInfo = {
    sub: 'apple_123',
    email: 'user@example.com',
    name: 'Apple User',
    profilePicture: 'https://example.com/avatar.jpg',
  };

  beforeEach(async () => {
    const mockUserRepository = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      existsByEmail: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      activate: jest.fn(),
      deactivate: jest.fn(),
      findByProvider: jest.fn(),
    };

    const mockTokenRepository = {
      findByValue: jest.fn(),
      findByUserId: jest.fn(),
      save: jest.fn(),
      revoke: jest.fn(),
      revokeAllByUserId: jest.fn(),
      deleteExpired: jest.fn(),
      countActiveTokensByUserId: jest.fn(),
    };

    const mockAuthSessionRepository = {
      findById: jest.fn(),
      findBySessionToken: jest.fn(),
      findByUserId: jest.fn(),
      save: jest.fn(),
      revoke: jest.fn(),
      updateActivity: jest.fn(),
      deleteExpired: jest.fn(),
    };

    const mockTokenService = {
      generateToken: jest.fn(),
      generateTokenPair: jest.fn(),
      verifyToken: jest.fn(),
      decodeToken: jest.fn(),
      revokeToken: jest.fn(),
    };

    const mockGoogleOAuthService = {
      exchangeCodeForTokens: jest.fn(),
      getUserInfo: jest.fn(),
      refreshTokens: jest.fn(),
      verifyIdToken: jest.fn(),
    };

    const mockAppleOAuthService = {
      verifyIdToken: jest.fn(),
      extractUserInfo: jest.fn(),
      validateNonce: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SocialLoginUseCase,
        { provide: 'UserRepository', useValue: mockUserRepository },
        { provide: 'TokenRepository', useValue: mockTokenRepository },
        { provide: 'AuthSessionRepository', useValue: mockAuthSessionRepository },
        { provide: 'TokenService', useValue: mockTokenService },
        { provide: 'GoogleOAuthService', useValue: mockGoogleOAuthService },
        { provide: 'AppleOAuthService', useValue: mockAppleOAuthService },
      ],
    }).compile();

    useCase = module.get<SocialLoginUseCase>(SocialLoginUseCase);
    userRepository = module.get('UserRepository');
    tokenRepository = module.get('TokenRepository');
    authSessionRepository = module.get('AuthSessionRepository');
    tokenService = module.get('TokenService');
    googleOAuthService = module.get('GoogleOAuthService');
    appleOAuthService = module.get('AppleOAuthService');
  });

  describe('execute - Google OAuth', () => {
    const googleRequest = {
      provider: AuthProvider.GOOGLE,
      authorizationCode: 'google_auth_code_123',
      clientInfo: mockClientInfo,
    };

    const mockAccessToken = new Token(
      'access_token_123',
      'user_123',
      TokenType.ACCESS,
      'access.token.value',
      new Date(Date.now() + 15 * 60 * 1000),
    );

    const mockRefreshToken = new Token(
      'refresh_token_123',
      'user_123',
      TokenType.REFRESH,
      'refresh.token.value',
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    );

    it('should successfully login new Google user', async () => {
      // Arrange
      const mockTokens = { access_token: 'google_access_token' };
      
      googleOAuthService.exchangeCodeForTokens.mockResolvedValue(mockTokens);
      googleOAuthService.getUserInfo.mockResolvedValue(mockGoogleUserInfo);
      userRepository.findByProvider.mockResolvedValue(null);
      userRepository.findByEmail.mockResolvedValue(null);
      userRepository.save.mockImplementation(user => Promise.resolve(user));
      authSessionRepository.save.mockImplementation(session => Promise.resolve(session));
      tokenService.generateTokenPair.mockResolvedValue({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });

      // Act
      const result = await useCase.execute(googleRequest);

      // Assert
      expect(result).toEqual({
        accessToken: 'access.token.value',
        refreshToken: 'refresh.token.value',
        sessionId: expect.any(String),
        user: {
          id: expect.any(String),
          email: 'user@example.com',
          name: 'Google User',
          profilePicture: 'https://example.com/avatar.jpg',
          provider: AuthProvider.GOOGLE,
          isActive: true,
        },
        isNewUser: true,
        expiresAt: mockAccessToken.getExpiresAt(),
      });

      expect(googleOAuthService.exchangeCodeForTokens).toHaveBeenCalledWith('google_auth_code_123');
      expect(googleOAuthService.getUserInfo).toHaveBeenCalledWith('google_access_token');
      expect(userRepository.findByProvider).toHaveBeenCalledWith(AuthProvider.GOOGLE, 'google_123');
      expect(userRepository.save).toHaveBeenCalled();
      expect(tokenRepository.revokeAllByUserId).toHaveBeenCalled();
    });

    it('should successfully login existing Google user', async () => {
      // Arrange
      const existingUser = new User(
        'user_123',
        'user@example.com',
        '',
        'Existing User',
        undefined,
        AuthProvider.GOOGLE,
        'google_123',
      );

      const mockTokens = { access_token: 'google_access_token' };
      
      googleOAuthService.exchangeCodeForTokens.mockResolvedValue(mockTokens);
      googleOAuthService.getUserInfo.mockResolvedValue(mockGoogleUserInfo);
      userRepository.findByProvider.mockResolvedValue(existingUser);
      authSessionRepository.save.mockImplementation(session => Promise.resolve(session));
      tokenService.generateTokenPair.mockResolvedValue({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });

      // Act
      const result = await useCase.execute(googleRequest);

      // Assert
      expect(result.isNewUser).toBe(false);
      expect(result.user.id).toBe('user_123');
      expect(userRepository.save).not.toHaveBeenCalled(); // Existing user, no save needed
    });

    it('should link Google account to existing email user', async () => {
      // Arrange
      const existingUser = new User(
        'user_123',
        'user@example.com',
        'hashedPassword',
        'Existing User',
        undefined,
        AuthProvider.LOCAL,
      );

      const mockTokens = { access_token: 'google_access_token' };
      
      googleOAuthService.exchangeCodeForTokens.mockResolvedValue(mockTokens);
      googleOAuthService.getUserInfo.mockResolvedValue(mockGoogleUserInfo);
      userRepository.findByProvider.mockResolvedValue(null);
      userRepository.findByEmail.mockResolvedValue(existingUser);
      authSessionRepository.save.mockImplementation(session => Promise.resolve(session));
      tokenService.generateTokenPair.mockResolvedValue({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });

      // Act
      const result = await useCase.execute(googleRequest);

      // Assert
      expect(result.isNewUser).toBe(false);
      expect(result.user.id).toBe('user_123');
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('should throw OAuthAuthorizationError when Google code exchange fails', async () => {
      // Arrange
      googleOAuthService.exchangeCodeForTokens.mockRejectedValue(new Error('Code exchange failed'));

      // Act & Assert
      await expect(useCase.execute(googleRequest)).rejects.toThrow(OAuthAuthorizationError);
    });

    it('should throw OAuthAuthorizationError when Google user info retrieval fails', async () => {
      // Arrange
      const mockTokens = { access_token: 'google_access_token' };
      
      googleOAuthService.exchangeCodeForTokens.mockResolvedValue(mockTokens);
      googleOAuthService.getUserInfo.mockRejectedValue(new Error('User info failed'));

      // Act & Assert
      await expect(useCase.execute(googleRequest)).rejects.toThrow(OAuthAuthorizationError);
    });

    it('should throw OAuthUserInfoError when Google returns invalid user info', async () => {
      // Arrange
      const mockTokens = { access_token: 'google_access_token' };
      const invalidUserInfo = { id: 'google_123' }; // Missing email
      
      googleOAuthService.exchangeCodeForTokens.mockResolvedValue(mockTokens);
      googleOAuthService.getUserInfo.mockResolvedValue(invalidUserInfo);

      // Act & Assert
      await expect(useCase.execute(googleRequest)).rejects.toThrow(OAuthAuthorizationError);
    });

    it('should throw error when authorization code is missing for Google', async () => {
      // Arrange
      const invalidRequest = {
        provider: AuthProvider.GOOGLE,
        clientInfo: mockClientInfo,
      };

      // Act & Assert
      await expect(useCase.execute(invalidRequest as any)).rejects.toThrow('Authorization code is required for Google OAuth');
    });
  });

  describe('execute - Apple OAuth', () => {
    const appleRequest = {
      provider: AuthProvider.APPLE,
      idToken: 'apple_id_token_123',
      userInfo: { name: 'Apple User' },
      clientInfo: mockClientInfo,
    };

    const mockAccessToken = new Token(
      'access_token_123',
      'user_123',
      TokenType.ACCESS,
      'access.token.value',
      new Date(Date.now() + 15 * 60 * 1000),
    );

    const mockRefreshToken = new Token(
      'refresh_token_123',
      'user_123',
      TokenType.REFRESH,
      'refresh.token.value',
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    );

    it('should successfully login new Apple user', async () => {
      // Arrange
      appleOAuthService.verifyIdToken.mockResolvedValue(true);
      appleOAuthService.extractUserInfo.mockResolvedValue(mockAppleUserInfo);
      userRepository.findByProvider.mockResolvedValue(null);
      userRepository.findByEmail.mockResolvedValue(null);
      userRepository.save.mockImplementation(user => Promise.resolve(user));
      authSessionRepository.save.mockImplementation(session => Promise.resolve(session));
      tokenService.generateTokenPair.mockResolvedValue({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });

      // Act
      const result = await useCase.execute(appleRequest);

      // Assert
      expect(result).toEqual({
        accessToken: 'access.token.value',
        refreshToken: 'refresh.token.value',
        sessionId: expect.any(String),
        user: {
          id: expect.any(String),
          email: 'user@example.com',
          name: 'Apple User',
          profilePicture: 'https://example.com/avatar.jpg',
          provider: AuthProvider.APPLE,
          isActive: true,
        },
        isNewUser: true,
        expiresAt: mockAccessToken.getExpiresAt(),
      });

      expect(appleOAuthService.verifyIdToken).toHaveBeenCalledWith('apple_id_token_123');
      expect(appleOAuthService.extractUserInfo).toHaveBeenCalledWith('apple_id_token_123', { name: 'Apple User' });
    });

    it('should throw OAuthAuthorizationError when Apple ID token verification fails', async () => {
      // Arrange
      appleOAuthService.verifyIdToken.mockResolvedValue(false);

      // Act & Assert
      await expect(useCase.execute(appleRequest)).rejects.toThrow(OAuthAuthorizationError);
    });

    it('should throw OAuthAuthorizationError when Apple user info extraction fails', async () => {
      // Arrange
      appleOAuthService.verifyIdToken.mockResolvedValue(true);
      appleOAuthService.extractUserInfo.mockRejectedValue(new Error('Extraction failed'));

      // Act & Assert
      await expect(useCase.execute(appleRequest)).rejects.toThrow(OAuthAuthorizationError);
    });

    it('should throw error when ID token is missing for Apple', async () => {
      // Arrange
      const invalidRequest = {
        provider: AuthProvider.APPLE,
        clientInfo: mockClientInfo,
      };

      // Act & Assert
      await expect(useCase.execute(invalidRequest as any)).rejects.toThrow('ID token is required for Apple OAuth');
    });
  });

  describe('validation', () => {
    it('should throw error when provider is missing', async () => {
      // Arrange
      const invalidRequest = {
        authorizationCode: 'test_code',
        clientInfo: mockClientInfo,
      };

      // Act & Assert
      await expect(useCase.execute(invalidRequest as any)).rejects.toThrow('OAuth provider is required');
    });

    it('should throw UnsupportedProviderError for invalid provider', async () => {
      // Arrange
      const invalidRequest = {
        provider: 'INVALID_PROVIDER' as AuthProvider,
        authorizationCode: 'test_code',
        clientInfo: mockClientInfo,
      };

      // Act & Assert
      await expect(useCase.execute(invalidRequest)).rejects.toThrow(UnsupportedProviderError);
    });

    it('should throw error when user account is deactivated', async () => {
      // Arrange
      const deactivatedUser = new User(
        'user_123',
        'user@example.com',
        '',
        'Deactivated User',
        undefined,
        AuthProvider.GOOGLE,
        'google_123',
      );
      deactivatedUser.deactivate();

      const mockTokens = { access_token: 'google_access_token' };
      
      googleOAuthService.exchangeCodeForTokens.mockResolvedValue(mockTokens);
      googleOAuthService.getUserInfo.mockResolvedValue(mockGoogleUserInfo);
      userRepository.findByProvider.mockResolvedValue(deactivatedUser);

      const googleRequest = {
        provider: AuthProvider.GOOGLE,
        authorizationCode: 'google_auth_code_123',
        clientInfo: mockClientInfo,
      };

      // Act & Assert
      await expect(useCase.execute(googleRequest)).rejects.toThrow('User account is deactivated');
    });
  });
});