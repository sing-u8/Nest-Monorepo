import { Test, TestingModule } from '@nestjs/testing';
import { RefreshTokenUseCase, InvalidRefreshTokenError, TokenExpiredError, UserNotActiveError } from '../refresh-token.use-case';
import { UserRepository } from '../../ports/user.repository';
import { TokenRepository } from '../../ports/token.repository';
import { AuthSessionRepository } from '../../ports/auth-session.repository';
import { TokenService } from '../../ports/token.service';
import { User } from '../../entities/user.entity';
import { Token } from '../../entities/token.entity';
import { AuthSession } from '../../entities/auth-session.entity';
import { AuthProvider, TokenType, ClientInfo } from '@auth/shared/types/auth.types';

describe('RefreshTokenUseCase', () => {
  let useCase: RefreshTokenUseCase;
  let userRepository: jest.Mocked<UserRepository>;
  let tokenRepository: jest.Mocked<TokenRepository>;
  let authSessionRepository: jest.Mocked<AuthSessionRepository>;
  let tokenService: jest.Mocked<TokenService>;

  const mockClientInfo: ClientInfo = {
    userAgent: 'Mozilla/5.0 Test Browser',
    ipAddress: '192.168.1.1',
    deviceId: 'test-device-123',
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

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RefreshTokenUseCase,
        { provide: 'UserRepository', useValue: mockUserRepository },
        { provide: 'TokenRepository', useValue: mockTokenRepository },
        { provide: 'AuthSessionRepository', useValue: mockAuthSessionRepository },
        { provide: 'TokenService', useValue: mockTokenService },
      ],
    }).compile();

    useCase = module.get<RefreshTokenUseCase>(RefreshTokenUseCase);
    userRepository = module.get('UserRepository');
    tokenRepository = module.get('TokenRepository');
    authSessionRepository = module.get('AuthSessionRepository');
    tokenService = module.get('TokenService');
  });

  describe('execute', () => {
    const validRefreshToken = 'valid.refresh.token';
    const mockUser = new User(
      'user_123',
      'test@example.com',
      'hashedPassword',
      'Test User',
      undefined,
      AuthProvider.LOCAL,
    );

    const mockToken = new Token(
      'token_123',
      'user_123',
      TokenType.REFRESH,
      validRefreshToken,
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
    );

    const mockSession = new AuthSession(
      'session_123',
      'user_123',
      'session_token_123',
      mockClientInfo,
      new Date(Date.now() + 24 * 60 * 60 * 1000), // 1 day from now
    );

    const mockTokenPayload = {
      userId: 'user_123',
      email: 'test@example.com',
      type: TokenType.REFRESH,
      sessionId: 'session_123',
    };

    it('should successfully refresh tokens with valid refresh token', async () => {
      // Arrange
      const request = { 
        refreshToken: validRefreshToken,
        clientInfo: mockClientInfo,
      };

      const newAccessToken = new Token(
        'new_access_token_123',
        'user_123',
        TokenType.ACCESS,
        'new.access.token',
        new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      );

      const newRefreshToken = new Token(
        'new_refresh_token_123',
        'user_123',
        TokenType.REFRESH,
        'new.refresh.token',
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      );

      tokenRepository.findByValue.mockResolvedValue(mockToken);
      tokenService.verifyToken.mockResolvedValue(mockTokenPayload);
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findByUserId.mockResolvedValue(mockSession);
      tokenService.generateTokenPair.mockResolvedValue({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });

      // Act
      const result = await useCase.execute(request);

      // Assert
      expect(result).toEqual({
        accessToken: 'new.access.token',
        refreshToken: 'new.refresh.token',
        sessionId: 'session_123',
        expiresAt: newAccessToken.getExpiresAt(),
      });

      expect(tokenRepository.findByValue).toHaveBeenCalledWith(validRefreshToken);
      expect(tokenService.verifyToken).toHaveBeenCalledWith(validRefreshToken, TokenType.REFRESH);
      expect(userRepository.findById).toHaveBeenCalledWith('user_123');
      expect(tokenRepository.revokeAllByUserId).toHaveBeenCalledWith('user_123');
      expect(tokenRepository.save).toHaveBeenCalledWith(mockToken);
      expect(tokenRepository.save).toHaveBeenCalledWith(newAccessToken);
      expect(tokenRepository.save).toHaveBeenCalledWith(newRefreshToken);
      expect(authSessionRepository.save).toHaveBeenCalledWith(mockSession);
    });

    it('should throw InvalidRefreshTokenError when refresh token is not found', async () => {
      // Arrange
      const request = { refreshToken: 'nonexistent.token' };
      tokenRepository.findByValue.mockResolvedValue(null);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(InvalidRefreshTokenError);
      expect(tokenRepository.findByValue).toHaveBeenCalledWith('nonexistent.token');
    });

    it('should throw InvalidRefreshTokenError when refresh token is invalid', async () => {
      // Arrange
      const invalidToken = new Token(
        'token_123',
        'user_123',
        TokenType.REFRESH,
        validRefreshToken,
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      );
      invalidToken.revoke(); // Make token invalid

      const request = { refreshToken: validRefreshToken };
      tokenRepository.findByValue.mockResolvedValue(invalidToken);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(InvalidRefreshTokenError);
    });

    it('should throw TokenExpiredError when refresh token is expired', async () => {
      // Arrange
      const expiredToken = new Token(
        'token_123',
        'user_123',
        TokenType.REFRESH,
        validRefreshToken,
        new Date(Date.now() - 1000), // Expired 1 second ago
      );

      const request = { refreshToken: validRefreshToken };
      tokenRepository.findByValue.mockResolvedValue(expiredToken);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(TokenExpiredError);
    });

    it('should throw InvalidRefreshTokenError when token verification fails', async () => {
      // Arrange
      const request = { refreshToken: validRefreshToken };
      tokenRepository.findByValue.mockResolvedValue(mockToken);
      tokenService.verifyToken.mockResolvedValue(null);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(InvalidRefreshTokenError);
    });

    it('should throw InvalidRefreshTokenError when token type is not REFRESH', async () => {
      // Arrange
      const invalidPayload = {
        ...mockTokenPayload,
        type: TokenType.ACCESS, // Wrong type
      };

      const request = { refreshToken: validRefreshToken };
      tokenRepository.findByValue.mockResolvedValue(mockToken);
      tokenService.verifyToken.mockResolvedValue(invalidPayload);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(InvalidRefreshTokenError);
    });

    it('should throw InvalidRefreshTokenError when user is not found', async () => {
      // Arrange
      const request = { refreshToken: validRefreshToken };
      tokenRepository.findByValue.mockResolvedValue(mockToken);
      tokenService.verifyToken.mockResolvedValue(mockTokenPayload);
      userRepository.findById.mockResolvedValue(null);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(InvalidRefreshTokenError);
    });

    it('should throw UserNotActiveError when user is not active', async () => {
      // Arrange
      const inactiveUser = new User(
        'user_123',
        'test@example.com',
        'hashedPassword',
        'Test User',
        undefined,
        AuthProvider.LOCAL,
      );
      inactiveUser.deactivate();

      const request = { refreshToken: validRefreshToken };
      tokenRepository.findByValue.mockResolvedValue(mockToken);
      tokenService.verifyToken.mockResolvedValue(mockTokenPayload);
      userRepository.findById.mockResolvedValue(inactiveUser);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(UserNotActiveError);
    });

    it('should throw InvalidRefreshTokenError when session is not found', async () => {
      // Arrange
      const request = { refreshToken: validRefreshToken };
      tokenRepository.findByValue.mockResolvedValue(mockToken);
      tokenService.verifyToken.mockResolvedValue(mockTokenPayload);
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findByUserId.mockResolvedValue(null);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(InvalidRefreshTokenError);
    });

    it('should throw InvalidRefreshTokenError when session is invalid', async () => {
      // Arrange
      const expiredSession = new AuthSession(
        'session_123',
        'user_123',
        'session_token_123',
        mockClientInfo,
        new Date(Date.now() - 1000), // Expired session
      );

      const request = { refreshToken: validRefreshToken };
      tokenRepository.findByValue.mockResolvedValue(mockToken);
      tokenService.verifyToken.mockResolvedValue(mockTokenPayload);
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findByUserId.mockResolvedValue(expiredSession);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(InvalidRefreshTokenError);
    });

    it('should throw error when refresh token format is invalid', async () => {
      // Arrange
      const request = { refreshToken: 'invalid.token' }; // Only 2 parts instead of 3

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(InvalidRefreshTokenError);
    });

    it('should throw error when refresh token is empty', async () => {
      // Arrange
      const request = { refreshToken: '' };

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow('Refresh token is required');
    });

    it('should throw error when refresh token is not provided', async () => {
      // Arrange
      const request = {} as any;

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow('Refresh token is required');
    });

    it('should successfully refresh tokens without updating session when clientInfo is not provided', async () => {
      // Arrange
      const request = { refreshToken: validRefreshToken }; // No clientInfo

      const newAccessToken = new Token(
        'new_access_token_123',
        'user_123',
        TokenType.ACCESS,
        'new.access.token',
        new Date(Date.now() + 15 * 60 * 1000),
      );

      const newRefreshToken = new Token(
        'new_refresh_token_123',
        'user_123',
        TokenType.REFRESH,
        'new.refresh.token',
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      );

      tokenRepository.findByValue.mockResolvedValue(mockToken);
      tokenService.verifyToken.mockResolvedValue(mockTokenPayload);
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findByUserId.mockResolvedValue(mockSession);
      tokenService.generateTokenPair.mockResolvedValue({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });

      // Act
      const result = await useCase.execute(request);

      // Assert
      expect(result).toEqual({
        accessToken: 'new.access.token',
        refreshToken: 'new.refresh.token',
        sessionId: 'session_123',
        expiresAt: newAccessToken.getExpiresAt(),
      });

      // Session should not be updated when clientInfo is not provided
      expect(authSessionRepository.save).not.toHaveBeenCalledWith(
        expect.objectContaining({ clientInfo: mockClientInfo })
      );
    });
  });
});