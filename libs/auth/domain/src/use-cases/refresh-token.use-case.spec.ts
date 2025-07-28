import { RefreshTokenUseCase } from './refresh-token.use-case';
import { User } from '../entities/user.entity';
import { Token } from '../entities/token.entity';
import { AuthSession } from '../entities/auth-session.entity';
import { UserRepository } from '../ports/repositories/user.repository';
import { TokenRepository } from '../ports/repositories/token.repository';
import { AuthSessionRepository } from '../ports/repositories/auth-session.repository';
import { TokenService } from '../ports/services/token.service';
import { AuthPresenter } from '../ports/presenters/auth.presenter';
import { RefreshTokenRequest, TokenType, AuthProvider } from '@auth/shared';

describe('RefreshTokenUseCase', () => {
  let useCase: RefreshTokenUseCase;
  let userRepository: jest.Mocked<UserRepository>;
  let tokenRepository: jest.Mocked<TokenRepository>;
  let sessionRepository: jest.Mocked<AuthSessionRepository>;
  let tokenService: jest.Mocked<TokenService>;
  let presenter: jest.Mocked<AuthPresenter>;

  const validRefreshToken = 'valid.refresh.token.jwt';
  const validRequest: RefreshTokenRequest = {
    refreshToken: validRefreshToken,
    clientInfo: {
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0 (Test Browser)',
    },
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

    useCase = new RefreshTokenUseCase(
      userRepository,
      tokenRepository,
      sessionRepository,
      tokenService,
      presenter
    );
  });

  describe('execute', () => {
    it('should successfully refresh tokens with token rotation', async () => {
      // Arrange
      const userId = 'user123';
      const newAccessToken = 'new.access.token.jwt';
      const newRefreshToken = 'new.refresh.token.jwt';

      const refreshToken = Token.createRefreshToken({
        id: 'refresh-token-1',
        userId: userId,
        value: validRefreshToken,
        expirationDays: 7,
      });

      const user = User.create({
        id: userId,
        email: 'test@example.com',
        password: 'HashedPass123!',
        name: 'Test User',
        provider: AuthProvider.LOCAL,
      });

      const activeSession = AuthSession.create({
        id: 'session-1',
        userId: userId,
        sessionToken: 'current.session.token',
        clientInfo: validRequest.clientInfo!,
        expirationHours: 24,
      });

      // Mock responses
      tokenRepository.findByValue.mockResolvedValue(refreshToken);
      userRepository.findById.mockResolvedValue(user);
      tokenService.validateToken.mockResolvedValue({ isValid: true });
      sessionRepository.findActiveByUserId.mockResolvedValue([activeSession]);
      tokenService.generateAccessToken.mockResolvedValue(newAccessToken);
      tokenService.generateRefreshToken.mockResolvedValue(newRefreshToken);
      tokenRepository.save.mockResolvedValue({} as Token);
      tokenRepository.findByUserId.mockResolvedValue([]);

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(tokenRepository.findByValue).toHaveBeenCalledWith(validRefreshToken);
      expect(userRepository.findById).toHaveBeenCalledWith(userId);
      expect(tokenService.validateToken).toHaveBeenCalledWith(validRefreshToken);
      expect(sessionRepository.findActiveByUserId).toHaveBeenCalledWith(userId);
      expect(tokenService.generateAccessToken).toHaveBeenCalledWith(userId, user.email, '15m');
      expect(tokenService.generateRefreshToken).toHaveBeenCalledWith(userId, user.email, '7d');
      expect(tokenRepository.save).toHaveBeenCalledTimes(3); // new access, new refresh, revoked old refresh
      expect(presenter.presentTokenRefreshSuccess).toHaveBeenCalledWith({
        tokens: {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
          expiresIn: 15 * 60,
        },
      });
    });

    it('should reject invalid refresh token', async () => {
      // Arrange
      tokenRepository.findByValue.mockResolvedValue(null);

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(tokenRepository.findByValue).toHaveBeenCalledWith(validRefreshToken);
      expect(presenter.presentTokenRefreshFailure).toHaveBeenCalledWith('Invalid or expired refresh token');
      expect(userRepository.findById).not.toHaveBeenCalled();
    });

    it('should reject expired refresh token', async () => {
      // Arrange
      // Create a token that will be manually expired
      const expiredToken = Token.createRefreshToken({
        id: 'expired-token',
        userId: 'user123',
        value: validRefreshToken,
        expirationDays: 1, // Create valid token first
      });
      
      // Mock isValid to return false (simulating expired/revoked token)
      jest.spyOn(expiredToken, 'isValid').mockReturnValue(false);

      tokenRepository.findByValue.mockResolvedValue(expiredToken);

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(presenter.presentTokenRefreshFailure).toHaveBeenCalledWith('Invalid or expired refresh token');
      expect(userRepository.findById).not.toHaveBeenCalled();
    });

    it('should reject revoked refresh token', async () => {
      // Arrange
      const revokedToken = Token.createRefreshToken({
        id: 'revoked-token',
        userId: 'user123',
        value: validRefreshToken,
        expirationDays: 7,
      });
      revokedToken.revoke();

      tokenRepository.findByValue.mockResolvedValue(revokedToken);

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(presenter.presentTokenRefreshFailure).toHaveBeenCalledWith('Invalid or expired refresh token');
      expect(userRepository.findById).not.toHaveBeenCalled();
    });

    it('should reject wrong token type', async () => {
      // Arrange
      const accessToken = Token.createAccessToken({
        id: 'access-token',
        userId: 'user123',
        value: validRefreshToken,
        expirationMinutes: 15,
      });

      tokenRepository.findByValue.mockResolvedValue(accessToken);

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(presenter.presentTokenRefreshFailure).toHaveBeenCalledWith('Invalid token type');
      expect(userRepository.findById).not.toHaveBeenCalled();
    });

    it('should handle user not found', async () => {
      // Arrange
      const refreshToken = Token.createRefreshToken({
        id: 'refresh-token',
        userId: 'nonexistent-user',
        value: validRefreshToken,
        expirationDays: 7,
      });

      tokenRepository.findByValue.mockResolvedValue(refreshToken);
      userRepository.findById.mockResolvedValue(null);
      tokenRepository.save.mockResolvedValue({} as Token);
      tokenRepository.revokeByUserId.mockResolvedValue(1);
      sessionRepository.invalidateByUserId.mockResolvedValue(1);

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(presenter.presentTokenRefreshFailure).toHaveBeenCalledWith('User not found');
      expect(tokenRepository.revokeByUserId).toHaveBeenCalledWith('nonexistent-user');
      expect(sessionRepository.invalidateByUserId).toHaveBeenCalledWith('nonexistent-user');
    });

    it('should handle inactive user account', async () => {
      // Arrange
      const refreshToken = Token.createRefreshToken({
        id: 'refresh-token',
        userId: 'user123',
        value: validRefreshToken,
        expirationDays: 7,
      });

      const inactiveUser = User.create({
        id: 'user123',
        email: 'test@example.com',
        password: 'HashedPass123!',
        name: 'Test User',
        provider: AuthProvider.LOCAL,
      });
      // Simulate inactive status
      inactiveUser.deactivate();

      tokenRepository.findByValue.mockResolvedValue(refreshToken);
      userRepository.findById.mockResolvedValue(inactiveUser);
      tokenRepository.save.mockResolvedValue({} as Token);
      tokenRepository.revokeByUserId.mockResolvedValue(1);
      sessionRepository.invalidateByUserId.mockResolvedValue(1);

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(presenter.presentTokenRefreshFailure).toHaveBeenCalledWith('Account is not active');
      expect(tokenRepository.revokeByUserId).toHaveBeenCalledWith('user123');
      expect(sessionRepository.invalidateByUserId).toHaveBeenCalledWith('user123');
    });

    it('should handle token service validation failure', async () => {
      // Arrange
      const refreshToken = Token.createRefreshToken({
        id: 'refresh-token',
        userId: 'user123',
        value: validRefreshToken,
        expirationDays: 7,
      });

      const user = User.create({
        id: 'user123',
        email: 'test@example.com',
        password: 'HashedPass123!',
        name: 'Test User',
        provider: AuthProvider.LOCAL,
      });

      tokenRepository.findByValue.mockResolvedValue(refreshToken);
      userRepository.findById.mockResolvedValue(user);
      tokenService.validateToken.mockResolvedValue({ isValid: false });
      tokenRepository.save.mockResolvedValue({} as Token);
      tokenRepository.revokeByUserId.mockResolvedValue(1);
      sessionRepository.invalidateByUserId.mockResolvedValue(1);

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(presenter.presentTokenRefreshFailure).toHaveBeenCalledWith('Token validation failed');
      expect(tokenRepository.revokeByUserId).toHaveBeenCalledWith('user123');
    });

    it('should handle session validation failure', async () => {
      // Arrange
      const refreshToken = Token.createRefreshToken({
        id: 'refresh-token',
        userId: 'user123',
        value: validRefreshToken,
        expirationDays: 7,
      });

      const user = User.create({
        id: 'user123',
        email: 'test@example.com',
        password: 'HashedPass123!',
        name: 'Test User',
        provider: AuthProvider.LOCAL,
      });

      tokenRepository.findByValue.mockResolvedValue(refreshToken);
      userRepository.findById.mockResolvedValue(user);
      tokenService.validateToken.mockResolvedValue({ isValid: true });
      sessionRepository.findActiveByUserId.mockResolvedValue([]); // No active sessions
      tokenRepository.save.mockResolvedValue({} as Token);
      tokenRepository.revokeByUserId.mockResolvedValue(1);
      sessionRepository.invalidateByUserId.mockResolvedValue(1);

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(presenter.presentTokenRefreshFailure).toHaveBeenCalledWith('Session validation failed');
      expect(tokenRepository.revokeByUserId).toHaveBeenCalledWith('user123');
    });

    it('should validate input and reject empty refresh token', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, refreshToken: '' };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentTokenRefreshFailure).toHaveBeenCalledWith('Refresh token is required');
      expect(tokenRepository.findByValue).not.toHaveBeenCalled();
    });

    it('should validate input and reject missing refresh token', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, refreshToken: undefined as any };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentTokenRefreshFailure).toHaveBeenCalledWith('Refresh token is required');
      expect(tokenRepository.findByValue).not.toHaveBeenCalled();
    });

    it('should work without client info provided', async () => {
      // Arrange
      const requestWithoutClientInfo = { refreshToken: validRefreshToken };
      const userId = 'user123';
      const newAccessToken = 'new.access.token.jwt';
      const newRefreshToken = 'new.refresh.token.jwt';

      const refreshToken = Token.createRefreshToken({
        id: 'refresh-token',
        userId: userId,
        value: validRefreshToken,
        expirationDays: 7,
      });

      const user = User.create({
        id: userId,
        email: 'test@example.com',
        password: 'HashedPass123!',
        name: 'Test User',
        provider: AuthProvider.LOCAL,
      });

      tokenRepository.findByValue.mockResolvedValue(refreshToken);
      userRepository.findById.mockResolvedValue(user);
      tokenService.validateToken.mockResolvedValue({ isValid: true });
      sessionRepository.findActiveByUserId.mockResolvedValue([]);
      tokenService.generateAccessToken.mockResolvedValue(newAccessToken);
      tokenService.generateRefreshToken.mockResolvedValue(newRefreshToken);
      tokenRepository.save.mockResolvedValue({} as Token);
      tokenRepository.findByUserId.mockResolvedValue([]);

      // Act
      await useCase.execute(requestWithoutClientInfo);

      // Assert
      expect(presenter.presentTokenRefreshSuccess).toHaveBeenCalledWith({
        tokens: {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
          expiresIn: 15 * 60,
        },
      });
    });

    it('should handle unexpected errors during refresh', async () => {
      // Arrange
      tokenRepository.findByValue.mockRejectedValue(new Error('Database error'));

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(presenter.presentTokenRefreshFailure).toHaveBeenCalledWith(
        'Token refresh failed due to an internal error'
      );
    });
  });
});