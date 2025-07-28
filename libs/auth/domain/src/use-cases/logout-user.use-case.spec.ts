import { Test, TestingModule } from '@nestjs/testing';
import { LogoutUserUseCase } from './logout-user.use-case';
import { UserRepository, TokenRepository, AuthSessionRepository } from '../ports/repositories';
import { TokenService } from '../ports/services';
import { LogoutUserPresenter } from '../ports/presenters';
import { User } from '../entities/user.entity';
import { Token } from '../entities/token.entity';
import { AuthSession } from '../entities/auth-session.entity';
import { LogoutUserRequest } from '@auth/shared';

describe('LogoutUserUseCase', () => {
  let useCase: LogoutUserUseCase;
  let userRepository: jest.Mocked<UserRepository>;
  let tokenRepository: jest.Mocked<TokenRepository>;
  let authSessionRepository: jest.Mocked<AuthSessionRepository>;
  let tokenService: jest.Mocked<TokenService>;
  let presenter: jest.Mocked<LogoutUserPresenter>;

  // Mock entities
  let mockUser: jest.Mocked<User>;
  let mockToken: jest.Mocked<Token>;
  let mockSession: jest.Mocked<AuthSession>;

  beforeEach(async () => {
    // Create mocked repositories
    userRepository = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
      findByProvider: jest.fn(),
      findActiveUsers: jest.fn(),
      findUsersByStatus: jest.fn(),
      count: jest.fn(),
    } as any;

    tokenRepository = {
      findById: jest.fn(),
      findByUserId: jest.fn(),
      findByValue: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
      deleteExpiredTokens: jest.fn(),
      deleteRevokedTokensOlderThan: jest.fn(),
      revokeAllUserTokens: jest.fn(),
      findExpiredTokens: jest.fn(),
    } as any;

    authSessionRepository = {
      findById: jest.fn(),
      findActiveByUserId: jest.fn(),
      findByToken: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
      deleteExpiredSessions: jest.fn(),
      invalidateAllUserSessions: jest.fn(),
      findActiveSessions: jest.fn(),
      findExpiredSessions: jest.fn(),
    } as any;

    // Create mocked services
    tokenService = {
      generateAccessToken: jest.fn(),
      generateRefreshToken: jest.fn(),
      validateToken: jest.fn(),
      refreshAccessToken: jest.fn(),
      blacklistToken: jest.fn(),
      isTokenBlacklisted: jest.fn(),
      generateSecureRandomToken: jest.fn(),
      signData: jest.fn(),
      verifyData: jest.fn(),
      getConfiguration: jest.fn(),
      healthCheck: jest.fn(),
    } as any;

    // Create mocked presenter
    presenter = {
      presentLogoutSuccess: jest.fn(),
      presentInvalidRefreshToken: jest.fn(),
      presentUserNotFound: jest.fn(),
      presentValidationError: jest.fn(),
      presentInternalError: jest.fn(),
    } as any;

    // Create mock entities
    mockUser = {
      getId: jest.fn().mockReturnValue('user-123'),
      getEmail: jest.fn().mockReturnValue('test@example.com'),
      getName: jest.fn().mockReturnValue('John Doe'),
      getStatus: jest.fn().mockReturnValue('active'),
      getProvider: jest.fn().mockReturnValue('local'),
      getProviderId: jest.fn().mockReturnValue(null),
      getCreatedAt: jest.fn().mockReturnValue(new Date()),
      getUpdatedAt: jest.fn().mockReturnValue(new Date()),
      getLastLoginAt: jest.fn().mockReturnValue(new Date()),
      updatePassword: jest.fn(),
      updateProfile: jest.fn(),
      updateLastLogin: jest.fn(),
      activate: jest.fn(),
      deactivate: jest.fn(),
      suspend: jest.fn(),
      markAsDeleted: jest.fn(),
      validatePassword: jest.fn(),
    } as any;

    mockToken = {
      getId: jest.fn().mockReturnValue('token-123'),
      getUserId: jest.fn().mockReturnValue('user-123'),
      getType: jest.fn().mockReturnValue('refresh'),
      getValue: jest.fn().mockReturnValue('refresh-token-value'),
      getExpiresAt: jest.fn().mockReturnValue(new Date(Date.now() + 3600000)),
      getRevokedAt: jest.fn().mockReturnValue(null),
      getCreatedAt: jest.fn().mockReturnValue(new Date()),
      isExpired: jest.fn().mockReturnValue(false),
      isRevoked: jest.fn().mockReturnValue(false),
      isValid: jest.fn().mockReturnValue(true),
      revoke: jest.fn(),
    } as any;

    mockSession = {
      getId: jest.fn().mockReturnValue('session-123'),
      getUserId: jest.fn().mockReturnValue('user-123'),
      getToken: jest.fn().mockReturnValue('session-token'),
      getClientInfo: jest.fn().mockReturnValue({
        userAgent: 'Mozilla/5.0...',
        ipAddress: '192.168.1.1',
        deviceId: 'device-123',
      }),
      getExpiresAt: jest.fn().mockReturnValue(new Date(Date.now() + 3600000)),
      getLastActivity: jest.fn().mockReturnValue(new Date()),
      getStatus: jest.fn().mockReturnValue('active'),
      getCreatedAt: jest.fn().mockReturnValue(new Date()),
      isExpired: jest.fn().mockReturnValue(false),
      isActive: jest.fn().mockReturnValue(true),
      updateActivity: jest.fn(),
      extendSession: jest.fn(),
      invalidate: jest.fn(),
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LogoutUserUseCase,
        {
          provide: 'UserRepository',
          useValue: userRepository,
        },
        {
          provide: 'TokenRepository',
          useValue: tokenRepository,
        },
        {
          provide: 'AuthSessionRepository',
          useValue: authSessionRepository,
        },
        {
          provide: 'TokenService',
          useValue: tokenService,
        },
        {
          provide: 'LogoutUserPresenter',
          useValue: presenter,
        },
      ],
    }).compile();

    useCase = module.get<LogoutUserUseCase>(LogoutUserUseCase);

    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('execute - successful logout from current device', () => {
    const mockRequest: LogoutUserRequest = {
      refreshToken: 'valid.refresh.token',
      logoutFromAllDevices: false,
      clientInfo: {
        userAgent: 'Mozilla/5.0...',
        ipAddress: '192.168.1.1',
        deviceId: 'device-123',
      },
    };

    it('should logout user from current device successfully', async () => {
      const mockTokenValidation = {
        isValid: true,
        payload: {
          sub: 'user-123',
          email: 'test@example.com',
          type: 'refresh',
        },
      };

      const mockLogoutResult = {
        loggedOutAt: expect.any(Date),
        sessionsClosed: 1,
        tokensRevoked: 2,
        user: {
          id: 'user-123',
          email: 'test@example.com',
          name: 'John Doe',
        },
      };

      const mockPresentationResult = {
        success: true,
        message: 'Logout successful',
        data: mockLogoutResult,
      };

      // Setup mocks
      tokenService.validateToken.mockResolvedValue(mockTokenValidation);
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findActiveByUserId.mockResolvedValue([mockSession]);
      tokenRepository.findByUserId.mockResolvedValue([mockToken]);
      tokenService.blacklistToken.mockResolvedValue(true);
      presenter.presentLogoutSuccess.mockReturnValue(mockPresentationResult);

      const result = await useCase.execute(mockRequest);

      expect(tokenService.validateToken).toHaveBeenCalledWith(mockRequest.refreshToken);
      expect(userRepository.findById).toHaveBeenCalledWith('user-123');
      expect(authSessionRepository.findActiveByUserId).toHaveBeenCalledWith('user-123');
      expect(tokenRepository.findByUserId).toHaveBeenCalledWith('user-123');
      expect(mockSession.invalidate).toHaveBeenCalled();
      expect(authSessionRepository.save).toHaveBeenCalledWith(mockSession);
      expect(mockToken.revoke).toHaveBeenCalled();
      expect(tokenRepository.save).toHaveBeenCalledWith(mockToken);
      expect(tokenService.blacklistToken).toHaveBeenCalledWith(mockRequest.refreshToken);
      expect(presenter.presentLogoutSuccess).toHaveBeenCalledWith(expect.objectContaining({
        sessionsClosed: 1,
        tokensRevoked: expect.any(Number),
        user: expect.objectContaining({
          id: 'user-123',
          email: 'test@example.com',
          name: 'John Doe',
        }),
      }));
      expect(result).toEqual(mockPresentationResult);
    });

    it('should perform cleanup tasks after logout', async () => {
      const mockTokenValidation = {
        isValid: true,
        payload: {
          sub: 'user-123',
          email: 'test@example.com',
          type: 'refresh',
        },
      };

      tokenService.validateToken.mockResolvedValue(mockTokenValidation);
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findActiveByUserId.mockResolvedValue([]);
      tokenRepository.findByUserId.mockResolvedValue([]);
      presenter.presentLogoutSuccess.mockReturnValue({ success: true } as any);

      await useCase.execute(mockRequest);

      expect(tokenRepository.deleteExpiredTokens).toHaveBeenCalled();
      expect(authSessionRepository.deleteExpiredSessions).toHaveBeenCalled();
      expect(tokenRepository.deleteRevokedTokensOlderThan).toHaveBeenCalledWith(expect.any(Date));
    });
  });

  describe('execute - successful logout from all devices', () => {
    const mockRequest: LogoutUserRequest = {
      refreshToken: 'valid.refresh.token',
      logoutFromAllDevices: true,
      clientInfo: {
        userAgent: 'Mozilla/5.0...',
        ipAddress: '192.168.1.1',
        deviceId: 'device-123',
      },
    };

    it('should logout user from all devices successfully', async () => {
      const mockTokenValidation = {
        isValid: true,
        payload: {
          sub: 'user-123',
          email: 'test@example.com',
          type: 'refresh',
        },
      };

      const mockSessions = [mockSession, { ...mockSession, getId: () => 'session-456' }] as any;
      const mockTokens = [mockToken, { ...mockToken, getId: () => 'token-456' }] as any;

      tokenService.validateToken.mockResolvedValue(mockTokenValidation);
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findActiveByUserId.mockResolvedValue(mockSessions);
      tokenRepository.findByUserId.mockResolvedValue(mockTokens);
      presenter.presentLogoutSuccess.mockReturnValue({ success: true } as any);

      const result = await useCase.execute(mockRequest);

      expect(authSessionRepository.findActiveByUserId).toHaveBeenCalledWith('user-123');
      expect(tokenRepository.findByUserId).toHaveBeenCalledWith('user-123');
      
      // Should invalidate all sessions
      mockSessions.forEach((session: any) => {
        expect(session.invalidate).toHaveBeenCalled();
      });
      expect(authSessionRepository.save).toHaveBeenCalledTimes(2);

      // Should revoke all tokens
      mockTokens.forEach((token: any) => {
        expect(token.revoke).toHaveBeenCalled();
      });
      expect(tokenRepository.save).toHaveBeenCalledTimes(2);
      expect(tokenService.blacklistToken).toHaveBeenCalledTimes(2);

      expect(presenter.presentLogoutSuccess).toHaveBeenCalledWith(expect.objectContaining({
        sessionsClosed: 2,
        tokensRevoked: 2,
      }));
    });
  });

  describe('execute - validation errors', () => {
    it('should handle missing refresh token', async () => {
      const invalidRequest = {
        refreshToken: '',
        logoutFromAllDevices: false,
        clientInfo: {},
      };

      presenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Refresh token is required for logout',
      });

      const result = await useCase.execute(invalidRequest);

      expect(presenter.presentValidationError).toHaveBeenCalledWith('Refresh token is required for logout');
      expect(result.success).toBe(false);
    });

    it('should handle invalid refresh token format', async () => {
      const invalidRequest = {
        refreshToken: 'invalid-format',
        logoutFromAllDevices: false,
        clientInfo: {},
      };

      presenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Invalid refresh token format',
      });

      const result = await useCase.execute(invalidRequest);

      expect(presenter.presentValidationError).toHaveBeenCalledWith('Invalid refresh token format');
      expect(result.success).toBe(false);
    });

    it('should handle invalid IP address format', async () => {
      const invalidRequest = {
        refreshToken: 'valid.refresh.token',
        logoutFromAllDevices: false,
        clientInfo: {
          ipAddress: 'invalid-ip',
        },
      };

      presenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Invalid IP address format',
      });

      const result = await useCase.execute(invalidRequest);

      expect(presenter.presentValidationError).toHaveBeenCalledWith('Invalid IP address format');
      expect(result.success).toBe(false);
    });

    it('should handle overly long user agent', async () => {
      const invalidRequest = {
        refreshToken: 'valid.refresh.token',
        logoutFromAllDevices: false,
        clientInfo: {
          userAgent: 'a'.repeat(1001), // Too long
        },
      };

      presenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'User agent is too long',
      });

      const result = await useCase.execute(invalidRequest);

      expect(presenter.presentValidationError).toHaveBeenCalledWith('User agent is too long');
      expect(result.success).toBe(false);
    });
  });

  describe('execute - authentication errors', () => {
    const mockRequest: LogoutUserRequest = {
      refreshToken: 'invalid.refresh.token',
      logoutFromAllDevices: false,
      clientInfo: {},
    };

    it('should handle invalid refresh token', async () => {
      const mockTokenValidation = {
        isValid: false,
        payload: null,
      };

      tokenService.validateToken.mockResolvedValue(mockTokenValidation);
      presenter.presentInvalidRefreshToken.mockReturnValue({
        success: false,
        error: 'INVALID_REFRESH_TOKEN',
        message: 'Refresh token is invalid or expired',
      });

      const result = await useCase.execute(mockRequest);

      expect(tokenService.validateToken).toHaveBeenCalledWith(mockRequest.refreshToken);
      expect(presenter.presentInvalidRefreshToken).toHaveBeenCalled();
      expect(result.success).toBe(false);
    });

    it('should handle user not found', async () => {
      const mockTokenValidation = {
        isValid: true,
        payload: {
          sub: 'non-existent-user',
          email: 'test@example.com',
          type: 'refresh',
        },
      };

      tokenService.validateToken.mockResolvedValue(mockTokenValidation);
      userRepository.findById.mockResolvedValue(null);
      presenter.presentUserNotFound.mockReturnValue({
        success: false,
        error: 'USER_NOT_FOUND',
        message: 'User not found',
      });

      const result = await useCase.execute(mockRequest);

      expect(userRepository.findById).toHaveBeenCalledWith('non-existent-user');
      expect(presenter.presentUserNotFound).toHaveBeenCalled();
      expect(result.success).toBe(false);
    });
  });

  describe('execute - error handling', () => {
    const mockRequest: LogoutUserRequest = {
      refreshToken: 'valid.refresh.token',
      logoutFromAllDevices: false,
      clientInfo: {},
    };

    it('should handle token service errors gracefully', async () => {
      tokenService.validateToken.mockRejectedValue(new Error('Token service unavailable'));
      presenter.presentInternalError.mockReturnValue({
        success: false,
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      });

      const result = await useCase.execute(mockRequest);

      expect(presenter.presentInternalError).toHaveBeenCalled();
      expect(result.success).toBe(false);
    });

    it('should handle database errors gracefully', async () => {
      const mockTokenValidation = {
        isValid: true,
        payload: {
          sub: 'user-123',
          email: 'test@example.com',
          type: 'refresh',
        },
      };

      tokenService.validateToken.mockResolvedValue(mockTokenValidation);
      userRepository.findById.mockRejectedValue(new Error('Database connection failed'));
      presenter.presentInternalError.mockReturnValue({
        success: false,
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      });

      const result = await useCase.execute(mockRequest);

      expect(presenter.presentInternalError).toHaveBeenCalled();
      expect(result.success).toBe(false);
    });

    it('should continue logout even if cleanup fails', async () => {
      const mockTokenValidation = {
        isValid: true,
        payload: {
          sub: 'user-123',
          email: 'test@example.com',
          type: 'refresh',
        },
      };

      tokenService.validateToken.mockResolvedValue(mockTokenValidation);
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findActiveByUserId.mockResolvedValue([]);
      tokenRepository.findByUserId.mockResolvedValue([]);
      
      // Cleanup operations fail
      tokenRepository.deleteExpiredTokens.mockRejectedValue(new Error('Cleanup failed'));
      authSessionRepository.deleteExpiredSessions.mockRejectedValue(new Error('Cleanup failed'));
      
      presenter.presentLogoutSuccess.mockReturnValue({ success: true } as any);

      const result = await useCase.execute(mockRequest);

      // Should still complete logout successfully
      expect(result.success).toBe(true);
      expect(presenter.presentLogoutSuccess).toHaveBeenCalled();
    });
  });

  describe('private methods validation', () => {
    it('should validate IPv4 addresses correctly', async () => {
      const validIPv4Request = {
        refreshToken: 'valid.refresh.token',
        logoutFromAllDevices: false,
        clientInfo: {
          ipAddress: '192.168.1.1',
        },
      };

      const mockTokenValidation = {
        isValid: true,
        payload: {
          sub: 'user-123',
          email: 'test@example.com',
          type: 'refresh',
        },
      };

      tokenService.validateToken.mockResolvedValue(mockTokenValidation);
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findActiveByUserId.mockResolvedValue([]);
      tokenRepository.findByUserId.mockResolvedValue([]);
      presenter.presentLogoutSuccess.mockReturnValue({ success: true } as any);

      const result = await useCase.execute(validIPv4Request);

      expect(result.success).toBe(true);
    });

    it('should validate IPv6 addresses correctly', async () => {
      const validIPv6Request = {
        refreshToken: 'valid.refresh.token',
        logoutFromAllDevices: false,
        clientInfo: {
          ipAddress: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        },
      };

      const mockTokenValidation = {
        isValid: true,
        payload: {
          sub: 'user-123',
          email: 'test@example.com',
          type: 'refresh',
        },
      };

      tokenService.validateToken.mockResolvedValue(mockTokenValidation);
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findActiveByUserId.mockResolvedValue([]);
      tokenRepository.findByUserId.mockResolvedValue([]);
      presenter.presentLogoutSuccess.mockReturnValue({ success: true } as any);

      const result = await useCase.execute(validIPv6Request);

      expect(result.success).toBe(true);
    });
  });
});