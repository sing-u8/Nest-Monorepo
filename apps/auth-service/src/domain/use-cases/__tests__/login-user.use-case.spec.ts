import { Test, TestingModule } from '@nestjs/testing';
import { LoginUserUseCase, InvalidCredentialsError, UserNotActiveError } from '../login-user.use-case';
import { UserRepository } from '../../ports/user.repository';
import { TokenRepository } from '../../ports/token.repository';
import { AuthSessionRepository } from '../../ports/auth-session.repository';
import { PasswordHashingService } from '../../ports/password-hashing.service';
import { TokenService } from '../../ports/token.service';
import { User } from '../../entities/user.entity';
import { Token } from '../../entities/token.entity';
import { AuthSession } from '../../entities/auth-session.entity';
import { LoginUserRequest } from '../../models/auth.models';
import { AuthProvider, TokenType, ClientInfo } from '@auth/shared/types/auth.types';

describe('LoginUserUseCase', () => {
  let useCase: LoginUserUseCase;
  let userRepository: jest.Mocked<UserRepository>;
  let tokenRepository: jest.Mocked<TokenRepository>;
  let authSessionRepository: jest.Mocked<AuthSessionRepository>;
  let passwordHashingService: jest.Mocked<PasswordHashingService>;
  let tokenService: jest.Mocked<TokenService>;

  const clientInfo: ClientInfo = {
    userAgent: 'Mozilla/5.0',
    ipAddress: '192.168.1.1',
    deviceId: 'device-123',
  };

  const validRequest: LoginUserRequest = {
    email: 'test@example.com',
    password: 'Password123!',
    clientInfo,
  };

  const mockUser = new User(
    'user_123',
    'test@example.com',
    'hashed_password',
    'Test User',
    undefined,
    AuthProvider.LOCAL
  );

  beforeEach(async () => {
    const mockUserRepository = {
      save: jest.fn(),
      findById: jest.fn(),
      findByEmail: jest.fn(),
      existsByEmail: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      activate: jest.fn(),
      deactivate: jest.fn(),
      findByProvider: jest.fn(),
    };

    const mockTokenRepository = {
      save: jest.fn(),
      findByValue: jest.fn(),
      findByUserId: jest.fn(),
      findByUserIdAndType: jest.fn(),
      revoke: jest.fn(),
      revokeAllByUserId: jest.fn(),
      deleteExpired: jest.fn(),
      existsByValue: jest.fn(),
      countActiveByUserId: jest.fn(),
    };

    const mockAuthSessionRepository = {
      save: jest.fn(),
      findById: jest.fn(),
      findBySessionToken: jest.fn(),
      findByUserId: jest.fn(),
      findActiveByUserId: jest.fn(),
      update: jest.fn(),
      revoke: jest.fn(),
      revokeAllByUserId: jest.fn(),
      deleteExpired: jest.fn(),
      deleteInactiveSessions: jest.fn(),
      existsBySessionToken: jest.fn(),
      updateActivity: jest.fn(),
      findByClientInfo: jest.fn(),
    };

    const mockPasswordHashingService = {
      hash: jest.fn(),
      compare: jest.fn(),
      isValidPasswordFormat: jest.fn(),
      generateSalt: jest.fn(),
    };

    const mockTokenService = {
      generateToken: jest.fn(),
      verifyToken: jest.fn(),
      decodeToken: jest.fn(),
      isTokenExpired: jest.fn(),
      generateTokenPair: jest.fn(),
      revokeToken: jest.fn(),
      isTokenRevoked: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LoginUserUseCase,
        { provide: 'UserRepository', useValue: mockUserRepository },
        { provide: 'TokenRepository', useValue: mockTokenRepository },
        { provide: 'AuthSessionRepository', useValue: mockAuthSessionRepository },
        { provide: 'PasswordHashingService', useValue: mockPasswordHashingService },
        { provide: 'TokenService', useValue: mockTokenService },
      ],
    }).compile();

    useCase = module.get<LoginUserUseCase>(LoginUserUseCase);
    userRepository = module.get('UserRepository');
    tokenRepository = module.get('TokenRepository');
    authSessionRepository = module.get('AuthSessionRepository');
    passwordHashingService = module.get('PasswordHashingService');
    tokenService = module.get('TokenService');
  });

  describe('execute', () => {
    it('should successfully login user with valid credentials', async () => {
      // Arrange
      const accessToken = 'access_token_123';
      const refreshToken = 'refresh_token_123';
      const mockTokenPair = { accessToken, refreshToken };

      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateTokenPair.mockResolvedValue(mockTokenPair);
      tokenRepository.revokeAllByUserId.mockResolvedValue();
      authSessionRepository.save.mockResolvedValue(expect.any(AuthSession));
      tokenRepository.save.mockResolvedValue(expect.any(Token));

      // Act
      const result = await useCase.execute(validRequest);

      // Assert
      expect(userRepository.findByEmail).toHaveBeenCalledWith(validRequest.email);
      expect(passwordHashingService.compare).toHaveBeenCalledWith(
        validRequest.password,
        mockUser.getPassword()
      );
      expect(tokenService.generateTokenPair).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          email: mockUser.email,
          type: TokenType.ACCESS,
        })
      );
      expect(tokenRepository.revokeAllByUserId).toHaveBeenCalledWith(mockUser.id);
      expect(authSessionRepository.save).toHaveBeenCalled();
      expect(tokenRepository.save).toHaveBeenCalledTimes(2); // access and refresh tokens

      expect(result).toEqual({
        accessToken,
        refreshToken,
        sessionId: expect.any(String),
        user: {
          id: mockUser.id,
          email: mockUser.email,
          name: mockUser.name,
          profilePicture: mockUser.profilePicture,
          isActive: mockUser.isAccountActive(),
        },
        expiresAt: expect.any(Date),
      });
    });

    it('should login user without client info', async () => {
      // Arrange
      const requestWithoutClientInfo = { ...validRequest, clientInfo: undefined };
      const accessToken = 'access_token_123';
      const refreshToken = 'refresh_token_123';
      const mockTokenPair = { accessToken, refreshToken };

      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateTokenPair.mockResolvedValue(mockTokenPair);
      tokenRepository.revokeAllByUserId.mockResolvedValue();
      authSessionRepository.save.mockResolvedValue(expect.any(AuthSession));
      tokenRepository.save.mockResolvedValue(expect.any(Token));

      // Act
      const result = await useCase.execute(requestWithoutClientInfo);

      // Assert
      expect(result.accessToken).toBe(accessToken);
      expect(result.refreshToken).toBe(refreshToken);
    });

    it('should throw InvalidCredentialsError when user not found', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(null);

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow(InvalidCredentialsError);
      expect(userRepository.findByEmail).toHaveBeenCalledWith(validRequest.email);
      expect(passwordHashingService.compare).not.toHaveBeenCalled();
    });

    it('should throw UserNotActiveError when user is not active', async () => {
      // Arrange
      const inactiveUser = new User(
        'user_123',
        'test@example.com',
        'hashed_password',
        'Test User',
        undefined,
        AuthProvider.LOCAL
      );
      inactiveUser.deactivate();

      userRepository.findByEmail.mockResolvedValue(inactiveUser);

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow(UserNotActiveError);
      expect(passwordHashingService.compare).not.toHaveBeenCalled();
    });

    it('should throw InvalidCredentialsError when password is invalid', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(false);

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow(InvalidCredentialsError);
      expect(passwordHashingService.compare).toHaveBeenCalledWith(
        validRequest.password,
        mockUser.getPassword()
      );
      expect(tokenService.generateTokenPair).not.toHaveBeenCalled();
    });

    it('should throw error when email is empty', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, email: '' };

      // Act & Assert
      await expect(useCase.execute(invalidRequest)).rejects.toThrow('Email is required');
    });

    it('should throw error when password is empty', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, password: '' };

      // Act & Assert
      await expect(useCase.execute(invalidRequest)).rejects.toThrow('Password is required');
    });

    it('should throw error when email format is invalid', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, email: 'invalid-email' };

      // Act & Assert
      await expect(useCase.execute(invalidRequest)).rejects.toThrow('Invalid email format');
    });

    it('should handle token generation failure', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateTokenPair.mockRejectedValue(new Error('Token generation failed'));

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('Token generation failed');
    });

    it('should handle session save failure', async () => {
      // Arrange
      const accessToken = 'access_token_123';
      const refreshToken = 'refresh_token_123';
      const mockTokenPair = { accessToken, refreshToken };

      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateTokenPair.mockResolvedValue(mockTokenPair);
      tokenRepository.revokeAllByUserId.mockResolvedValue();
      authSessionRepository.save.mockRejectedValue(new Error('Session save failed'));

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('Session save failed');
    });

    it('should handle token save failure', async () => {
      // Arrange
      const accessToken = 'access_token_123';
      const refreshToken = 'refresh_token_123';
      const mockTokenPair = { accessToken, refreshToken };

      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateTokenPair.mockResolvedValue(mockTokenPair);
      tokenRepository.revokeAllByUserId.mockResolvedValue();
      authSessionRepository.save.mockResolvedValue(expect.any(AuthSession));
      tokenRepository.save.mockRejectedValue(new Error('Token save failed'));

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('Token save failed');
    });
  });
});