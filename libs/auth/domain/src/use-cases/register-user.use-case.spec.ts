import { RegisterUserUseCase } from './register-user.use-case';
import { User } from '../entities/user.entity';
import { Token } from '../entities/token.entity';
import { AuthSession } from '../entities/auth-session.entity';
import { UserRepository } from '../ports/repositories/user.repository';
import { TokenRepository } from '../ports/repositories/token.repository';
import { AuthSessionRepository } from '../ports/repositories/auth-session.repository';
import { PasswordHashingService } from '../ports/services/password-hashing.service';
import { TokenService } from '../ports/services/token.service';
import { AuthPresenter } from '../ports/presenters/auth.presenter';
import { RegisterUserRequest, AuthProvider } from '@auth/shared';

describe('RegisterUserUseCase', () => {
  let useCase: RegisterUserUseCase;
  let userRepository: jest.Mocked<UserRepository>;
  let tokenRepository: jest.Mocked<TokenRepository>;
  let sessionRepository: jest.Mocked<AuthSessionRepository>;
  let passwordHashingService: jest.Mocked<PasswordHashingService>;
  let tokenService: jest.Mocked<TokenService>;
  let presenter: jest.Mocked<AuthPresenter>;

  const validRequest: RegisterUserRequest = {
    email: 'test@example.com',
    password: 'SecurePass42!',
    name: 'Test User',
    profilePicture: 'https://example.com/profile.jpg',
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

    passwordHashingService = {
      hash: jest.fn(),
      compare: jest.fn(),
      generateSalt: jest.fn(),
      hashWithSalt: jest.fn(),
      getRounds: jest.fn(),
      needsRehash: jest.fn(),
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

    useCase = new RegisterUserUseCase(
      userRepository,
      tokenRepository,
      sessionRepository,
      passwordHashingService,
      tokenService,
      presenter
    );
  });

  describe('execute', () => {
    it('should successfully register a new user', async () => {
      // Arrange
      const hashedPassword = 'hashedPassword123';
      const accessTokenValue = 'access.token.jwt';
      const refreshTokenValue = 'refresh.token.jwt';
      const savedUser = User.create({
        id: 'user123',
        ...validRequest,
        password: hashedPassword,
        provider: AuthProvider.LOCAL,
      });

      userRepository.findByEmail.mockResolvedValue(null);
      passwordHashingService.hash.mockResolvedValue(hashedPassword);
      userRepository.save.mockResolvedValue(savedUser);
      tokenService.generateAccessToken.mockResolvedValue(accessTokenValue);
      tokenService.generateRefreshToken.mockResolvedValue(refreshTokenValue);
      tokenRepository.save.mockResolvedValue({} as Token);
      sessionRepository.save.mockResolvedValue({} as AuthSession);

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(userRepository.findByEmail).toHaveBeenCalledWith(validRequest.email);
      expect(passwordHashingService.hash).toHaveBeenCalledWith(validRequest.password);
      expect(userRepository.save).toHaveBeenCalledWith(expect.any(User));
      expect(tokenService.generateAccessToken).toHaveBeenCalledWith(
        savedUser.id,
        savedUser.email,
        '15m'
      );
      expect(tokenService.generateRefreshToken).toHaveBeenCalledWith(
        savedUser.id,
        savedUser.email,
        '7d'
      );
      expect(tokenRepository.save).toHaveBeenCalledTimes(2); // access + refresh tokens
      expect(sessionRepository.save).toHaveBeenCalledWith(expect.any(AuthSession));
      expect(presenter.presentRegistrationSuccess).toHaveBeenCalledWith({
        user: {
          id: savedUser.id,
          email: savedUser.email,
          name: savedUser.name,
          profilePicture: savedUser.profilePicture,
          provider: savedUser.provider,
          createdAt: savedUser.toObject()['createdAt'],
        },
        tokens: {
          accessToken: accessTokenValue,
          refreshToken: refreshTokenValue,
          expiresIn: 15 * 60, // 15 minutes
        },
      });
    });

    it('should present duplicate email error when user already exists', async () => {
      // Arrange
      const existingUser = User.create({
        id: 'existing-user',
        ...validRequest,
        password: 'HashedPass123!',
        provider: AuthProvider.LOCAL,
      });
      userRepository.findByEmail.mockResolvedValue(existingUser);

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(userRepository.findByEmail).toHaveBeenCalledWith(validRequest.email);
      expect(presenter.presentDuplicateEmail).toHaveBeenCalledWith(validRequest.email);
      expect(passwordHashingService.hash).not.toHaveBeenCalled();
    });

    it('should validate email format and present validation error', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, email: 'invalid-email', password: 'ValidPass123!' };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        email: ['Invalid email format'],
      });
      expect(userRepository.findByEmail).not.toHaveBeenCalled();
    });

    it('should validate required email and present validation error', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, email: '' };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        email: ['Email is required'],
      });
    });

    it('should validate password strength and present validation errors', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, password: 'weak' };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        password: [
          'Password must be at least 8 characters long',
          'Password must contain at least one uppercase letter',
          'Password must contain at least one number',
          'Password must contain at least one special character',
        ],
      });
    });

    it('should validate required password and present validation error', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, password: '' };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        password: ['Password is required'],
      });
    });

    it('should validate name requirements and present validation errors', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, name: 'A' };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        name: ['Name must be at least 2 characters long'],
      });
    });

    it('should validate name length limit and present validation error', async () => {
      // Arrange
      const longName = 'A'.repeat(101);
      const invalidRequest = { ...validRequest, name: longName };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        name: ['Name must not exceed 100 characters'],
      });
    });

    it('should validate required name and present validation error', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, name: '' };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        name: ['Name is required'],
      });
    });

    it('should validate profile picture URL format', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, profilePicture: 'invalid-url' };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        profilePicture: ['Invalid profile picture URL format'],
      });
    });

    it('should allow registration without profile picture', async () => {
      // Arrange
      const requestWithoutPicture = { ...validRequest };
      delete requestWithoutPicture.profilePicture;
      
      const hashedPassword = 'hashedPassword123';
      const accessTokenValue = 'access.token.jwt';
      const refreshTokenValue = 'refresh.token.jwt';
      const savedUser = User.create({
        id: 'user123',
        ...requestWithoutPicture,
        password: hashedPassword,
        provider: AuthProvider.LOCAL,
      });

      userRepository.findByEmail.mockResolvedValue(null);
      passwordHashingService.hash.mockResolvedValue(hashedPassword);
      userRepository.save.mockResolvedValue(savedUser);
      tokenService.generateAccessToken.mockResolvedValue(accessTokenValue);
      tokenService.generateRefreshToken.mockResolvedValue(refreshTokenValue);
      tokenRepository.save.mockResolvedValue({} as Token);
      sessionRepository.save.mockResolvedValue({} as AuthSession);

      // Act
      await useCase.execute(requestWithoutPicture);

      // Assert
      expect(presenter.presentRegistrationSuccess).toHaveBeenCalled();
    });

    it('should validate multiple fields and present all validation errors', async () => {
      // Arrange
      const invalidRequest = {
        email: 'invalid-email',
        password: 'weak',
        name: '',
        profilePicture: 'invalid-url',
      };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        email: ['Invalid email format'],
        password: [
          'Password must be at least 8 characters long',
          'Password must contain at least one uppercase letter',
          'Password must contain at least one number',
          'Password must contain at least one special character',
        ],
        name: ['Name is required'],
        profilePicture: ['Invalid profile picture URL format'],
      });
    });

    it('should detect common password patterns', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, password: 'Password123abc' };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        password: ['Password must not contain common sequences'],
      });
    });

    it('should detect repeated characters in password', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, password: 'Passsssword123!' };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        password: ['Password must not contain repeated characters'],
      });
    });

    it('should handle password length limits', async () => {
      // Arrange
      const longPassword = 'A'.repeat(129) + '1!';
      const invalidRequest = { ...validRequest, password: longPassword };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
        password: ['Password must not exceed 128 characters'],
      });
    });

    it('should handle unexpected errors during registration', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(null);
      passwordHashingService.hash.mockRejectedValue(new Error('Hashing failed'));

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(presenter.presentAuthenticationError).toHaveBeenCalledWith(
        'Registration failed due to an internal error',
        'REGISTRATION_ERROR'
      );
    });

    it('should handle token generation errors', async () => {
      // Arrange
      const hashedPassword = 'hashedPassword123';
      const savedUser = User.create({
        id: 'user123',
        ...validRequest,
        password: 'HashedSecure42$',
        provider: AuthProvider.LOCAL,
      });

      userRepository.findByEmail.mockResolvedValue(null);
      passwordHashingService.hash.mockResolvedValue(hashedPassword);
      userRepository.save.mockResolvedValue(savedUser);
      tokenService.generateAccessToken.mockRejectedValue(new Error('Token generation failed'));

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(presenter.presentAuthenticationError).toHaveBeenCalledWith(
        'Registration failed due to an internal error',
        'REGISTRATION_ERROR'
      );
    });

    it('should handle database save errors', async () => {
      // Arrange
      const hashedPassword = 'hashedPassword123';

      userRepository.findByEmail.mockResolvedValue(null);
      passwordHashingService.hash.mockResolvedValue(hashedPassword);
      userRepository.save.mockRejectedValue(new Error('Database save failed'));

      // Act
      await useCase.execute(validRequest);

      // Assert
      expect(presenter.presentAuthenticationError).toHaveBeenCalledWith(
        'Registration failed due to an internal error',
        'REGISTRATION_ERROR'
      );
    });
  });
});