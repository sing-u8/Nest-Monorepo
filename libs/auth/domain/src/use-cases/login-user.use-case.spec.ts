import { LoginUserUseCase } from './login-user.use-case';
import { UserRepository } from '../ports/repositories/user.repository';
import { TokenRepository } from '../ports/repositories/token.repository';
import { AuthSessionRepository } from '../ports/repositories/auth-session.repository';
import { PasswordHashingService } from '../ports/services/password-hashing.service';
import { TokenService } from '../ports/services/token.service';
import { AuthPresenter } from '../ports/presenters/auth.presenter';
import { User } from '../entities/user.entity';
import { Token } from '../entities/token.entity';
import { AuthSession } from '../entities/auth-session.entity';
import { LoginUserRequest } from '@auth/shared';
import { AuthProvider } from '@auth/shared';

describe('LoginUserUseCase', () => {
  let useCase: LoginUserUseCase;
  let userRepository: jest.Mocked<UserRepository>;
  let tokenRepository: jest.Mocked<TokenRepository>;
  let sessionRepository: jest.Mocked<AuthSessionRepository>;
  let passwordHashingService: jest.Mocked<PasswordHashingService>;
  let tokenService: jest.Mocked<TokenService>;
  let presenter: jest.Mocked<AuthPresenter>;

  const mockUser = User.create({
    id: 'user-123',
    email: 'test@example.com',
    password: 'hashed-password',
    name: 'Test User',
    provider: AuthProvider.LOCAL,
  });

  const mockAccessToken = Token.createAccessToken({
    id: 'access-token-123',
    userId: 'user-123',
    value: 'access-token-value',
    expirationMinutes: 15,
  });

  const mockRefreshToken = Token.createRefreshToken({
    id: 'refresh-token-123',
    userId: 'user-123',
    value: 'refresh-token-value',
    expirationDays: 7,
  });

  const mockSession = AuthSession.create({
    id: 'session-123',
    userId: 'user-123',
    sessionToken: 'access-token-value',
    clientInfo: {
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
    },
    expirationHours: 24,
  });

  beforeEach(() => {
    userRepository = {
      findByEmail: jest.fn(),
      findById: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      findAll: jest.fn(),
    };

    tokenRepository = {
      findByUserId: jest.fn(),
      findByValue: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      deleteByUserId: jest.fn(),
      deleteExpiredTokens: jest.fn(),
    };

    sessionRepository = {
      findByUserId: jest.fn(),
      findBySessionToken: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      deleteByUserId: jest.fn(),
      deleteExpiredSessions: jest.fn(),
    };

    passwordHashingService = {
      hash: jest.fn(),
      compare: jest.fn(),
    };

    tokenService = {
      generateAccessToken: jest.fn(),
      generateRefreshToken: jest.fn(),
      verifyToken: jest.fn(),
      extractPayload: jest.fn(),
    };

    presenter = {
      presentLoginSuccess: jest.fn(),
      presentRegistrationSuccess: jest.fn(),
      presentTokenRefreshSuccess: jest.fn(),
      presentLogoutSuccess: jest.fn(),
      presentSocialLoginSuccess: jest.fn(),
      presentAuthenticationError: jest.fn(),
      presentValidationError: jest.fn(),
      presentDuplicateEmail: jest.fn(),
      presentRegistrationValidationError: jest.fn(),
      presentInvalidCredentials: jest.fn(),
      presentAccountLocked: jest.fn(),
      presentTokenExpired: jest.fn(),
      presentInvalidToken: jest.fn(),
      presentServiceUnavailable: jest.fn(),
    };

    useCase = new LoginUserUseCase(
      userRepository,
      tokenRepository,
      sessionRepository,
      passwordHashingService,
      tokenService,
      presenter
    );
  });

  describe('execute', () => {
    const validLoginRequest: LoginUserRequest = {
      email: 'test@example.com',
      password: 'ValidPassword123!',
      clientInfo: {
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        deviceId: 'device-123',
      },
    };

    it('should successfully login user with valid credentials', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateAccessToken.mockResolvedValue('access-token-value');
      tokenService.generateRefreshToken.mockResolvedValue('refresh-token-value');
      tokenRepository.save.mockResolvedValue(mockAccessToken);
      sessionRepository.save.mockResolvedValue(mockSession);

      // Act
      await useCase.execute(validLoginRequest);

      // Assert
      expect(userRepository.findByEmail).toHaveBeenCalledWith('test@example.com');
      expect(passwordHashingService.compare).toHaveBeenCalledWith('ValidPassword123!', 'hashed-password');
      expect(tokenService.generateAccessToken).toHaveBeenCalledWith('user-123', 'test@example.com', '15m');
      expect(tokenService.generateRefreshToken).toHaveBeenCalledWith('user-123', 'test@example.com', '7d');
      expect(tokenRepository.save).toHaveBeenCalledTimes(2);
      expect(sessionRepository.save).toHaveBeenCalled();
      expect(presenter.presentLoginSuccess).toHaveBeenCalled();
    });

    it('should present invalid credentials when user not found', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(null);

      // Act
      await useCase.execute(validLoginRequest);

      // Assert
      expect(userRepository.findByEmail).toHaveBeenCalledWith('test@example.com');
      expect(passwordHashingService.compare).not.toHaveBeenCalled();
      expect(presenter.presentInvalidCredentials).toHaveBeenCalled();
    });

    it('should present invalid credentials when password does not match', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(false);

      // Act
      await useCase.execute(validLoginRequest);

      // Assert
      expect(userRepository.findByEmail).toHaveBeenCalledWith('test@example.com');
      expect(passwordHashingService.compare).toHaveBeenCalledWith('ValidPassword123!', 'hashed-password');
      expect(presenter.presentInvalidCredentials).toHaveBeenCalled();
    });

    it('should validate email format', async () => {
      // Arrange
      const invalidEmailRequest = {
        ...validLoginRequest,
        email: 'invalid-email',
      };

      // Act
      await useCase.execute(invalidEmailRequest);

      // Assert
      expect(presenter.presentValidationError).toHaveBeenCalledWith(
        expect.objectContaining({
          email: expect.arrayContaining(['Invalid email format'])
        })
      );
    });

    it('should validate password presence', async () => {
      // Arrange
      const noPasswordRequest = {
        ...validLoginRequest,
        password: '',
      };

      // Act
      await useCase.execute(noPasswordRequest);

      // Assert
      expect(presenter.presentValidationError).toHaveBeenCalledWith(
        expect.objectContaining({
          password: expect.arrayContaining(['Password is required'])
        })
      );
    });

    it('should handle multiple validation errors', async () => {
      // Arrange
      const invalidRequest = {
        email: 'invalid-email',
        password: '',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'test-agent',
        },
      };

      // Act
      await useCase.execute(invalidRequest);

      // Assert
      expect(presenter.presentValidationError).toHaveBeenCalledWith(
        expect.objectContaining({
          email: expect.arrayContaining(['Invalid email format']),
          password: expect.arrayContaining(['Password is required'])
        })
      );
    });

    it('should handle database errors gracefully', async () => {
      // Arrange
      userRepository.findByEmail.mockRejectedValue(new Error('Database connection failed'));

      // Act
      await useCase.execute(validLoginRequest);

      // Assert
      expect(presenter.presentAuthenticationError).toHaveBeenCalledWith(
        'Login failed due to an internal error',
        'LOGIN_ERROR'
      );
    });

    it('should handle token generation errors', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateAccessToken.mockRejectedValue(new Error('Token generation failed'));

      // Act
      await useCase.execute(validLoginRequest);

      // Assert
      expect(presenter.presentAuthenticationError).toHaveBeenCalledWith(
        'Login failed due to an internal error',
        'LOGIN_ERROR'
      );
    });

    it('should handle token save errors', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateAccessToken.mockResolvedValue('access-token-value');
      tokenService.generateRefreshToken.mockResolvedValue('refresh-token-value');
      tokenRepository.save.mockRejectedValue(new Error('Token save failed'));

      // Act
      await useCase.execute(validLoginRequest);

      // Assert
      expect(presenter.presentAuthenticationError).toHaveBeenCalledWith(
        'Login failed due to an internal error',
        'LOGIN_ERROR'
      );
    });

    it('should handle session creation errors', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateAccessToken.mockResolvedValue('access-token-value');
      tokenService.generateRefreshToken.mockResolvedValue('refresh-token-value');
      tokenRepository.save.mockResolvedValue(mockAccessToken);
      sessionRepository.save.mockRejectedValue(new Error('Session save failed'));

      // Act
      await useCase.execute(validLoginRequest);

      // Assert
      expect(presenter.presentAuthenticationError).toHaveBeenCalledWith(
        'Login failed due to an internal error',
        'LOGIN_ERROR'
      );
    });

    it('should clean up tokens when session creation fails', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateAccessToken.mockResolvedValue('access-token-value');
      tokenService.generateRefreshToken.mockResolvedValue('refresh-token-value');
      tokenRepository.save.mockResolvedValue(mockAccessToken);
      sessionRepository.save.mockRejectedValue(new Error('Session save failed'));
      tokenRepository.deleteByUserId = jest.fn().mockResolvedValue(undefined);

      // Act
      await useCase.execute(validLoginRequest);

      // Assert
      expect(tokenRepository.deleteByUserId).toHaveBeenCalledWith('user-123');
      expect(presenter.presentAuthenticationError).toHaveBeenCalled();
    });

    it('should include client information in session', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateAccessToken.mockResolvedValue('access-token-value');
      tokenService.generateRefreshToken.mockResolvedValue('refresh-token-value');
      tokenRepository.save.mockResolvedValue(mockAccessToken);
      sessionRepository.save.mockResolvedValue(mockSession);

      const requestWithClientInfo = {
        ...validLoginRequest,
        clientInfo: {
          ipAddress: '192.168.1.100',
          userAgent: 'Mozilla/5.0',
          deviceId: 'device-456',
        },
      };

      // Act
      await useCase.execute(requestWithClientInfo);

      // Assert
      expect(sessionRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          clientInfo: {
            ipAddress: '192.168.1.100',
            userAgent: 'Mozilla/5.0',
          },
        })
      );
    });

    it('should present successful login with correct response format', async () => {
      // Arrange
      userRepository.findByEmail.mockResolvedValue(mockUser);
      passwordHashingService.compare.mockResolvedValue(true);
      tokenService.generateAccessToken.mockResolvedValue('access-token-value');
      tokenService.generateRefreshToken.mockResolvedValue('refresh-token-value');
      tokenRepository.save.mockResolvedValue(mockAccessToken);
      sessionRepository.save.mockResolvedValue(mockSession);

      // Act
      await useCase.execute(validLoginRequest);

      // Assert
      expect(presenter.presentLoginSuccess).toHaveBeenCalledWith(
        expect.objectContaining({
          user: expect.objectContaining({
            id: 'user-123',
            email: 'test@example.com',
            name: 'Test User',
            provider: AuthProvider.LOCAL,
          }),
          tokens: expect.objectContaining({
            accessToken: 'access-token-value',
            refreshToken: 'refresh-token-value',
            expiresIn: 15 * 60, // 15 minutes in seconds
          }),
        })
      );
    });
  });

  describe('input validation', () => {
    it('should validate email format correctly', async () => {
      const invalidEmails = [
        'invalid-email',
        '@example.com',
        'test@',
        'test.example.com',
        '',
      ];

      for (const email of invalidEmails) {
        const request = {
          email,
          password: 'ValidPassword123!',
          clientInfo: {
            ipAddress: '127.0.0.1',
            userAgent: 'test-agent',
          },
        };

        await useCase.execute(request);

        expect(presenter.presentValidationError).toHaveBeenCalledWith(
          expect.objectContaining({
            email: expect.arrayContaining(['Invalid email format'])
          })
        );

        jest.clearAllMocks();
      }
    });

    it('should accept valid email formats', async () => {
      const validEmails = [
        'test@example.com',
        'user.name@example.com',
        'user+tag@example.co.uk',
        'test123@test-domain.com',
      ];

      userRepository.findByEmail.mockResolvedValue(null);

      for (const email of validEmails) {
        const request = {
          email,
          password: 'ValidPassword123!',
          clientInfo: {
            ipAddress: '127.0.0.1',
            userAgent: 'test-agent',
          },
        };

        await useCase.execute(request);

        expect(userRepository.findByEmail).toHaveBeenCalledWith(email);
        expect(presenter.presentValidationError).not.toHaveBeenCalled();

        jest.clearAllMocks();
      }
    });
  });
});