import { RegisterUserUseCase } from './register-user.use-case';
import { UserRepository } from '../ports/repositories/user.repository';
import { TokenRepository } from '../ports/repositories/token.repository';
import { AuthSessionRepository } from '../ports/repositories/auth-session.repository';
import { PasswordHashingService } from '../ports/services/password-hashing.service';
import { TokenService } from '../ports/services/token.service';
import { AuthPresenter } from '../ports/presenters/auth.presenter';
import { RegisterUserRequest, AuthProvider } from '@auth/shared';

describe('RegisterUserUseCase - Simple Test', () => {
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
    // Create minimal mocked dependencies
    userRepository = {
      findByEmail: jest.fn(),
      save: jest.fn(),
    } as any;

    tokenRepository = {
      save: jest.fn(),
    } as any;

    sessionRepository = {
      save: jest.fn(),
    } as any;

    passwordHashingService = {
      hash: jest.fn(),
    } as any;

    tokenService = {
      generateAccessToken: jest.fn(),
      generateRefreshToken: jest.fn(),
    } as any;

    presenter = {
      presentRegistrationSuccess: jest.fn(),
      presentDuplicateEmail: jest.fn(),
      presentRegistrationValidationError: jest.fn(),
      presentAuthenticationError: jest.fn(),
    } as any;

    useCase = new RegisterUserUseCase(
      userRepository,
      tokenRepository,
      sessionRepository,
      passwordHashingService,
      tokenService,
      presenter
    );
  });

  it('should successfully register a new user', async () => {
    // Arrange
    const hashedPassword = 'hashedPassword123';
    const accessTokenValue = 'access.token.jwt';
    const refreshTokenValue = 'refresh.token.jwt';

    userRepository.findByEmail.mockResolvedValue(null);
    passwordHashingService.hash.mockResolvedValue(hashedPassword);
    userRepository.save.mockImplementation(async (user) => user);
    tokenService.generateAccessToken.mockResolvedValue(accessTokenValue);
    tokenService.generateRefreshToken.mockResolvedValue(refreshTokenValue);
    tokenRepository.save.mockResolvedValue({} as any);
    sessionRepository.save.mockResolvedValue({} as any);

    // Act
    await useCase.execute(validRequest);

    // Assert
    expect(userRepository.findByEmail).toHaveBeenCalledWith(validRequest.email);
    expect(passwordHashingService.hash).toHaveBeenCalledWith(validRequest.password);
    expect(userRepository.save).toHaveBeenCalled();
    expect(tokenService.generateAccessToken).toHaveBeenCalled();
    expect(tokenService.generateRefreshToken).toHaveBeenCalled();
    expect(tokenRepository.save).toHaveBeenCalledTimes(2); // access + refresh tokens
    expect(sessionRepository.save).toHaveBeenCalled();
    expect(presenter.presentRegistrationSuccess).toHaveBeenCalled();
  });

  it('should present duplicate email error when user already exists', async () => {
    // Arrange
    const existingUser = { id: 'existing', email: validRequest.email } as any;
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
    const invalidRequest = { ...validRequest, email: 'invalid-email' };

    // Act
    await useCase.execute(invalidRequest);

    // Assert
    expect(presenter.presentRegistrationValidationError).toHaveBeenCalledWith({
      email: ['Invalid email format'],
    });
    expect(userRepository.findByEmail).not.toHaveBeenCalled();
  });

  it('should validate password requirements', async () => {
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
});