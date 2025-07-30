import { Test, TestingModule } from '@nestjs/testing';
import { RegisterUserUseCase, UserAlreadyExistsError, InvalidPasswordError } from '../register-user.use-case';
import { UserRepository } from '../../ports/user.repository';
import { PasswordHashingService } from '../../ports/password-hashing.service';
import { User } from '../../entities/user.entity';
import { RegisterUserRequest } from '../../models/auth.models';
import { AuthProvider } from '@auth/shared/types/auth.types';

describe('RegisterUserUseCase', () => {
  let useCase: RegisterUserUseCase;
  let userRepository: jest.Mocked<UserRepository>;
  let passwordHashingService: jest.Mocked<PasswordHashingService>;

  const validRequest: RegisterUserRequest = {
    email: 'test@example.com',
    password: 'Password123!',
    name: 'Test User',
    profilePicture: 'https://example.com/avatar.jpg',
  };

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

    const mockPasswordHashingService = {
      hash: jest.fn(),
      compare: jest.fn(),
      isValidPasswordFormat: jest.fn(),
      generateSalt: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RegisterUserUseCase,
        { provide: 'UserRepository', useValue: mockUserRepository },
        { provide: 'PasswordHashingService', useValue: mockPasswordHashingService },
      ],
    }).compile();

    useCase = module.get<RegisterUserUseCase>(RegisterUserUseCase);
    userRepository = module.get('UserRepository');
    passwordHashingService = module.get('PasswordHashingService');
  });

  describe('execute', () => {
    it('should successfully register a new user', async () => {
      // Arrange
      const hashedPassword = 'hashed_password_123';
      const mockUser = new User(
        'user_123',
        validRequest.email,
        hashedPassword,
        validRequest.name,
        validRequest.profilePicture,
        AuthProvider.LOCAL
      );

      userRepository.existsByEmail.mockResolvedValue(false);
      passwordHashingService.isValidPasswordFormat.mockReturnValue(true);
      passwordHashingService.hash.mockResolvedValue(hashedPassword);
      userRepository.save.mockResolvedValue(mockUser);

      // Act
      const result = await useCase.execute(validRequest);

      // Assert
      expect(userRepository.existsByEmail).toHaveBeenCalledWith(validRequest.email);
      expect(passwordHashingService.isValidPasswordFormat).toHaveBeenCalledWith(validRequest.password);
      expect(passwordHashingService.hash).toHaveBeenCalledWith(validRequest.password);
      expect(userRepository.save).toHaveBeenCalledWith(expect.any(User));

      expect(result).toEqual({
        userId: mockUser.id,
        email: mockUser.email,
        name: mockUser.name,
        profilePicture: mockUser.profilePicture,
        isActive: mockUser.isAccountActive(),
        createdAt: mockUser.getCreatedAt(),
      });
    });

    it('should register user without profile picture', async () => {
      // Arrange
      const requestWithoutPicture = { ...validRequest, profilePicture: undefined };
      const hashedPassword = 'hashed_password_123';
      const mockUser = new User(
        'user_123',
        requestWithoutPicture.email,
        hashedPassword,
        requestWithoutPicture.name,
        undefined,
        AuthProvider.LOCAL
      );

      userRepository.existsByEmail.mockResolvedValue(false);
      passwordHashingService.isValidPasswordFormat.mockReturnValue(true);
      passwordHashingService.hash.mockResolvedValue(hashedPassword);
      userRepository.save.mockResolvedValue(mockUser);

      // Act
      const result = await useCase.execute(requestWithoutPicture);

      // Assert
      expect(result.profilePicture).toBeUndefined();
    });

    it('should throw UserAlreadyExistsError when user already exists', async () => {
      // Arrange
      userRepository.existsByEmail.mockResolvedValue(true);

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow(UserAlreadyExistsError);
      expect(userRepository.existsByEmail).toHaveBeenCalledWith(validRequest.email);
      expect(passwordHashingService.hash).not.toHaveBeenCalled();
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('should throw InvalidPasswordError when password format is invalid', async () => {
      // Arrange
      userRepository.existsByEmail.mockResolvedValue(false);
      passwordHashingService.isValidPasswordFormat.mockReturnValue(false);

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow(InvalidPasswordError);
      expect(passwordHashingService.isValidPasswordFormat).toHaveBeenCalledWith(validRequest.password);
      expect(passwordHashingService.hash).not.toHaveBeenCalled();
      expect(userRepository.save).not.toHaveBeenCalled();
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

    it('should throw error when name is empty', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, name: '' };

      // Act & Assert
      await expect(useCase.execute(invalidRequest)).rejects.toThrow('Name is required');
    });

    it('should throw error when email format is invalid', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, email: 'invalid-email' };

      // Act & Assert
      await expect(useCase.execute(invalidRequest)).rejects.toThrow('Invalid email format');
    });

    it('should throw error when name is too short', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, name: 'A' };

      // Act & Assert
      await expect(useCase.execute(invalidRequest)).rejects.toThrow('Name must be between 2 and 50 characters');
    });

    it('should throw error when name is too long', async () => {
      // Arrange
      const invalidRequest = { ...validRequest, name: 'A'.repeat(51) };

      // Act & Assert
      await expect(useCase.execute(invalidRequest)).rejects.toThrow('Name must be between 2 and 50 characters');
    });

    it('should handle repository save failure', async () => {
      // Arrange
      userRepository.existsByEmail.mockResolvedValue(false);
      passwordHashingService.isValidPasswordFormat.mockReturnValue(true);
      passwordHashingService.hash.mockResolvedValue('hashed_password');
      userRepository.save.mockRejectedValue(new Error('Database error'));

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('Database error');
    });

    it('should handle password hashing failure', async () => {
      // Arrange
      userRepository.existsByEmail.mockResolvedValue(false);
      passwordHashingService.isValidPasswordFormat.mockReturnValue(true);
      passwordHashingService.hash.mockRejectedValue(new Error('Hashing error'));

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('Hashing error');
    });
  });
});