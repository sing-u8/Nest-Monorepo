import { Test, TestingModule } from '@nestjs/testing';
import { UpdateProfileUseCase, UserNotFoundError, UserNotActiveError, InvalidProfileDataError, NoChangesError } from '../update-profile.use-case';
import { UserRepository } from '../../ports/user.repository';
import { User } from '../../entities/user.entity';
import { AuthProvider } from '@auth/shared/types/auth.types';

describe('UpdateProfileUseCase', () => {
  let useCase: UpdateProfileUseCase;
  let userRepository: jest.Mocked<UserRepository>;

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

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UpdateProfileUseCase,
        { provide: 'UserRepository', useValue: mockUserRepository },
      ],
    }).compile();

    useCase = module.get<UpdateProfileUseCase>(UpdateProfileUseCase);
    userRepository = module.get('UserRepository');
  });

  describe('execute', () => {
    const mockUser = new User(
      'user_123456789_abc123def',
      'test@example.com',
      'hashedPassword',
      'Original Name',
      'https://example.com/original.jpg',
      AuthProvider.LOCAL,
    );

    it('should successfully update user profile with name only', async () => {
      // Arrange
      const request = {
        userId: 'user_123456789_abc123def',
        name: 'Updated Name',
      };

      userRepository.findById.mockResolvedValue(mockUser);
      userRepository.save.mockImplementation(user => Promise.resolve(user));

      // Act
      const result = await useCase.execute(request);

      // Assert
      expect(result).toEqual({
        userId: 'user_123456789_abc123def',
        email: 'test@example.com',
        name: 'Updated Name',
        profilePicture: 'https://example.com/original.jpg',
        updatedAt: expect.any(Date),
      });

      expect(userRepository.findById).toHaveBeenCalledWith('user_123456789_abc123def');
      expect(userRepository.save).toHaveBeenCalledWith(mockUser);
    });

    it('should successfully update user profile with profile picture only', async () => {
      // Arrange
      const request = {
        userId: 'user_123456789_abc123def',
        profilePicture: 'https://example.com/new-avatar.png',
      };

      userRepository.findById.mockResolvedValue(mockUser);
      userRepository.save.mockImplementation(user => Promise.resolve(user));

      // Act
      const result = await useCase.execute(request);

      // Assert
      expect(result).toEqual({
        userId: 'user_123456789_abc123def',
        email: 'test@example.com',
        name: 'Original Name',
        profilePicture: 'https://example.com/new-avatar.png',
        updatedAt: expect.any(Date),
      });
    });

    it('should successfully update both name and profile picture', async () => {
      // Arrange
      const request = {
        userId: 'user_123456789_abc123def',
        name: 'New Name',
        profilePicture: 'https://example.com/new-avatar.webp',
      };

      userRepository.findById.mockResolvedValue(mockUser);
      userRepository.save.mockImplementation(user => Promise.resolve(user));

      // Act
      const result = await useCase.execute(request);

      // Assert
      expect(result.name).toBe('New Name');
      expect(result.profilePicture).toBe('https://example.com/new-avatar.webp');
    });

    it('should successfully remove profile picture with empty string', async () => {
      // Arrange
      const request = {
        userId: 'user_123456789_abc123def',
        profilePicture: '',
      };

      userRepository.findById.mockResolvedValue(mockUser);
      userRepository.save.mockImplementation(user => Promise.resolve(user));

      // Act
      const result = await useCase.execute(request);

      // Assert
      expect(result.profilePicture).toBe('');
    });

    it('should throw UserNotFoundError when user does not exist', async () => {
      // Arrange
      const request = {
        userId: 'user_123456789_nonexist',
        name: 'New Name',
      };

      userRepository.findById.mockResolvedValue(null);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(UserNotFoundError);
      expect(userRepository.findById).toHaveBeenCalledWith('user_123456789_nonexist');
    });

    it('should throw UserNotActiveError when user is deactivated', async () => {
      // Arrange
      const deactivatedUser = new User(
        'user_123456789_abc123def',
        'test@example.com',
        'hashedPassword',
        'Test User',
        undefined,
        AuthProvider.LOCAL,
      );
      deactivatedUser.deactivate();

      const request = {
        userId: 'user_123456789_abc123def',
        name: 'New Name',
      };

      userRepository.findById.mockResolvedValue(deactivatedUser);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(UserNotActiveError);
    });

    it('should throw NoChangesError when no fields are provided', async () => {
      // Arrange
      const request = {
        userId: 'user_123456789_abc123def',
      };

      userRepository.findById.mockResolvedValue(mockUser);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(NoChangesError);
    });

    it('should throw NoChangesError when values are identical to current values', async () => {
      // Arrange
      const request = {
        userId: 'user_123456789_abc123def',
        name: 'Original Name', // Same as current
        profilePicture: 'https://example.com/original.jpg', // Same as current
      };

      userRepository.findById.mockResolvedValue(mockUser);

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow(NoChangesError);
    });
  });

  describe('validation', () => {
    it('should throw error when userId is missing', async () => {
      // Arrange
      const request = {
        name: 'New Name',
      };

      // Act & Assert
      await expect(useCase.execute(request as any)).rejects.toThrow('User ID is required');
    });

    it('should throw error when userId is empty', async () => {
      // Arrange
      const request = {
        userId: '',
        name: 'New Name',
      };

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow('User ID is required');
    });

    it('should throw error when userId format is invalid', async () => {
      // Arrange
      const request = {
        userId: 'invalid-user-id',
        name: 'New Name',
      };

      // Act & Assert
      await expect(useCase.execute(request)).rejects.toThrow('Invalid user ID format');
    });

    describe('name validation', () => {
      const mockUser = new User(
        'user_123456789_abc123def',
        'test@example.com',
        'hashedPassword',
        'Original Name',
        undefined,
        AuthProvider.LOCAL,
      );

      beforeEach(() => {
        userRepository.findById.mockResolvedValue(mockUser);
      });

      it('should throw InvalidProfileDataError when name is null', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          name: null,
        };

        // Act & Assert
        await expect(useCase.execute(request as any)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should throw InvalidProfileDataError when name is not a string', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          name: 123,
        };

        // Act & Assert
        await expect(useCase.execute(request as any)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should throw InvalidProfileDataError when name is empty', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          name: '',
        };

        // Act & Assert
        await expect(useCase.execute(request)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should throw InvalidProfileDataError when name is too short', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          name: 'A', // Only 1 character
        };

        // Act & Assert
        await expect(useCase.execute(request)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should throw InvalidProfileDataError when name is too long', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          name: 'A'.repeat(101), // 101 characters
        };

        // Act & Assert
        await expect(useCase.execute(request)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should throw InvalidProfileDataError when name contains invalid characters', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          name: 'John123', // Contains numbers
        };

        // Act & Assert
        await expect(useCase.execute(request)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should throw InvalidProfileDataError when name contains consecutive spaces', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          name: 'John  Doe', // Double space
        };

        // Act & Assert
        await expect(useCase.execute(request)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should throw InvalidProfileDataError when name has leading/trailing whitespace', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          name: ' John Doe ', // Leading and trailing spaces
        };

        // Act & Assert
        await expect(useCase.execute(request)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should accept valid names with letters, spaces, hyphens, and apostrophes', async () => {
        // Arrange
        const validNames = [
          'John Doe',
          'Mary-Jane Watson',
          "O'Connor",
          'Jean-Claude Van Damme',
          "Mary O'Sullivan-Johnson",
        ];

        userRepository.save.mockImplementation(user => Promise.resolve(user));

        // Act & Assert
        for (const validName of validNames) {
          const request = {
            userId: 'user_123456789_abc123def',
            name: validName,
          };

          await expect(useCase.execute(request)).resolves.toEqual({
            userId: 'user_123456789_abc123def',
            email: 'test@example.com',
            name: validName,
            profilePicture: undefined,
            updatedAt: expect.any(Date),
          });
        }
      });
    });

    describe('profile picture validation', () => {
      const mockUser = new User(
        'user_123456789_abc123def',
        'test@example.com',
        'hashedPassword',
        'Test User',
        undefined,
        AuthProvider.LOCAL,
      );

      beforeEach(() => {
        userRepository.findById.mockResolvedValue(mockUser);
        userRepository.save.mockImplementation(user => Promise.resolve(user));
      });

      it('should accept null profile picture', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          profilePicture: null,
        };

        // Act
        const result = await useCase.execute(request as any);

        // Assert
        expect(result.profilePicture).toBeNull();
      });

      it('should accept empty string profile picture', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          profilePicture: '',
        };

        // Act
        const result = await useCase.execute(request);

        // Assert
        expect(result.profilePicture).toBe('');
      });

      it('should throw InvalidProfileDataError when profile picture is not a string', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          profilePicture: 123,
        };

        // Act & Assert
        await expect(useCase.execute(request as any)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should throw InvalidProfileDataError when profile picture URL is not HTTPS', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          profilePicture: 'http://example.com/avatar.jpg', // HTTP instead of HTTPS
        };

        // Act & Assert
        await expect(useCase.execute(request)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should throw InvalidProfileDataError when profile picture has invalid file extension', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          profilePicture: 'https://example.com/avatar.txt', // Invalid extension
        };

        // Act & Assert
        await expect(useCase.execute(request)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should throw InvalidProfileDataError when profile picture URL is too long', async () => {
        // Arrange
        const longUrl = 'https://example.com/' + 'a'.repeat(2040) + '.jpg'; // > 2048 chars
        const request = {
          userId: 'user_123456789_abc123def',
          profilePicture: longUrl,
        };

        // Act & Assert
        await expect(useCase.execute(request)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should throw InvalidProfileDataError when profile picture URL is malformed', async () => {
        // Arrange
        const request = {
          userId: 'user_123456789_abc123def',
          profilePicture: 'not-a-valid-url',
        };

        // Act & Assert
        await expect(useCase.execute(request)).rejects.toThrow(InvalidProfileDataError);
      });

      it('should accept valid image URLs', async () => {
        // Arrange
        const validUrls = [
          'https://example.com/avatar.jpg',
          'https://example.com/avatar.jpeg',
          'https://example.com/avatar.png',
          'https://example.com/avatar.gif',
          'https://example.com/avatar.webp',
        ];

        // Act & Assert
        for (const validUrl of validUrls) {
          const request = {
            userId: 'user_123456789_abc123def',
            profilePicture: validUrl,
          };

          await expect(useCase.execute(request)).resolves.toEqual({
            userId: 'user_123456789_abc123def',
            email: 'test@example.com',
            name: 'Test User',
            profilePicture: validUrl,
            updatedAt: expect.any(Date),
          });
        }
      });
    });
  });
});