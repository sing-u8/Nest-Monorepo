import { UpdateProfileUseCase } from './update-profile.use-case';
import { User } from '../entities/user.entity';
import { UserRepository } from '../ports/repositories/user.repository';
import { ProfilePresenter } from '../ports/presenters/profile.presenter';
import { 
  UpdateProfileRequest, 
  UploadProfilePictureRequest, 
  AuthProvider 
} from '@auth/shared';

describe('UpdateProfileUseCase', () => {
  let useCase: UpdateProfileUseCase;
  let userRepository: jest.Mocked<UserRepository>;
  let presenter: jest.Mocked<ProfilePresenter>;

  const validUserId = 'user123';
  const validUpdateRequest: UpdateProfileRequest = {
    name: 'Updated User Name',
    profilePicture: 'https://example.com/new-profile.jpg',
  };

  const validUploadRequest: UploadProfilePictureRequest = {
    file: {
      buffer: Buffer.from('fake-image-data'),
      mimetype: 'image/jpeg',
      originalname: 'profile.jpg',
      size: 1024000, // 1MB
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

    presenter = {
      presentProfileUpdateSuccess: jest.fn(),
      presentProfileUpdateFailure: jest.fn(),
      presentProfileUpdateValidationError: jest.fn(),
      presentProfilePictureUploadSuccess: jest.fn(),
      presentProfilePictureUploadFailure: jest.fn(),
      presentUserNotFound: jest.fn(),
      presentAccountLocked: jest.fn(),
      presentUnauthorizedAccess: jest.fn(),
      presentServerError: jest.fn(),
    };

    useCase = new UpdateProfileUseCase(userRepository, presenter);
  });

  describe('execute - Profile Update', () => {
    it('should successfully update user profile', async () => {
      // Arrange
      const existingUser = User.create({
        id: validUserId,
        email: 'user@example.com',
        password: 'HashedPassword123!',
        name: 'Original Name',
        profilePicture: 'https://example.com/old-profile.jpg',
        provider: AuthProvider.LOCAL,
      });

      const updatedUser = User.create({
        id: validUserId,
        email: 'user@example.com',
        password: 'HashedPassword123!',
        name: validUpdateRequest.name!,
        profilePicture: validUpdateRequest.profilePicture!,
        provider: AuthProvider.LOCAL,
      });

      userRepository.findById.mockResolvedValue(existingUser);
      userRepository.save.mockResolvedValue(updatedUser);

      // Act
      await useCase.execute(validUserId, validUpdateRequest);

      // Assert
      expect(userRepository.findById).toHaveBeenCalledWith(validUserId);
      expect(userRepository.save).toHaveBeenCalled();
      expect(presenter.presentProfileUpdateSuccess).toHaveBeenCalledWith({
        user: {
          id: validUserId,
          email: 'user@example.com',
          name: validUpdateRequest.name,
          profilePicture: validUpdateRequest.profilePicture,
          updatedAt: expect.any(Date),
        },
      });
    });

    it('should successfully update only name', async () => {
      // Arrange
      const nameOnlyRequest: UpdateProfileRequest = {
        name: 'New Name Only',
      };

      const existingUser = User.create({
        id: validUserId,
        email: 'user@example.com',
        password: 'HashedPassword123!',
        name: 'Original Name',
        profilePicture: 'https://example.com/profile.jpg',
        provider: AuthProvider.LOCAL,
      });

      const updatedUser = User.create({
        id: validUserId,
        email: 'user@example.com',
        password: 'HashedPassword123!',
        name: nameOnlyRequest.name!,
        profilePicture: 'https://example.com/profile.jpg',
        provider: AuthProvider.LOCAL,
      });

      userRepository.findById.mockResolvedValue(existingUser);
      userRepository.save.mockResolvedValue(updatedUser);

      // Act
      await useCase.execute(validUserId, nameOnlyRequest);

      // Assert
      expect(presenter.presentProfileUpdateSuccess).toHaveBeenCalledWith({
        user: {
          id: validUserId,
          email: 'user@example.com',
          name: nameOnlyRequest.name,
          profilePicture: 'https://example.com/profile.jpg',
          updatedAt: expect.any(Date),
        },
      });
    });

    it('should successfully update only profile picture', async () => {
      // Arrange
      const pictureOnlyRequest: UpdateProfileRequest = {
        profilePicture: 'https://example.com/new-picture.jpg',
      };

      const existingUser = User.create({
        id: validUserId,
        email: 'user@example.com',
        password: 'HashedPassword123!',
        name: 'User Name',
        profilePicture: 'https://example.com/old-picture.jpg',
        provider: AuthProvider.LOCAL,
      });

      const updatedUser = User.create({
        id: validUserId,
        email: 'user@example.com',
        password: 'HashedPassword123!',
        name: 'User Name',
        profilePicture: pictureOnlyRequest.profilePicture!,
        provider: AuthProvider.LOCAL,
      });

      userRepository.findById.mockResolvedValue(existingUser);
      userRepository.save.mockResolvedValue(updatedUser);

      // Act
      await useCase.execute(validUserId, pictureOnlyRequest);

      // Assert
      expect(presenter.presentProfileUpdateSuccess).toHaveBeenCalledWith(
        expect.objectContaining({
          user: expect.objectContaining({
            profilePicture: pictureOnlyRequest.profilePicture,
          }),
        })
      );
    });

    it('should reject update when user not found', async () => {
      // Arrange
      userRepository.findById.mockResolvedValue(null);

      // Act
      await useCase.execute(validUserId, validUpdateRequest);

      // Assert
      expect(presenter.presentUserNotFound).toHaveBeenCalled();
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('should reject update for inactive user', async () => {
      // Arrange
      const inactiveUser = User.create({
        id: validUserId,
        email: 'user@example.com',
        password: 'HashedPassword123!',
        name: 'User Name',
        provider: AuthProvider.LOCAL,
      });
      inactiveUser.deactivate();

      userRepository.findById.mockResolvedValue(inactiveUser);

      // Act
      await useCase.execute(validUserId, validUpdateRequest);

      // Assert
      expect(presenter.presentAccountLocked).toHaveBeenCalledWith(
        'Account is not active and cannot be updated'
      );
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('should reject update when no changes detected', async () => {
      // Arrange
      const noChangeRequest: UpdateProfileRequest = {
        name: 'Existing Name',
        profilePicture: 'https://example.com/existing-picture.jpg',
      };

      const existingUser = User.create({
        id: validUserId,
        email: 'user@example.com',
        password: 'HashedPassword123!',
        name: 'Existing Name',
        profilePicture: 'https://example.com/existing-picture.jpg',
        provider: AuthProvider.LOCAL,
      });

      userRepository.findById.mockResolvedValue(existingUser);

      // Act
      await useCase.execute(validUserId, noChangeRequest);

      // Assert
      expect(presenter.presentProfileUpdateFailure).toHaveBeenCalledWith(
        'No changes detected in profile data'
      );
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    describe('Validation', () => {
      it('should reject empty user ID', async () => {
        // Act
        await useCase.execute('', validUpdateRequest);

        // Assert
        expect(presenter.presentProfileUpdateValidationError).toHaveBeenCalledWith(
          'User ID is required'
        );
        expect(userRepository.findById).not.toHaveBeenCalled();
      });

      it('should reject null request', async () => {
        // Act
        await useCase.execute(validUserId, null as any);

        // Assert
        expect(presenter.presentProfileUpdateValidationError).toHaveBeenCalledWith(
          'Profile data is required'
        );
      });

      it('should reject empty request', async () => {
        // Act
        await useCase.execute(validUserId, {});

        // Assert
        expect(presenter.presentProfileUpdateValidationError).toHaveBeenCalledWith(
          'At least one profile field must be provided for update'
        );
      });

      it('should reject invalid name - too short', async () => {
        // Arrange
        const invalidRequest: UpdateProfileRequest = {
          name: 'A',
        };

        const existingUser = User.create({
          id: validUserId,
          email: 'user@example.com',
          password: 'HashedPassword123!',
          name: 'Original Name',
          provider: AuthProvider.LOCAL,
        });

        userRepository.findById.mockResolvedValue(existingUser);

        // Act
        await useCase.execute(validUserId, invalidRequest);

        // Assert
        expect(presenter.presentProfileUpdateValidationError).toHaveBeenCalledWith(
          'Name must be at least 2 characters long'
        );
      });

      it('should reject invalid name - too long', async () => {
        // Arrange
        const invalidRequest: UpdateProfileRequest = {
          name: 'A'.repeat(101), // 101 characters
        };

        const existingUser = User.create({
          id: validUserId,
          email: 'user@example.com',
          password: 'HashedPassword123!',
          name: 'Original Name',
          provider: AuthProvider.LOCAL,
        });

        userRepository.findById.mockResolvedValue(existingUser);

        // Act
        await useCase.execute(validUserId, invalidRequest);

        // Assert
        expect(presenter.presentProfileUpdateValidationError).toHaveBeenCalledWith(
          'Name cannot exceed 100 characters'
        );
      });

      it('should reject invalid name - invalid characters', async () => {
        // Arrange
        const invalidRequest: UpdateProfileRequest = {
          name: 'User@Name123',
        };

        const existingUser = User.create({
          id: validUserId,
          email: 'user@example.com',
          password: 'HashedPassword123!',
          name: 'Original Name',
          provider: AuthProvider.LOCAL,
        });

        userRepository.findById.mockResolvedValue(existingUser);

        // Act
        await useCase.execute(validUserId, invalidRequest);

        // Assert
        expect(presenter.presentProfileUpdateValidationError).toHaveBeenCalledWith(
          'Name can only contain letters, spaces, and common international characters'
        );
      });

      it('should reject invalid profile picture URL', async () => {
        // Arrange
        const invalidRequest: UpdateProfileRequest = {
          profilePicture: 'not-a-valid-url',
        };

        const existingUser = User.create({
          id: validUserId,
          email: 'user@example.com',
          password: 'HashedPassword123!',
          name: 'User Name',
          provider: AuthProvider.LOCAL,
        });

        userRepository.findById.mockResolvedValue(existingUser);

        // Act
        await useCase.execute(validUserId, invalidRequest);

        // Assert
        expect(presenter.presentProfileUpdateValidationError).toHaveBeenCalledWith(
          'Profile picture URL must be a valid HTTP or HTTPS URL'
        );
      });

      it('should accept valid international names', async () => {
        // Arrange
        const internationalNames = [
          'José García',
          'François Müller',
          '김철수',
          '山田太郎',
          'Владимир Иванов',
        ];

        for (const name of internationalNames) {
          const request: UpdateProfileRequest = { name };

          const existingUser = User.create({
            id: validUserId,
            email: 'user@example.com',
            password: 'HashedPassword123!',
            name: 'Original Name',
            provider: AuthProvider.LOCAL,
          });

          const updatedUser = User.create({
            id: validUserId,
            email: 'user@example.com',
            password: 'HashedPassword123!',
            name: name,
            provider: AuthProvider.LOCAL,
          });

          userRepository.findById.mockResolvedValue(existingUser);
          userRepository.save.mockResolvedValue(updatedUser);

          // Act
          await useCase.execute(validUserId, request);

          // Assert
          expect(presenter.presentProfileUpdateSuccess).toHaveBeenCalledWith(
            expect.objectContaining({
              user: expect.objectContaining({
                name: name,
              }),
            })
          );
        }
      });
    });

    it('should handle unexpected errors during update', async () => {
      // Arrange
      userRepository.findById.mockRejectedValue(new Error('Database error'));

      // Act
      await useCase.execute(validUserId, validUpdateRequest);

      // Assert
      expect(presenter.presentProfileUpdateFailure).toHaveBeenCalledWith(
        'Profile update failed due to an internal error'
      );
    });
  });

  describe('executeProfilePictureUpload - Profile Picture Upload', () => {
    it('should successfully upload profile picture', async () => {
      // Arrange
      const existingUser = User.create({
        id: validUserId,
        email: 'user@example.com',
        password: 'HashedPassword123!',
        name: 'User Name',
        profilePicture: 'https://example.com/old-picture.jpg',
        provider: AuthProvider.LOCAL,
      });

      userRepository.findById.mockResolvedValue(existingUser);
      userRepository.save.mockResolvedValue(existingUser);

      // Act
      await useCase.executeProfilePictureUpload(validUserId, validUploadRequest);

      // Assert
      expect(userRepository.findById).toHaveBeenCalledWith(validUserId);
      expect(userRepository.save).toHaveBeenCalled();
      expect(presenter.presentProfilePictureUploadSuccess).toHaveBeenCalledWith({
        profilePicture: expect.stringMatching(/^https:\/\/storage\.example\.com\/profile-pictures\//),
        uploadedAt: expect.any(Date),
      });
    });

    it('should reject upload when user not found', async () => {
      // Arrange
      userRepository.findById.mockResolvedValue(null);

      // Act
      await useCase.executeProfilePictureUpload(validUserId, validUploadRequest);

      // Assert
      expect(presenter.presentUserNotFound).toHaveBeenCalled();
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('should reject upload for inactive user', async () => {
      // Arrange
      const inactiveUser = User.create({
        id: validUserId,
        email: 'user@example.com',
        password: 'HashedPassword123!',
        name: 'User Name',
        provider: AuthProvider.LOCAL,
      });
      inactiveUser.deactivate();

      userRepository.findById.mockResolvedValue(inactiveUser);

      // Act
      await useCase.executeProfilePictureUpload(validUserId, validUploadRequest);

      // Assert
      expect(presenter.presentAccountLocked).toHaveBeenCalledWith(
        'Account is not active and cannot be updated'
      );
    });

    describe('File Validation', () => {
      it('should reject empty user ID', async () => {
        // Act
        await useCase.executeProfilePictureUpload('', validUploadRequest);

        // Assert
        expect(presenter.presentProfilePictureUploadFailure).toHaveBeenCalledWith(
          'User ID is required'
        );
      });

      it('should reject missing file', async () => {
        // Arrange
        const invalidRequest = { file: null as any };

        // Act
        await useCase.executeProfilePictureUpload(validUserId, invalidRequest);

        // Assert
        expect(presenter.presentProfilePictureUploadFailure).toHaveBeenCalledWith(
          'File is required for profile picture upload'
        );
      });

      it('should reject invalid MIME type', async () => {
        // Arrange
        const invalidRequest: UploadProfilePictureRequest = {
          file: {
            ...validUploadRequest.file,
            mimetype: 'text/plain',
          },
        };

        const existingUser = User.create({
          id: validUserId,
          email: 'user@example.com',
          password: 'HashedPassword123!',
          name: 'User Name',
          provider: AuthProvider.LOCAL,
        });

        userRepository.findById.mockResolvedValue(existingUser);

        // Act
        await useCase.executeProfilePictureUpload(validUserId, invalidRequest);

        // Assert
        expect(presenter.presentProfilePictureUploadFailure).toHaveBeenCalledWith(
          'File must be an image (JPEG, PNG, GIF, or WebP)'
        );
      });

      it('should reject file too large', async () => {
        // Arrange
        const invalidRequest: UploadProfilePictureRequest = {
          file: {
            ...validUploadRequest.file,
            size: 6 * 1024 * 1024, // 6MB
          },
        };

        const existingUser = User.create({
          id: validUserId,
          email: 'user@example.com',
          password: 'HashedPassword123!',
          name: 'User Name',
          provider: AuthProvider.LOCAL,
        });

        userRepository.findById.mockResolvedValue(existingUser);

        // Act
        await useCase.executeProfilePictureUpload(validUserId, invalidRequest);

        // Assert
        expect(presenter.presentProfilePictureUploadFailure).toHaveBeenCalledWith(
          'File size cannot exceed 5MB'
        );
      });

      it('should accept valid image types', async () => {
        // Arrange
        const validMimeTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];

        for (const mimetype of validMimeTypes) {
          const request: UploadProfilePictureRequest = {
            file: {
              ...validUploadRequest.file,
              mimetype,
            },
          };

          const existingUser = User.create({
            id: validUserId,
            email: 'user@example.com',
            password: 'HashedPassword123!',
            name: 'User Name',
            provider: AuthProvider.LOCAL,
          });

          userRepository.findById.mockResolvedValue(existingUser);
          userRepository.save.mockResolvedValue(existingUser);

          // Act
          await useCase.executeProfilePictureUpload(validUserId, request);

          // Assert
          expect(presenter.presentProfilePictureUploadSuccess).toHaveBeenCalledWith(
            expect.objectContaining({
              profilePicture: expect.any(String),
              uploadedAt: expect.any(Date),
            })
          );
        }
      });

      it('should reject missing buffer', async () => {
        // Arrange
        const invalidRequest: UploadProfilePictureRequest = {
          file: {
            ...validUploadRequest.file,
            buffer: null as any,
          },
        };

        const existingUser = User.create({
          id: validUserId,
          email: 'user@example.com',
          password: 'HashedPassword123!',
          name: 'User Name',
          provider: AuthProvider.LOCAL,
        });

        userRepository.findById.mockResolvedValue(existingUser);

        // Act
        await useCase.executeProfilePictureUpload(validUserId, invalidRequest);

        // Assert
        expect(presenter.presentProfilePictureUploadFailure).toHaveBeenCalledWith(
          'File buffer is required'
        );
      });

      it('should reject zero file size', async () => {
        // Arrange
        const invalidRequest: UploadProfilePictureRequest = {
          file: {
            ...validUploadRequest.file,
            size: 0,
          },
        };

        const existingUser = User.create({
          id: validUserId,
          email: 'user@example.com',
          password: 'HashedPassword123!',
          name: 'User Name',
          provider: AuthProvider.LOCAL,
        });

        userRepository.findById.mockResolvedValue(existingUser);

        // Act
        await useCase.executeProfilePictureUpload(validUserId, invalidRequest);

        // Assert
        expect(presenter.presentProfilePictureUploadFailure).toHaveBeenCalledWith(
          'File size is required and must be positive'
        );
      });
    });

    it('should handle unexpected errors during upload', async () => {
      // Arrange
      userRepository.findById.mockRejectedValue(new Error('Database error'));

      // Act
      await useCase.executeProfilePictureUpload(validUserId, validUploadRequest);

      // Assert
      expect(presenter.presentProfilePictureUploadFailure).toHaveBeenCalledWith(
        'Profile picture upload failed due to an internal error'
      );
    });
  });
});