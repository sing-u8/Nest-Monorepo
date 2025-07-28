import {
  UpdateProfileRequest,
  UpdateProfileResponse,
  UploadProfilePictureRequest,
  UploadProfilePictureResponse,
} from '@auth/shared';
import { User } from '../entities/user.entity';
import { UserRepository } from '../ports/repositories/user.repository';
import { ProfilePresenter } from '../ports/presenters/profile.presenter';

/**
 * Update Profile Use Case
 * 
 * Handles user profile updates including name changes and profile picture uploads.
 * Implements proper validation and security measures for profile modifications.
 */
export class UpdateProfileUseCase {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly presenter: ProfilePresenter
  ) {}

  /**
   * Execute profile update
   * @param userId - User ID requesting the update
   * @param request - Profile update request data
   */
  async execute(userId: string, request: UpdateProfileRequest): Promise<void> {
    try {
      // 1. Validate input
      this.validateUpdateProfileInput(userId, request);

      // 2. Find user
      const user = await this.userRepository.findById(userId);
      if (!user) {
        this.presenter.presentUserNotFound();
        return;
      }

      // 3. Check if user account is active
      if (!this.isUserActive(user)) {
        this.presenter.presentAccountLocked('Account is not active and cannot be updated');
        return;
      }

      // 4. Validate profile data
      if (request.name) {
        this.validateName(request.name);
      }

      if (request.profilePicture) {
        this.validateProfilePictureUrl(request.profilePicture);
      }

      // 5. Check if any changes are being made
      const userObject = user.toObject();
      const hasChanges = this.hasProfileChanges(userObject, request);
      
      if (!hasChanges) {
        this.presenter.presentProfileUpdateFailure('No changes detected in profile data');
        return;
      }

      // 6. Update user profile
      const updatedUser = this.updateUserProfile(user, request);

      // 7. Save updated user
      const savedUser = await this.userRepository.save(updatedUser);

      // 8. Present success response
      const response: UpdateProfileResponse = {
        user: {
          id: savedUser.id,
          email: savedUser.email,
          name: savedUser.name,
          profilePicture: savedUser.profilePicture,
          updatedAt: new Date(),
        },
      };

      this.presenter.presentProfileUpdateSuccess(response);
    } catch (error) {
      this.handleUpdateProfileError(error);
    }
  }

  /**
   * Execute profile picture upload
   * @param userId - User ID requesting the upload
   * @param request - Profile picture upload request data
   */
  async executeProfilePictureUpload(
    userId: string, 
    request: UploadProfilePictureRequest
  ): Promise<void> {
    try {
      // 1. Validate input
      this.validateProfilePictureUploadInput(userId, request);

      // 2. Find user
      const user = await this.userRepository.findById(userId);
      if (!user) {
        this.presenter.presentUserNotFound();
        return;
      }

      // 3. Check if user account is active
      if (!this.isUserActive(user)) {
        this.presenter.presentAccountLocked('Account is not active and cannot be updated');
        return;
      }

      // 4. Validate file
      this.validateUploadedFile(request.file);

      // 5. Generate profile picture URL (in real implementation, upload to storage service)
      const profilePictureUrl = this.generateProfilePictureUrl(userId, request.file);

      // 6. Update user profile picture
      const userObject = user.toObject();
      const updatedUser = User.create({
        id: userObject['id'],
        email: userObject['email'],
        password: userObject['password'],
        name: userObject['name'],
        profilePicture: profilePictureUrl,
        provider: userObject['provider'],
        providerId: userObject['providerId'],
        emailVerified: userObject['emailVerified'],
        status: userObject['status'],
      });

      // 7. Save updated user
      await this.userRepository.save(updatedUser);

      // 8. Present success response
      const response: UploadProfilePictureResponse = {
        profilePicture: profilePictureUrl,
        uploadedAt: new Date(),
      };

      this.presenter.presentProfilePictureUploadSuccess(response);
    } catch (error) {
      this.handleProfilePictureUploadError(error);
    }
  }

  /**
   * Validate update profile input
   * @param userId - User ID
   * @param request - Update profile request data
   */
  private validateUpdateProfileInput(userId: string, request: UpdateProfileRequest): void {
    const errors: string[] = [];

    // User ID validation
    if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
      errors.push('User ID is required');
    }

    // Request validation
    if (!request || typeof request !== 'object') {
      errors.push('Profile data is required');
    } else {
      // Check if at least one field is provided
      if (!request.name && !request.profilePicture) {
        errors.push('At least one profile field must be provided for update');
      }
    }

    if (errors.length > 0) {
      this.presenter.presentProfileUpdateValidationError(errors.join(', '));
      throw new Error('Profile update validation failed');
    }
  }

  /**
   * Validate profile picture upload input
   * @param userId - User ID
   * @param request - Profile picture upload request data
   */
  private validateProfilePictureUploadInput(
    userId: string, 
    request: UploadProfilePictureRequest
  ): void {
    const errors: string[] = [];

    // User ID validation
    if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
      errors.push('User ID is required');
    }

    // Request validation
    if (!request || typeof request !== 'object') {
      errors.push('Upload data is required');
    } else if (!request.file) {
      errors.push('File is required for profile picture upload');
    }

    if (errors.length > 0) {
      this.presenter.presentProfilePictureUploadFailure(errors.join(', '));
      throw new Error('Profile picture upload validation failed');
    }
  }

  /**
   * Validate name field
   * @param name - Name to validate
   */
  private validateName(name: string): void {
    const errors: string[] = [];

    if (typeof name !== 'string') {
      errors.push('Name must be a string');
    } else {
      const trimmedName = name.trim();
      
      if (trimmedName.length === 0) {
        errors.push('Name cannot be empty');
      } else if (trimmedName.length < 2) {
        errors.push('Name must be at least 2 characters long');
      } else if (trimmedName.length > 100) {
        errors.push('Name cannot exceed 100 characters');
      } else if (!/^[a-zA-Z\s\u00C0-\u017F\u1E00-\u1EFF\u0100-\u024F\u4E00-\u9FFF\uAC00-\uD7AF]+$/.test(trimmedName)) {
        errors.push('Name can only contain letters, spaces, and common international characters');
      }
    }

    if (errors.length > 0) {
      this.presenter.presentProfileUpdateValidationError(errors.join(', '));
      throw new Error('Name validation failed');
    }
  }

  /**
   * Validate profile picture URL
   * @param profilePictureUrl - Profile picture URL to validate
   */
  private validateProfilePictureUrl(profilePictureUrl: string): void {
    const errors: string[] = [];

    if (typeof profilePictureUrl !== 'string') {
      errors.push('Profile picture URL must be a string');
    } else {
      const trimmedUrl = profilePictureUrl.trim();
      
      if (trimmedUrl.length === 0) {
        errors.push('Profile picture URL cannot be empty');
      } else if (trimmedUrl.length > 500) {
        errors.push('Profile picture URL cannot exceed 500 characters');
      } else if (!/^https?:\/\/.+/.test(trimmedUrl)) {
        errors.push('Profile picture URL must be a valid HTTP or HTTPS URL');
      }
    }

    if (errors.length > 0) {
      this.presenter.presentProfileUpdateValidationError(errors.join(', '));
      throw new Error('Profile picture URL validation failed');
    }
  }

  /**
   * Validate uploaded file
   * @param file - Uploaded file to validate
   */
  private validateUploadedFile(file: any): void {
    const errors: string[] = [];

    if (!file || typeof file !== 'object') {
      errors.push('File object is required');
      this.presenter.presentProfilePictureUploadFailure(errors.join(', '));
      throw new Error('File validation failed');
    }

    // Check required properties
    if (!file.buffer || !Buffer.isBuffer(file.buffer)) {
      errors.push('File buffer is required');
    }

    if (!file.mimetype || typeof file.mimetype !== 'string') {
      errors.push('File MIME type is required');
    }

    if (!file.originalname || typeof file.originalname !== 'string') {
      errors.push('File name is required');
    }

    if (typeof file.size !== 'number' || file.size <= 0) {
      errors.push('File size is required and must be positive');
    }

    // Validate MIME type
    const allowedMimeTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    if (file.mimetype && !allowedMimeTypes.includes(file.mimetype.toLowerCase())) {
      errors.push('File must be an image (JPEG, PNG, GIF, or WebP)');
    }

    // Validate file size (max 5MB)
    const maxFileSize = 5 * 1024 * 1024; // 5MB in bytes
    if (file.size && file.size > maxFileSize) {
      errors.push('File size cannot exceed 5MB');
    }

    // Validate file name
    if (file.originalname && file.originalname.length > 255) {
      errors.push('File name cannot exceed 255 characters');
    }

    if (errors.length > 0) {
      this.presenter.presentProfilePictureUploadFailure(errors.join(', '));
      throw new Error('File validation failed');
    }
  }

  /**
   * Check if user account is active
   * @param user - User entity
   * @returns True if user is active
   */
  private isUserActive(user: User): boolean {
    const userObject = user.toObject();
    return userObject['status'] === 'active';
  }

  /**
   * Check if profile has changes
   * @param currentUser - Current user data
   * @param request - Update request
   * @returns True if changes detected
   */
  private hasProfileChanges(currentUser: any, request: UpdateProfileRequest): boolean {
    if (request.name && request.name.trim() !== currentUser['name']) {
      return true;
    }

    if (request.profilePicture && request.profilePicture !== currentUser['profilePicture']) {
      return true;
    }

    return false;
  }

  /**
   * Update user profile with new data
   * @param user - User entity to update
   * @param request - Update request data
   * @returns Updated user entity
   */
  private updateUserProfile(user: User, request: UpdateProfileRequest): User {
    const userObject = user.toObject();

    return User.create({
      id: userObject['id'],
      email: userObject['email'],
      password: userObject['password'],
      name: request.name?.trim() || userObject['name'],
      profilePicture: request.profilePicture || userObject['profilePicture'],
      provider: userObject['provider'],
      providerId: userObject['providerId'],
      emailVerified: userObject['emailVerified'],
      status: userObject['status'],
    });
  }

  /**
   * Generate profile picture URL
   * @param userId - User ID
   * @param file - Uploaded file
   * @returns Generated profile picture URL
   */
  private generateProfilePictureUrl(userId: string, file: any): string {
    // In real implementation, upload to storage service (AWS S3, Google Cloud Storage, etc.)
    // and return the public URL
    const timestamp = Date.now();
    const fileExtension = this.getFileExtension(file.mimetype);
    return `https://storage.example.com/profile-pictures/${userId}-${timestamp}.${fileExtension}`;
  }

  /**
   * Get file extension from MIME type
   * @param mimetype - File MIME type
   * @returns File extension
   */
  private getFileExtension(mimetype: string): string {
    const mimeToExtension: { [key: string]: string } = {
      'image/jpeg': 'jpg',
      'image/jpg': 'jpg',
      'image/png': 'png',
      'image/gif': 'gif',
      'image/webp': 'webp',
    };

    return mimeToExtension[mimetype.toLowerCase()] || 'jpg';
  }

  /**
   * Handle profile update errors
   * @param error - Error that occurred during profile update
   */
  private handleUpdateProfileError(error: any): void {
    if (error.message === 'Profile update validation failed' ||
        error.message === 'Name validation failed' ||
        error.message === 'Profile picture URL validation failed') {
      // Validation errors already presented
      return;
    }

    // Log error for debugging (in real implementation)
    console.error('Profile update error:', error);

    // Present generic error to user
    this.presenter.presentProfileUpdateFailure(
      'Profile update failed due to an internal error'
    );
  }

  /**
   * Handle profile picture upload errors
   * @param error - Error that occurred during profile picture upload
   */
  private handleProfilePictureUploadError(error: any): void {
    if (error.message === 'Profile picture upload validation failed' ||
        error.message === 'File validation failed') {
      // Validation errors already presented
      return;
    }

    // Log error for debugging (in real implementation)
    console.error('Profile picture upload error:', error);

    // Present generic error to user
    this.presenter.presentProfilePictureUploadFailure(
      'Profile picture upload failed due to an internal error'
    );
  }
}