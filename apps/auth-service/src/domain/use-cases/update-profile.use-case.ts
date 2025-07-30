import { Injectable, Inject } from '@nestjs/common';
import { UserRepository } from '../ports/user.repository';
import { UpdateProfileRequest, UpdateProfileResponse } from '../models/auth.models';

export class UserNotFoundError extends Error {
  constructor(userId: string) {
    super(`User with ID ${userId} not found`);
    this.name = 'UserNotFoundError';
  }
}

export class UserNotActiveError extends Error {
  constructor(message: string = 'User account is not active') {
    super(message);
    this.name = 'UserNotActiveError';
  }
}

export class InvalidProfileDataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidProfileDataError';
  }
}

export class NoChangesError extends Error {
  constructor(message: string = 'No changes provided for profile update') {
    super(message);
    this.name = 'NoChangesError';
  }
}

@Injectable()
export class UpdateProfileUseCase {
  constructor(
    @Inject('UserRepository')
    private readonly userRepository: UserRepository,
  ) {}

  async execute(request: UpdateProfileRequest): Promise<UpdateProfileResponse> {
    // Validate input
    this.validateRequest(request);

    // Find user by ID
    const user = await this.userRepository.findById(request.userId);
    if (!user) {
      throw new UserNotFoundError(request.userId);
    }

    // Check if user account is active
    if (!user.isAccountActive()) {
      throw new UserNotActiveError('Cannot update profile for inactive user');
    }

    // Check if any changes are provided
    const hasChanges = request.name !== undefined || request.profilePicture !== undefined;
    if (!hasChanges) {
      throw new NoChangesError('At least one field (name or profilePicture) must be provided');
    }

    // Validate profile picture URL format if provided
    if (request.profilePicture !== undefined) {
      this.validateProfilePicture(request.profilePicture);
    }

    // Update user profile
    try {
      // Only update name if provided and different from current
      const newName = request.name !== undefined ? request.name : user.name;
      
      // Only update profile picture if provided
      const newProfilePicture = request.profilePicture !== undefined 
        ? request.profilePicture 
        : user.profilePicture;

      // Check if there are actual changes
      if (newName === user.name && newProfilePicture === user.profilePicture) {
        throw new NoChangesError('No actual changes detected in profile data');
      }

      // Update user profile (this will call the domain entity method)
      user.updateProfile(newName, newProfilePicture);

      // Save updated user
      const updatedUser = await this.userRepository.save(user);

      return {
        userId: updatedUser.id,
        email: updatedUser.email,
        name: updatedUser.name,
        profilePicture: updatedUser.profilePicture,
        updatedAt: updatedUser.getUpdatedAt(),
      };
    } catch (error) {
      if (error instanceof NoChangesError) {
        throw error;
      }
      throw new InvalidProfileDataError(`Failed to update profile: ${error.message}`);
    }
  }

  private validateRequest(request: UpdateProfileRequest): void {
    if (!request.userId || request.userId.trim().length === 0) {
      throw new Error('User ID is required');
    }

    // Validate user ID format (basic UUID check)
    const userIdPattern = /^user_\d+_[a-z0-9]+$/;
    if (!userIdPattern.test(request.userId)) {
      throw new Error('Invalid user ID format');
    }

    // Validate name if provided
    if (request.name !== undefined) {
      this.validateName(request.name);
    }
  }

  private validateName(name: string): void {
    if (name === null) {
      throw new InvalidProfileDataError('Name cannot be null');
    }

    if (typeof name !== 'string') {
      throw new InvalidProfileDataError('Name must be a string');
    }

    if (name.trim().length === 0) {
      throw new InvalidProfileDataError('Name cannot be empty');
    }

    if (name.length < 2) {
      throw new InvalidProfileDataError('Name must be at least 2 characters long');
    }

    if (name.length > 100) {
      throw new InvalidProfileDataError('Name cannot exceed 100 characters');
    }

    // Check for valid characters (letters, spaces, hyphens, apostrophes)
    const namePattern = /^[a-zA-Z\s\-']+$/;
    if (!namePattern.test(name)) {
      throw new InvalidProfileDataError('Name can only contain letters, spaces, hyphens, and apostrophes');
    }

    // Check for excessive whitespace
    if (name.includes('  ')) {
      throw new InvalidProfileDataError('Name cannot contain consecutive spaces');
    }

    // Check for leading/trailing whitespace
    if (name !== name.trim()) {
      throw new InvalidProfileDataError('Name cannot have leading or trailing whitespace');
    }
  }

  private validateProfilePicture(profilePicture: string): void {
    if (profilePicture === null) {
      return; // null is allowed (removes profile picture)
    }

    if (typeof profilePicture !== 'string') {
      throw new InvalidProfileDataError('Profile picture must be a string URL or null');
    }

    // Allow empty string to remove profile picture
    if (profilePicture === '') {
      return;
    }

    // Validate URL format
    try {
      const url = new URL(profilePicture);
      
      // Only allow https URLs for security
      if (url.protocol !== 'https:') {
        throw new InvalidProfileDataError('Profile picture URL must use HTTPS protocol');
      }

      // Check file extension (basic image formats)
      const validExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
      const pathname = url.pathname.toLowerCase();
      const hasValidExtension = validExtensions.some(ext => pathname.endsWith(ext));
      
      if (!hasValidExtension) {
        throw new InvalidProfileDataError('Profile picture must be a valid image file (jpg, jpeg, png, gif, webp)');
      }

      // Check URL length
      if (profilePicture.length > 2048) {
        throw new InvalidProfileDataError('Profile picture URL cannot exceed 2048 characters');
      }

    } catch (error) {
      if (error instanceof InvalidProfileDataError) {
        throw error;
      }
      throw new InvalidProfileDataError('Invalid profile picture URL format');
    }
  }
}