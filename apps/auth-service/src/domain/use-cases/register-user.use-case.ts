import { Injectable, Inject } from '@nestjs/common';
import { User } from '../entities/user.entity';
import { UserRepository } from '../ports/user.repository';
import { PasswordHashingService } from '../ports/password-hashing.service';
import { RegisterUserRequest, RegisterUserResponse } from '../models/auth.models';
import { AuthProvider } from '@auth/shared/types/auth.types';

export class UserAlreadyExistsError extends Error {
  constructor(email: string) {
    super(`User with email ${email} already exists`);
    this.name = 'UserAlreadyExistsError';
  }
}

export class InvalidPasswordError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidPasswordError';
  }
}

@Injectable()
export class RegisterUserUseCase {
  constructor(
    @Inject('UserRepository')
    private readonly userRepository: UserRepository,
    @Inject('PasswordHashingService')
    private readonly passwordHashingService: PasswordHashingService,
  ) {}

  async execute(request: RegisterUserRequest): Promise<RegisterUserResponse> {
    // Validate input
    this.validateRequest(request);

    // Check if user already exists
    const existingUser = await this.userRepository.existsByEmail(request.email);
    if (existingUser) {
      throw new UserAlreadyExistsError(request.email);
    }

    // Validate password format
    if (!this.passwordHashingService.isValidPasswordFormat(request.password)) {
      throw new InvalidPasswordError(
        'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character'
      );
    }

    // Hash password
    const hashedPassword = await this.passwordHashingService.hash(request.password);

    // Create user entity
    const user = new User(
      this.generateUserId(),
      request.email,
      hashedPassword,
      request.name,
      request.profilePicture,
      AuthProvider.LOCAL
    );

    // Save user
    const savedUser = await this.userRepository.save(user);

    // Return response
    return {
      userId: savedUser.id,
      email: savedUser.email,
      name: savedUser.name,
      profilePicture: savedUser.profilePicture,
      isActive: savedUser.isAccountActive(),
      createdAt: savedUser.getCreatedAt(),
    };
  }

  private validateRequest(request: RegisterUserRequest): void {
    if (!request.email || request.email.trim().length === 0) {
      throw new Error('Email is required');
    }

    if (!request.password || request.password.trim().length === 0) {
      throw new Error('Password is required');
    }

    if (!request.name || request.name.trim().length === 0) {
      throw new Error('Name is required');
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(request.email)) {
      throw new Error('Invalid email format');
    }

    // Name length validation
    if (request.name.length < 2 || request.name.length > 50) {
      throw new Error('Name must be between 2 and 50 characters');
    }
  }

  private generateUserId(): string {
    return `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}