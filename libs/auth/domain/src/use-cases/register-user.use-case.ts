import {
  RegisterUserRequest,
  RegisterUserResponse,
} from '@auth/shared';
import { User } from '../entities/user.entity';
import { Token } from '../entities/token.entity';
import { AuthSession } from '../entities/auth-session.entity';
import { UserRepository } from '../ports/repositories/user.repository';
import { TokenRepository } from '../ports/repositories/token.repository';
import { AuthSessionRepository } from '../ports/repositories/auth-session.repository';
import { PasswordHashingService } from '../ports/services/password-hashing.service';
import { TokenService } from '../ports/services/token.service';
import { AuthPresenter } from '../ports/presenters/auth.presenter';
import { AuthProvider } from '@auth/shared';

/**
 * Register User Use Case
 * 
 * Handles new user registration with email validation, duplicate checking,
 * password hashing, and token generation following clean architecture principles.
 */
export class RegisterUserUseCase {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly tokenRepository: TokenRepository,
    private readonly sessionRepository: AuthSessionRepository,
    private readonly passwordHashingService: PasswordHashingService,
    private readonly tokenService: TokenService,
    private readonly presenter: AuthPresenter
  ) {}

  /**
   * Execute user registration
   * @param request - Registration request data
   */
  async execute(request: RegisterUserRequest): Promise<void> {
    try {
      // 1. Validate input
      this.validateRegistrationInput(request);

      // 2. Check if user already exists
      const existingUser = await this.userRepository.findByEmail(request.email);
      if (existingUser) {
        this.presenter.presentDuplicateEmail(request.email);
        return;
      }

      // 3. Hash password
      const hashedPassword = await this.passwordHashingService.hash(
        request.password
      );

      // 4. Create user entity
      const user = User.create({
        id: this.generateUserId(),
        email: request.email,
        password: hashedPassword,
        name: request.name,
        profilePicture: request.profilePicture,
        provider: AuthProvider.LOCAL,
      });

      // 5. Save user to repository
      const savedUser = await this.userRepository.save(user);

      // 6. Generate access and refresh tokens
      const accessTokenValue = await this.tokenService.generateAccessToken(
        savedUser.id,
        savedUser.email,
        '15m'
      );
      const refreshTokenValue = await this.tokenService.generateRefreshToken(
        savedUser.id,
        savedUser.email,
        '7d'
      );

      // 7. Create token entities
      const accessToken = Token.createAccessToken({
        id: this.generateTokenId('access'),
        userId: savedUser.id,
        value: accessTokenValue,
        expirationMinutes: 15,
      });

      const refreshToken = Token.createRefreshToken({
        id: this.generateTokenId('refresh'),
        userId: savedUser.id,
        value: refreshTokenValue,
        expirationDays: 7,
      });

      // 8. Save tokens
      await Promise.all([
        this.tokenRepository.save(accessToken),
        this.tokenRepository.save(refreshToken),
      ]);

      // 9. Create initial session
      const session = AuthSession.create({
        id: this.generateSessionId(),
        userId: savedUser.id,
        sessionToken: accessTokenValue,
        clientInfo: {
          ipAddress: '127.0.0.1', // Should come from request
          userAgent: 'Unknown', // Should come from request
        },
        expirationHours: 24,
      });

      await this.sessionRepository.save(session);

      // 10. Present success response
      const userObject = savedUser.toObject();
      const response: RegisterUserResponse = {
        user: {
          id: savedUser.id,
          email: savedUser.email,
          name: savedUser.name,
          profilePicture: savedUser.profilePicture,
          provider: savedUser.provider,
          createdAt: userObject['createdAt'],
        },
        tokens: {
          accessToken: accessTokenValue,
          refreshToken: refreshTokenValue,
          expiresIn: 15 * 60, // 15 minutes in seconds
        },
      };

      this.presenter.presentRegistrationSuccess(response);
    } catch (error) {
      this.handleRegistrationError(error);
    }
  }

  /**
   * Validate registration input
   * @param request - Registration request data
   */
  private validateRegistrationInput(request: RegisterUserRequest): void {
    const errors: Record<string, string[]> = {};

    // Email validation
    if (!request.email) {
      errors['email'] = ['Email is required'];
    } else if (!this.isValidEmail(request.email)) {
      errors['email'] = ['Invalid email format'];
    }

    // Password validation
    if (!request.password) {
      errors['password'] = ['Password is required'];
    } else {
      const passwordErrors = this.validatePassword(request.password);
      if (passwordErrors.length > 0) {
        errors['password'] = passwordErrors;
      }
    }

    // Name validation
    if (!request.name) {
      errors['name'] = ['Name is required'];
    } else if (request.name.trim().length < 2) {
      errors['name'] = ['Name must be at least 2 characters long'];
    } else if (request.name.trim().length > 100) {
      errors['name'] = ['Name must not exceed 100 characters'];
    }

    // Profile picture validation (optional)
    if (request.profilePicture && !this.isValidUrl(request.profilePicture)) {
      errors['profilePicture'] = ['Invalid profile picture URL format'];
    }

    if (Object.keys(errors).length > 0) {
      this.presenter.presentRegistrationValidationError(errors);
      throw new Error('Registration validation failed');
    }
  }

  /**
   * Validate email format
   * @param email - Email to validate
   * @returns True if valid email format
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email.toLowerCase());
  }

  /**
   * Validate password strength
   * @param password - Password to validate
   * @returns Array of validation errors
   */
  private validatePassword(password: string): string[] {
    const errors: string[] = [];

    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }

    if (password.length > 128) {
      errors.push('Password must not exceed 128 characters');
    }

    if (!/(?=.*[a-z])/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/(?=.*[A-Z])/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/(?=.*\d)/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (!/(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    // Check for common patterns
    if (/(.)\1{2,}/.test(password)) {
      errors.push('Password must not contain repeated characters');
    }

    if (/123|abc|qwe|asd/i.test(password)) {
      errors.push('Password must not contain common sequences');
    }

    return errors;
  }

  /**
   * Validate URL format
   * @param url - URL to validate
   * @returns True if valid URL format
   */
  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return url.startsWith('http://') || url.startsWith('https://');
    } catch {
      return false;
    }
  }

  /**
   * Generate unique user ID
   * @returns Generated user ID
   */
  private generateUserId(): string {
    // In real implementation, use UUID library or database sequence
    return 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  /**
   * Generate unique token ID
   * @param type - Token type for prefix
   * @returns Generated token ID
   */
  private generateTokenId(type: string): string {
    // In real implementation, use UUID library or database sequence
    return `${type}_token_` + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  /**
   * Generate unique session ID
   * @returns Generated session ID
   */
  private generateSessionId(): string {
    // In real implementation, use UUID library or database sequence
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  /**
   * Handle registration errors
   * @param error - Error that occurred during registration
   */
  private handleRegistrationError(error: any): void {
    if (error.message === 'Registration validation failed') {
      // Validation errors already presented
      return;
    }

    // Log error for debugging (in real implementation)
    console.error('Registration error:', error);

    // Present generic error to user
    this.presenter.presentAuthenticationError(
      'Registration failed due to an internal error',
      'REGISTRATION_ERROR'
    );
  }
}