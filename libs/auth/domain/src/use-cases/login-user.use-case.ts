import {
  LoginUserRequest,
  LoginUserResponse,
  UserStatus,
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

/**
 * Login User Use Case
 * 
 * Handles user authentication with JWT token generation and session management.
 * Includes credential validation, account status checking, and security measures.
 */
export class LoginUserUseCase {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly tokenRepository: TokenRepository,
    private readonly sessionRepository: AuthSessionRepository,
    private readonly passwordHashingService: PasswordHashingService,
    private readonly tokenService: TokenService,
    private readonly presenter: AuthPresenter
  ) {}

  /**
   * Execute user login
   * @param request - Login request data
   */
  async execute(request: LoginUserRequest): Promise<void> {
    try {
      // 1. Validate input
      this.validateLoginInput(request);

      // 2. Find user by email
      const user = await this.userRepository.findByEmail(request.email);
      if (!user) {
        this.presenter.presentInvalidCredentials();
        return;
      }

      // 3. Check account status
      if (!this.isAccountAccessible(user)) {
        const reason = this.getAccountLockReason(user);
        this.presenter.presentAccountLocked(reason);
        return;
      }

      // 4. Verify password
      const userObject = user.toObject();
      const isPasswordValid = await this.passwordHashingService.compare(
        request.password,
        userObject['password']
      );

      if (!isPasswordValid) {
        this.presenter.presentInvalidCredentials();
        return;
      }

      // 5. Generate access and refresh tokens
      const accessTokenValue = await this.tokenService.generateAccessToken(
        user.id,
        user.email,
        '15m'
      );
      const refreshTokenValue = await this.tokenService.generateRefreshToken(
        user.id,
        user.email,
        '7d'
      );

      // 6. Create token entities
      const accessToken = Token.createAccessToken({
        id: this.generateTokenId('access'),
        userId: user.id,
        value: accessTokenValue,
        expirationMinutes: 15,
      });

      const refreshToken = Token.createRefreshToken({
        id: this.generateTokenId('refresh'),
        userId: user.id,
        value: refreshTokenValue,
        expirationDays: 7,
      });

      // 7. Save tokens
      await Promise.all([
        this.tokenRepository.save(accessToken),
        this.tokenRepository.save(refreshToken),
      ]);

      // 8. Create session
      const session = AuthSession.create({
        id: this.generateSessionId(),
        userId: user.id,
        sessionToken: accessTokenValue,
        clientInfo: request.clientInfo || {
          ipAddress: '127.0.0.1', // Should come from request context
          userAgent: 'Unknown', // Should come from request context
        },
        expirationHours: request.rememberMe ? 24 * 7 : 24, // 7 days if remember me, otherwise 24 hours
      });

      await this.sessionRepository.save(session);

      // 9. Update last login timestamp
      await this.userRepository.updateLastLogin(user.id, new Date());

      // 10. Present success response
      const response: LoginUserResponse = {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          profilePicture: user.profilePicture,
          provider: user.provider,
          lastLoginAt: new Date(),
        },
        tokens: {
          accessToken: accessTokenValue,
          refreshToken: refreshTokenValue,
          expiresIn: 15 * 60, // 15 minutes in seconds
        },
        session: {
          id: session.id,
          expiresAt: session.expiresAt,
        },
      };

      this.presenter.presentLoginSuccess(response);
    } catch (error) {
      this.handleLoginError(error);
    }
  }

  /**
   * Validate login input
   * @param request - Login request data
   */
  private validateLoginInput(request: LoginUserRequest): void {
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
    }

    if (Object.keys(errors).length > 0) {
      this.presenter.presentAuthenticationError(
        'Invalid login credentials provided',
        'VALIDATION_ERROR'
      );
      return;
    }
  }

  /**
   * Check if account is accessible for login
   * @param user - User entity
   * @returns True if account can be accessed
   */
  private isAccountAccessible(user: User): boolean {
    const userObject = user.toObject();
    const status = userObject['status'];
    
    return status === UserStatus.ACTIVE;
  }

  /**
   * Get reason why account is locked
   * @param user - User entity
   * @returns Lock reason message
   */
  private getAccountLockReason(user: User): string {
    const userObject = user.toObject();
    const status = userObject['status'];

    switch (status) {
      case UserStatus.INACTIVE:
        return 'Account is inactive. Please contact support to activate your account.';
      case UserStatus.SUSPENDED:
        return 'Account has been suspended. Please contact support for assistance.';
      case UserStatus.DELETED:
        return 'Account has been deleted and cannot be accessed.';
      default:
        return 'Account access is restricted. Please contact support.';
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
   * Handle login errors
   * @param error - Error that occurred during login
   */
  private handleLoginError(error: any): void {
    // Log error for debugging (in real implementation)
    console.error('Login error:', error);

    // Present generic error to user
    this.presenter.presentAuthenticationError(
      'Login failed due to an internal error',
      'LOGIN_ERROR'
    );
  }
}