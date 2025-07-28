import {
  SocialLoginRequest,
  SocialLoginResponse,
  AuthProvider,
  UserStatus,
} from '@auth/shared';
import { User } from '../entities/user.entity';
import { Token } from '../entities/token.entity';
import { AuthSession } from '../entities/auth-session.entity';
import { UserRepository } from '../ports/repositories/user.repository';
import { TokenRepository } from '../ports/repositories/token.repository';
import { AuthSessionRepository } from '../ports/repositories/auth-session.repository';
import { TokenService } from '../ports/services/token.service';
import { GoogleOAuthService, GoogleUserProfile } from '../ports/services/google-oauth.service';
import { AppleOAuthService, AppleUserProfile } from '../ports/services/apple-oauth.service';
import { AuthPresenter } from '../ports/presenters/auth.presenter';

/**
 * Social Login Use Case
 * 
 * Handles OAuth authentication flows for Google and Apple Sign In.
 * Supports new user creation and existing user lookup with proper error handling.
 */
export class SocialLoginUseCase {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly tokenRepository: TokenRepository,
    private readonly sessionRepository: AuthSessionRepository,
    private readonly tokenService: TokenService,
    private readonly googleOAuthService: GoogleOAuthService,
    private readonly appleOAuthService: AppleOAuthService,
    private readonly presenter: AuthPresenter
  ) {}

  /**
   * Execute social login
   * @param request - Social login request data
   */
  async execute(request: SocialLoginRequest): Promise<void> {
    try {
      // 1. Validate input
      this.validateSocialLoginInput(request);

      // 2. Process OAuth based on provider
      let userProfile: GoogleUserProfile | AppleUserProfile;
      
      if (request.provider === AuthProvider.GOOGLE) {
        userProfile = await this.processGoogleOAuth(request);
      } else if (request.provider === AuthProvider.APPLE) {
        userProfile = await this.processAppleOAuth(request);
      } else {
        this.presenter.presentSocialLoginFailure(
          request.provider as string,
          'Unsupported OAuth provider'
        );
        return;
      }

      // 3. Find or create user
      const { user, isNewUser } = await this.findOrCreateUser(userProfile, request.provider);

      // 4. Check user account status
      if (!this.isUserActive(user)) {
        const reason = this.getAccountLockReason(user);
        this.presenter.presentAccountLocked(reason);
        return;
      }

      // 5. Generate tokens
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
        expirationHours: 24,
      });

      await this.sessionRepository.save(session);

      // 9. Update last login timestamp
      await this.userRepository.updateLastLogin(user.id, new Date());

      // 10. Present success response
      const response: SocialLoginResponse = {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          profilePicture: user.profilePicture,
          provider: user.provider,
          isNewUser: isNewUser,
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

      this.presenter.presentSocialLoginSuccess(response);
    } catch (error) {
      this.handleSocialLoginError(error, request.provider as string);
    }
  }

  /**
   * Validate social login input
   * @param request - Social login request data
   */
  private validateSocialLoginInput(request: SocialLoginRequest): void {
    const errors: string[] = [];

    // Provider validation
    if (!request.provider) {
      errors.push('OAuth provider is required');
    } else if (![AuthProvider.GOOGLE, AuthProvider.APPLE].includes(request.provider)) {
      errors.push('Unsupported OAuth provider');
    }

    // Provider-specific validation
    if (request.provider === AuthProvider.GOOGLE) {
      if (!request.code && !request.idToken) {
        errors.push('Authorization code or ID token is required for Google OAuth');
      }
    }

    if (request.provider === AuthProvider.APPLE) {
      if (!request.idToken) {
        errors.push('Identity token is required for Apple Sign In');
      }
    }

    if (errors.length > 0) {
      this.presenter.presentSocialLoginFailure(
        request.provider as string,
        errors.join(', ')
      );
      throw new Error('Social login validation failed');
    }
  }

  /**
   * Process Google OAuth authentication
   * @param request - Social login request
   * @returns Google user profile
   */
  private async processGoogleOAuth(request: SocialLoginRequest): Promise<GoogleUserProfile> {
    try {
      if (request.code) {
        // Authorization code flow
        const tokenResponse = await this.googleOAuthService.exchangeCodeForTokens(
          request.code,
          'state' // Should be validated against stored state
        );
        
        return await this.googleOAuthService.getUserProfile(tokenResponse.accessToken);
      } else if (request.idToken) {
        // ID token flow
        const tokenPayload = await this.googleOAuthService.verifyIdToken(request.idToken);
        return await this.googleOAuthService.extractUserProfile(tokenPayload);
      } else {
        throw new Error('Invalid Google OAuth parameters');
      }
    } catch (error) {
      console.error('Google OAuth error:', error);
      throw new Error('Google OAuth authentication failed');
    }
  }

  /**
   * Process Apple OAuth authentication
   * @param request - Social login request
   * @returns Apple user profile
   */
  private async processAppleOAuth(request: SocialLoginRequest): Promise<AppleUserProfile> {
    try {
      if (request.code) {
        // Authorization code flow
        const tokenResponse = await this.appleOAuthService.exchangeCodeForTokens(
          request.code,
          'state' // Should be validated against stored state
        );
        
        return tokenResponse.userProfile;
      } else if (request.idToken) {
        // Identity token flow
        return await this.appleOAuthService.extractUserProfile(
          request.idToken,
          request.userInfo
        );
      } else {
        throw new Error('Invalid Apple OAuth parameters');
      }
    } catch (error) {
      console.error('Apple OAuth error:', error);
      throw new Error('Apple OAuth authentication failed');
    }
  }

  /**
   * Find existing user or create new user from OAuth profile
   * @param profile - OAuth user profile
   * @param provider - OAuth provider
   * @returns User and isNewUser flag
   */
  private async findOrCreateUser(
    profile: GoogleUserProfile | AppleUserProfile,
    provider: AuthProvider
  ): Promise<{ user: User; isNewUser: boolean }> {
    // 1. Try to find user by email
    let user = await this.userRepository.findByEmail(profile.email);
    
    if (user) {
      // User exists - check if provider matches or if it's a different provider
      const userObject = user.toObject();
      
      if (userObject['provider'] !== provider) {
        // User exists with different provider - could be account linking scenario
        // For now, we'll treat this as an error, but in production you might want to support account linking
        throw new Error(`Account already exists with different provider: ${userObject['provider']}`);
      }
      
      return { user, isNewUser: false };
    }

    // 2. Try to find user by provider ID
    user = await this.userRepository.findByProviderId(provider as string, profile.id);
    
    if (user) {
      return { user, isNewUser: false };
    }

    // 3. Create new user
    const newUser = User.createFromSocialProvider({
      id: this.generateUserId(),
      email: profile.email,
      name: this.extractFullName(profile),
      provider: provider,
      providerId: profile.id,
      profilePicture: this.extractProfilePicture(profile),
      emailVerified: this.isEmailVerified(profile),
    });

    const savedUser = await this.userRepository.save(newUser);
    return { user: savedUser, isNewUser: true };
  }

  /**
   * Extract full name from OAuth profile
   * @param profile - OAuth user profile
   * @returns Full name string
   */
  private extractFullName(profile: GoogleUserProfile | AppleUserProfile): string {
    if ('name' in profile && profile.name) {
      // Google profile
      return profile.name;
    } else if ('name' in profile && profile.name && typeof profile.name === 'object') {
      // Apple profile with name object
      const nameObj = profile.name as { firstName?: string; lastName?: string };
      const firstName = nameObj.firstName || '';
      const lastName = nameObj.lastName || '';
      return `${firstName} ${lastName}`.trim() || profile.email.split('@')[0];
    }
    
    // Fallback to email username
    return profile.email.split('@')[0];
  }

  /**
   * Extract profile picture URL from OAuth profile
   * @param profile - OAuth user profile
   * @returns Profile picture URL or undefined
   */
  private extractProfilePicture(profile: GoogleUserProfile | AppleUserProfile): string | undefined {
    if ('picture' in profile) {
      return profile.picture;
    }
    return undefined;
  }

  /**
   * Check if email is verified from OAuth profile
   * @param profile - OAuth user profile
   * @returns True if email is verified
   */
  private isEmailVerified(profile: GoogleUserProfile | AppleUserProfile): boolean {
    if ('emailVerified' in profile) {
      return profile.emailVerified;
    }
    if ('email_verified' in profile) {
      return profile.email_verified;
    }
    // Default to true for OAuth providers as they typically verify emails
    return true;
  }

  /**
   * Check if user account is active
   * @param user - User entity
   * @returns True if user is active
   */
  private isUserActive(user: User): boolean {
    const userObject = user.toObject();
    return userObject['status'] === UserStatus.ACTIVE;
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
   * Handle social login errors
   * @param error - Error that occurred during social login
   * @param provider - OAuth provider name
   */
  private handleSocialLoginError(error: any, provider: string): void {
    if (error.message === 'Social login validation failed') {
      // Validation errors already presented
      return;
    }

    // Log error for debugging (in real implementation)
    console.error(`${provider} OAuth error:`, error);

    // Present provider-specific error to user
    if (error.message.includes('OAuth authentication failed')) {
      this.presenter.presentSocialLoginFailure(
        provider,
        `${provider} authentication failed. Please try again.`
      );
    } else if (error.message.includes('Account already exists with different provider')) {
      this.presenter.presentSocialLoginFailure(
        provider,
        'An account with this email already exists with a different sign-in method. Please use your original sign-in method.'
      );
    } else {
      this.presenter.presentSocialLoginFailure(
        provider,
        `${provider} sign-in failed due to an internal error. Please try again.`
      );
    }
  }
}