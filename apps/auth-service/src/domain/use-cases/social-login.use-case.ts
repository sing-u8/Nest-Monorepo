import { Injectable, Inject } from '@nestjs/common';
import { User } from '../entities/user.entity';
import { AuthSession } from '../entities/auth-session.entity';
import { UserRepository } from '../ports/user.repository';
import { TokenRepository } from '../ports/token.repository';
import { AuthSessionRepository } from '../ports/auth-session.repository';
import { TokenService } from '../ports/token.service';
import { GoogleOAuthService } from '../ports/google-oauth.service';
import { AppleOAuthService } from '../ports/apple-oauth.service';
import { SocialLoginRequest, SocialLoginResponse } from '../models/auth.models';
import { AuthProvider, TokenType } from '@auth/shared/types/auth.types';

export class UnsupportedProviderError extends Error {
  constructor(provider: string) {
    super(`Unsupported OAuth provider: ${provider}`);
    this.name = 'UnsupportedProviderError';
  }
}

export class OAuthAuthorizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OAuthAuthorizationError';
  }
}

export class OAuthUserInfoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OAuthUserInfoError';
  }
}

export class InvalidOAuthTokenError extends Error {
  constructor(message: string) {
    super(message);
  }
}

@Injectable()
export class SocialLoginUseCase {
  constructor(
    @Inject('UserRepository')
    private readonly userRepository: UserRepository,
    @Inject('TokenRepository')
    private readonly tokenRepository: TokenRepository,
    @Inject('AuthSessionRepository')
    private readonly authSessionRepository: AuthSessionRepository,
    @Inject('TokenService')
    private readonly tokenService: TokenService,
    @Inject('GoogleOAuthService')
    private readonly googleOAuthService: GoogleOAuthService,
    @Inject('AppleOAuthService')
    private readonly appleOAuthService: AppleOAuthService,
  ) {}

  async execute(request: SocialLoginRequest): Promise<SocialLoginResponse> {
    // Validate input
    this.validateRequest(request);

    let userInfo: any;
    let providerId: string;

    try {
      // Handle OAuth flow based on provider
      switch (request.provider) {
        case AuthProvider.GOOGLE:
          userInfo = await this.handleGoogleOAuth(request);
          providerId = userInfo.id;
          break;
        case AuthProvider.APPLE:
          userInfo = await this.handleAppleOAuth(request);
          providerId = userInfo.sub; // Apple uses 'sub' as user identifier
          break;
        default:
          throw new UnsupportedProviderError(request.provider);
      }
    } catch (error) {
      if (error instanceof UnsupportedProviderError) {
        throw error;
      }
      throw new OAuthAuthorizationError(`OAuth authentication failed: ${error.message}`);
    }

    // Check if user already exists by provider
    let user = await this.userRepository.findByProvider(request.provider, providerId);
    let isNewUser = false;

    if (!user) {
      // Check if user exists by email (linking existing account)
      const existingUser = await this.userRepository.findByEmail(userInfo.email);
      
      if (existingUser) {
        // Link social account to existing user
        // Note: In production, this should require user confirmation
        user = existingUser;
      } else {
        // Create new user from social login
        user = this.createUserFromSocialInfo(userInfo, request.provider, providerId);
        user = await this.userRepository.save(user);
        isNewUser = true;
      }
    }

    // Check if user account is active
    if (!user.isAccountActive()) {
      throw new Error('User account is deactivated');
    }

    // Create new auth session
    const sessionToken = this.generateSessionToken();
    const authSession = new AuthSession(
      this.generateSessionId(),
      user.id,
      sessionToken,
      request.clientInfo,
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    );

    await this.authSessionRepository.save(authSession);

    // Revoke existing tokens for security (optional, can be configured)
    await this.tokenRepository.revokeAllByUserId(user.id);

    // Generate new token pair
    const tokenPair = await this.tokenService.generateTokenPair({
      userId: user.id,
      email: user.email,
      type: TokenType.ACCESS,
      sessionId: authSession.id,
      provider: request.provider,
    });

    // Save tokens
    await this.tokenRepository.save(tokenPair.accessToken);
    await this.tokenRepository.save(tokenPair.refreshToken);

    return {
      accessToken: tokenPair.accessToken.getValue(),
      refreshToken: tokenPair.refreshToken.getValue(),
      sessionId: authSession.id,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        profilePicture: user.profilePicture,
        provider: user.provider,
        isActive: user.isAccountActive(),
      },
      isNewUser,
      expiresAt: tokenPair.accessToken.getExpiresAt(),
    };
  }

  private async handleGoogleOAuth(request: SocialLoginRequest): Promise<any> {
    if (!request.authorizationCode) {
      throw new OAuthAuthorizationError('Google authorization code is required');
    }

    try {
      // Exchange authorization code for access token
      const tokens = await this.googleOAuthService.exchangeCodeForTokens(request.authorizationCode);
      
      // Get user info from Google
      const userInfo = await this.googleOAuthService.getUserInfo(tokens.access_token);
      
      if (!userInfo || !userInfo.email) {
        throw new OAuthUserInfoError('Failed to retrieve user information from Google');
      }

      return userInfo;
    } catch (error) {
      throw new OAuthAuthorizationError(`Google OAuth failed: ${error.message}`);
    }
  }

  private async handleAppleOAuth(request: SocialLoginRequest): Promise<any> {
    if (!request.idToken) {
      throw new OAuthAuthorizationError('Apple ID token is required');
    }

    try {
      // Verify Apple ID token
      const isValid = await this.appleOAuthService.verifyIdToken(request.idToken);
      if (!isValid) {
        throw new InvalidOAuthTokenError('Invalid Apple ID token');
      }

      // Extract user info from ID token
      const userInfo = await this.appleOAuthService.extractUserInfo(request.idToken, request.userInfo);
      
      if (!userInfo || !userInfo.email) {
        throw new OAuthUserInfoError('Failed to extract user information from Apple ID token');
      }

      return userInfo;
    } catch (error) {
      throw new OAuthAuthorizationError(`Apple OAuth failed: ${error.message}`);
    }
  }

  private createUserFromSocialInfo(userInfo: any, provider: AuthProvider, providerId: string): User {
    const user = new User(
      this.generateUserId(),
      userInfo.email,
      '', // No password for social users
      userInfo.name || userInfo.given_name + ' ' + userInfo.family_name || 'Social User',
      userInfo.picture || userInfo.profilePicture,
      provider,
      providerId,
    );

    return user;
  }

  private validateRequest(request: SocialLoginRequest): void {
    if (!request.provider) {
      throw new Error('OAuth provider is required');
    }

    if (!Object.values(AuthProvider).includes(request.provider)) {
      throw new UnsupportedProviderError(request.provider);
    }

    switch (request.provider) {
      case AuthProvider.GOOGLE:
        if (!request.authorizationCode) {
          throw new Error('Authorization code is required for Google OAuth');
        }
        break;
      case AuthProvider.APPLE:
        if (!request.idToken) {
          throw new Error('ID token is required for Apple OAuth');
        }
        break;
    }
  }

  private generateUserId(): string {
    return `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateSessionId(): string {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateSessionToken(): string {
    return `token_${Date.now()}_${Math.random().toString(36).substr(2, 16)}`;
  }
}