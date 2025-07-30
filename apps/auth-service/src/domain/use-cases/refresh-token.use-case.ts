import { Injectable, Inject } from '@nestjs/common';
import { UserRepository } from '../ports/user.repository';
import { TokenRepository } from '../ports/token.repository';
import { AuthSessionRepository } from '../ports/auth-session.repository';
import { TokenService } from '../ports/token.service';
import { RefreshTokenRequest, RefreshTokenResponse } from '../models/auth.models';
import { TokenType } from '@auth/shared/types/auth.types';

export class InvalidRefreshTokenError extends Error {
  constructor(message: string = 'Invalid or expired refresh token') {
    super(message);
    this.name = 'InvalidRefreshTokenError';
  }
}

export class TokenExpiredError extends Error {
  constructor(message: string = 'Refresh token has expired') {
    super(message);
    this.name = 'TokenExpiredError';
  }
}

export class UserNotActiveError extends Error {
  constructor(message: string = 'User account is not active') {
    super(message);
    this.name = 'UserNotActiveError';
  }
}

@Injectable()
export class RefreshTokenUseCase {
  constructor(
    @Inject('UserRepository')
    private readonly userRepository: UserRepository,
    @Inject('TokenRepository')
    private readonly tokenRepository: TokenRepository,
    @Inject('AuthSessionRepository')
    private readonly authSessionRepository: AuthSessionRepository,
    @Inject('TokenService')
    private readonly tokenService: TokenService,
  ) {}

  async execute(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // Validate input
    this.validateRequest(request);

    // Find and validate refresh token
    const refreshToken = await this.tokenRepository.findByValue(request.refreshToken);
    if (!refreshToken) {
      throw new InvalidRefreshTokenError('Refresh token not found');
    }

    // Check if token is valid (not expired and not revoked)
    if (!refreshToken.isValid()) {
      throw new InvalidRefreshTokenError('Refresh token is invalid or revoked');
    }

    if (refreshToken.isExpired()) {
      throw new TokenExpiredError('Refresh token has expired');
    }

    // Verify token signature and extract payload
    const tokenPayload = await this.tokenService.verifyToken(refreshToken.getValue(), TokenType.REFRESH);
    if (!tokenPayload || tokenPayload.type !== TokenType.REFRESH) {
      throw new InvalidRefreshTokenError('Invalid refresh token format');
    }

    // Get user from token payload
    const user = await this.userRepository.findById(tokenPayload.userId);
    if (!user) {
      throw new InvalidRefreshTokenError('User not found for refresh token');
    }

    // Check if user is still active
    if (!user.isAccountActive()) {
      throw new UserNotActiveError('User account is deactivated');
    }

    // Find associated session
    const session = await this.authSessionRepository.findByUserId(user.id);
    if (!session || !session.isValid()) {
      throw new InvalidRefreshTokenError('No valid session found');
    }

    // Revoke old refresh token (token rotation for security)
    refreshToken.revoke();
    await this.tokenRepository.save(refreshToken);

    // Revoke all existing tokens for this user (optional: can be configured)
    await this.tokenRepository.revokeAllByUserId(user.id);

    // Generate new token pair
    const newTokens = await this.tokenService.generateTokenPair({
      userId: user.id,
      email: user.email,
      type: TokenType.ACCESS,
      sessionId: session.id,
    });

    // Save new tokens to repository
    await this.tokenRepository.save(newTokens.accessToken);
    await this.tokenRepository.save(newTokens.refreshToken);

    // Update session activity
    if (request.clientInfo) {
      session.updateActivity(request.clientInfo);
      await this.authSessionRepository.save(session);
    }

    return {
      accessToken: newTokens.accessToken.getValue(),
      refreshToken: newTokens.refreshToken.getValue(),
      sessionId: session.id,
      expiresAt: newTokens.accessToken.getExpiresAt(),
    };
  }

  private validateRequest(request: RefreshTokenRequest): void {
    if (!request.refreshToken || request.refreshToken.trim().length === 0) {
      throw new Error('Refresh token is required');
    }

    // Validate token format (basic JWT structure check)
    const tokenParts = request.refreshToken.split('.');
    if (tokenParts.length !== 3) {
      throw new InvalidRefreshTokenError('Invalid refresh token format');
    }
  }
}