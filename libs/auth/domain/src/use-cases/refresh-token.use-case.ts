import {
  RefreshTokenRequest,
  RefreshTokenResponse,
  TokenType,
} from '@auth/shared';
import { User } from '../entities/user.entity';
import { Token } from '../entities/token.entity';
import { AuthSession } from '../entities/auth-session.entity';
import { UserRepository } from '../ports/repositories/user.repository';
import { TokenRepository } from '../ports/repositories/token.repository';
import { AuthSessionRepository } from '../ports/repositories/auth-session.repository';
import { TokenService } from '../ports/services/token.service';
import { AuthPresenter } from '../ports/presenters/auth.presenter';

/**
 * Refresh Token Use Case
 * 
 * Handles secure token refresh with token rotation and validation.
 * Implements security best practices including token revocation and session validation.
 */
export class RefreshTokenUseCase {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly tokenRepository: TokenRepository,
    private readonly sessionRepository: AuthSessionRepository,
    private readonly tokenService: TokenService,
    private readonly presenter: AuthPresenter
  ) {}

  /**
   * Execute token refresh
   * @param request - Token refresh request data
   */
  async execute(request: RefreshTokenRequest): Promise<void> {
    try {
      // 1. Validate input
      this.validateRefreshInput(request);

      // 2. Find and validate refresh token
      const refreshToken = await this.tokenRepository.findByValue(request.refreshToken);
      if (!refreshToken || !refreshToken.isValid()) {
        this.presenter.presentTokenRefreshFailure('Invalid or expired refresh token');
        return;
      }

      // 3. Validate token type
      if (refreshToken.type !== TokenType.REFRESH) {
        this.presenter.presentTokenRefreshFailure('Invalid token type');
        return;
      }

      // 4. Find user associated with token
      const user = await this.userRepository.findById(refreshToken.userId);
      if (!user) {
        this.presenter.presentTokenRefreshFailure('User not found');
        await this.revokeTokenAndRelated(refreshToken);
        return;
      }

      // 5. Check user account status
      if (!this.isUserActive(user)) {
        this.presenter.presentTokenRefreshFailure('Account is not active');
        await this.revokeTokenAndRelated(refreshToken);
        return;
      }

      // 6. Validate token service signature (additional security check)
      const tokenValidationResult = await this.tokenService.validateToken(request.refreshToken);
      if (!tokenValidationResult.isValid) {
        this.presenter.presentTokenRefreshFailure('Token validation failed');
        await this.revokeTokenAndRelated(refreshToken);
        return;
      }

      // 7. Find and validate active session (if client info provided)
      if (request.clientInfo) {
        const isSessionValid = await this.validateUserSession(user.id, request.clientInfo);
        if (!isSessionValid) {
          this.presenter.presentTokenRefreshFailure('Session validation failed');
          await this.revokeTokenAndRelated(refreshToken);
          return;
        }
      }

      // 8. Generate new tokens (token rotation)
      const newAccessTokenValue = await this.tokenService.generateAccessToken(
        user.id,
        user.email,
        '15m'
      );
      const newRefreshTokenValue = await this.tokenService.generateRefreshToken(
        user.id,
        user.email,
        '7d'
      );

      // 9. Create new token entities
      const newAccessToken = Token.createAccessToken({
        id: this.generateTokenId('access'),
        userId: user.id,
        value: newAccessTokenValue,
        expirationMinutes: 15,
      });

      const newRefreshToken = Token.createRefreshToken({
        id: this.generateTokenId('refresh'),
        userId: user.id,
        value: newRefreshTokenValue,
        expirationDays: 7,
      });

      // 10. Revoke old refresh token (token rotation security)
      refreshToken.revoke();

      // 11. Save tokens atomically
      await Promise.all([
        this.tokenRepository.save(newAccessToken),
        this.tokenRepository.save(newRefreshToken),
        this.tokenRepository.save(refreshToken), // Save revoked token
      ]);

      // 12. Update existing sessions with new access token
      await this.updateActiveSessionsWithNewToken(user.id, newAccessTokenValue);

      // 13. Clean up expired tokens (housekeeping)
      await this.cleanupExpiredTokens(user.id);

      // 14. Present success response
      const response: RefreshTokenResponse = {
        tokens: {
          accessToken: newAccessTokenValue,
          refreshToken: newRefreshTokenValue,
          expiresIn: 15 * 60, // 15 minutes in seconds
        },
      };

      this.presenter.presentTokenRefreshSuccess(response);
    } catch (error) {
      this.handleRefreshError(error);
    }
  }

  /**
   * Validate refresh token input
   * @param request - Refresh token request data
   */
  private validateRefreshInput(request: RefreshTokenRequest): void {
    if (!request.refreshToken || request.refreshToken === undefined) {
      this.presenter.presentTokenRefreshFailure('Refresh token is required');
      throw new Error('Refresh token validation failed');
    }

    if (typeof request.refreshToken !== 'string' || request.refreshToken.trim().length === 0) {
      this.presenter.presentTokenRefreshFailure('Invalid refresh token format');
      throw new Error('Refresh token validation failed');
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
   * Validate user session with client information
   * @param userId - User ID
   * @param clientInfo - Client information from request
   * @returns True if session is valid
   */
  private async validateUserSession(userId: string, clientInfo: any): Promise<boolean> {
    try {
      const activeSessions = await this.sessionRepository.findActiveByUserId(userId);
      
      if (activeSessions.length === 0) {
        return false;
      }

      // Check if there's a session matching the client info
      const matchingSession = activeSessions.find(session => {
        const sessionObject = session.toObject();
        const sessionClientInfo = sessionObject['clientInfo'];
        
        return (
          sessionClientInfo &&
          sessionClientInfo.ipAddress === clientInfo.ipAddress &&
          sessionClientInfo.userAgent === clientInfo.userAgent
        );
      });

      return !!matchingSession && matchingSession.isValid();
    } catch (error) {
      console.error('Session validation error:', error);
      return false;
    }
  }

  /**
   * Revoke token and related tokens/sessions
   * @param token - Token to revoke
   */
  private async revokeTokenAndRelated(token: Token): Promise<void> {
    try {
      // Revoke the token
      token.revoke();
      await this.tokenRepository.save(token);

      // Revoke all tokens for the user (security measure)
      await this.tokenRepository.revokeByUserId(token.userId);

      // Invalidate all sessions for the user
      await this.sessionRepository.invalidateByUserId(token.userId);
    } catch (error) {
      console.error('Error revoking tokens and sessions:', error);
    }
  }

  /**
   * Update active sessions with new access token
   * @param userId - User ID
   * @param newAccessToken - New access token value
   */
  private async updateActiveSessionsWithNewToken(userId: string, newAccessToken: string): Promise<void> {
    try {
      const activeSessions = await this.sessionRepository.findActiveByUserId(userId);
      
      for (const session of activeSessions) {
        if (session.isValid()) {
          // Update session activity
          session.updateActivity();
          await this.sessionRepository.save(session);
        }
      }
    } catch (error) {
      console.error('Error updating sessions:', error);
    }
  }

  /**
   * Clean up expired tokens for user
   * @param userId - User ID
   */
  private async cleanupExpiredTokens(userId: string): Promise<void> {
    try {
      // Delete expired tokens for this user
      const userTokens = await this.tokenRepository.findByUserId(userId);
      const expiredTokens = userTokens.filter(token => token.isExpired());
      
      for (const expiredToken of expiredTokens) {
        await this.tokenRepository.delete(expiredToken.id);
      }
    } catch (error) {
      console.error('Error cleaning up expired tokens:', error);
    }
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
   * Handle refresh token errors
   * @param error - Error that occurred during refresh
   */
  private handleRefreshError(error: any): void {
    if (error.message === 'Refresh token validation failed') {
      // Validation errors already presented
      return;
    }

    // Log error for debugging (in real implementation)
    console.error('Token refresh error:', error);

    // Present generic error to user
    this.presenter.presentTokenRefreshFailure(
      'Token refresh failed due to an internal error'
    );
  }
}