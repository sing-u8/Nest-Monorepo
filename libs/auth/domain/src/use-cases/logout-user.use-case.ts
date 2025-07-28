import { Inject, Injectable } from '@nestjs/common';
import { UserRepository, TokenRepository, AuthSessionRepository } from '../ports/repositories';
import { TokenService } from '../ports/services';
import { LogoutUserPresenter } from '../ports/presenters';
import { LogoutUserRequest, LogoutUserResult } from '@auth/shared';

/**
 * Logout User Use Case
 * 
 * Handles user logout functionality including:
 * - Token revocation and blacklisting
 * - Session invalidation
 * - Optional logout from all devices
 * - Cleanup of expired tokens
 * 
 * Security features:
 * - Comprehensive token cleanup
 * - Session invalidation
 * - Audit logging for logout events
 * - Graceful error handling
 */
@Injectable()
export class LogoutUserUseCase {
  constructor(
    @Inject('UserRepository')
    private readonly userRepository: UserRepository,

    @Inject('TokenRepository')
    private readonly tokenRepository: TokenRepository,

    @Inject('AuthSessionRepository')
    private readonly authSessionRepository: AuthSessionRepository,

    @Inject('TokenService')
    private readonly tokenService: TokenService,

    @Inject('LogoutUserPresenter')
    private readonly presenter: LogoutUserPresenter,
  ) {}

  /**
   * Execute logout user use case
   * @param request - Logout request data
   * @returns Logout result with statistics
   */
  async execute(request: LogoutUserRequest): Promise<LogoutUserResult> {
    try {
      // 1. Validate input
      this.validateLogoutInput(request);

      // 2. Validate and decode refresh token to get user information
      const tokenValidation = await this.tokenService.validateToken(request.refreshToken);
      if (!tokenValidation.isValid || !tokenValidation.payload) {
        return this.presenter.presentInvalidRefreshToken();
      }

      const userId = tokenValidation.payload.sub;
      const userEmail = tokenValidation.payload.email;

      // 3. Get user to ensure they exist and are active
      const user = await this.userRepository.findById(userId);
      if (!user) {
        return this.presenter.presentUserNotFound();
      }

      // 4. Perform logout operations
      let sessionsClosed = 0;
      let tokensRevoked = 0;

      if (request.logoutFromAllDevices) {
        // Logout from all devices
        const logoutStats = await this.logoutFromAllDevices(userId);
        sessionsClosed = logoutStats.sessionsClosed;
        tokensRevoked = logoutStats.tokensRevoked;
      } else {
        // Logout from current device only
        const logoutStats = await this.logoutFromCurrentDevice(userId, request.refreshToken, request.clientInfo);
        sessionsClosed = logoutStats.sessionsClosed;
        tokensRevoked = logoutStats.tokensRevoked;
      }

      // 5. Cleanup expired tokens and sessions (housekeeping)
      await this.performCleanupTasks(userId);

      // 6. Create logout result
      const logoutResult: LogoutUserResult = {
        loggedOutAt: new Date(),
        sessionsClosed,
        tokensRevoked,
        user: {
          id: user.getId(),
          email: user.getEmail(),
          name: user.getName(),
        },
      };

      // 7. Present successful logout
      return this.presenter.presentLogoutSuccess(logoutResult);

    } catch (error) {
      // Log error for monitoring
      console.error('Logout use case error:', error);

      // Present error
      if (error.message?.includes('validation')) {
        return this.presenter.presentValidationError(error.message);
      }

      if (error.message?.includes('token')) {
        return this.presenter.presentInvalidRefreshToken();
      }

      return this.presenter.presentInternalError();
    }
  }

  private validateLogoutInput(request: LogoutUserRequest): void {
    if (!request) {
      throw new Error('Logout request is required');
    }

    if (!request.refreshToken || request.refreshToken.trim().length === 0) {
      throw new Error('Refresh token is required for logout');
    }

    // Basic JWT format validation
    const tokenParts = request.refreshToken.split('.');
    if (tokenParts.length !== 3) {
      throw new Error('Invalid refresh token format');
    }

    // Validate client info if provided
    if (request.clientInfo) {
      if (request.clientInfo.userAgent && request.clientInfo.userAgent.length > 1000) {
        throw new Error('User agent is too long');
      }
      
      if (request.clientInfo.ipAddress && !this.isValidIpAddress(request.clientInfo.ipAddress)) {
        throw new Error('Invalid IP address format');
      }
    }
  }

  private async logoutFromCurrentDevice(
    userId: string, 
    refreshToken: string, 
    clientInfo?: any
  ): Promise<{ sessionsClosed: number; tokensRevoked: number }> {
    let sessionsClosed = 0;
    let tokensRevoked = 0;

    try {
      // 1. Find and invalidate current session
      const sessions = await this.authSessionRepository.findActiveByUserId(userId);
      
      // Try to match session by client info
      let currentSession = null;
      if (clientInfo && sessions.length > 1) {
        currentSession = sessions.find(session => 
          session.getClientInfo()?.deviceId === clientInfo.deviceId ||
          session.getClientInfo()?.ipAddress === clientInfo.ipAddress
        );
      } else if (sessions.length > 0) {
        // If we can't match specifically, take the most recent session
        currentSession = sessions.sort((a, b) => 
          new Date(b.getLastActivity()).getTime() - new Date(a.getLastActivity()).getTime()
        )[0];
      }

      if (currentSession) {
        currentSession.invalidate();
        await this.authSessionRepository.save(currentSession);
        sessionsClosed = 1;
      }

      // 2. Revoke tokens associated with this refresh token
      const tokensToRevoke = await this.tokenRepository.findByUserId(userId);
      
      for (const token of tokensToRevoke) {
        // Revoke access tokens and the specific refresh token
        if (token.getValue() === refreshToken || token.getType() === 'access') {
          token.revoke();
          await this.tokenRepository.save(token);
          tokensRevoked++;
        }
      }

      // 3. Blacklist the refresh token
      await this.tokenService.blacklistToken(refreshToken);

    } catch (error) {
      console.error('Error during current device logout:', error);
      // Continue with best effort - don't fail the entire logout
    }

    return { sessionsClosed, tokensRevoked };
  }

  private async logoutFromAllDevices(userId: string): Promise<{ sessionsClosed: number; tokensRevoked: number }> {
    let sessionsClosed = 0;
    let tokensRevoked = 0;

    try {
      // 1. Invalidate all active sessions
      const sessions = await this.authSessionRepository.findActiveByUserId(userId);
      
      for (const session of sessions) {
        session.invalidate();
        await this.authSessionRepository.save(session);
        sessionsClosed++;
      }

      // 2. Revoke all tokens
      const tokens = await this.tokenRepository.findByUserId(userId);
      
      for (const token of tokens) {
        if (!token.isRevoked()) {
          token.revoke();
          await this.tokenRepository.save(token);
          
          // Blacklist the token if it's still valid
          if (!token.isExpired()) {
            await this.tokenService.blacklistToken(token.getValue());
          }
          
          tokensRevoked++;
        }
      }

    } catch (error) {
      console.error('Error during all devices logout:', error);
      // Continue with best effort - don't fail the entire logout
    }

    return { sessionsClosed, tokensRevoked };
  }

  private async performCleanupTasks(userId: string): Promise<void> {
    try {
      // Cleanup expired tokens
      await this.tokenRepository.deleteExpiredTokens();
      
      // Cleanup expired sessions
      await this.authSessionRepository.deleteExpiredSessions();
      
      // Remove old revoked tokens (older than 30 days)
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      await this.tokenRepository.deleteRevokedTokensOlderThan(thirtyDaysAgo);

    } catch (error) {
      // Cleanup errors should not fail the logout process
      console.warn('Cleanup tasks failed during logout:', error);
    }
  }

  private isValidIpAddress(ip: string): boolean {
    // IPv4 regex
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    
    // IPv6 regex (simplified)
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  }
}