import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-custom';
import { SocialLoginUseCase } from '@auth/domain';
import { AppleOAuthService } from '../services';
import { Request } from 'express';

/**
 * Apple Sign In Passport Strategy
 * 
 * Custom Passport strategy for Apple Sign In authentication.
 * Unlike traditional OAuth flows, Apple Sign In uses ID tokens
 * and has specific requirements for client secret generation.
 * 
 * This strategy validates Apple ID tokens and creates/updates
 * user accounts using the SocialLoginUseCase.
 */
@Injectable()
export class AppleStrategy extends PassportStrategy(Strategy, 'apple') {
  private readonly logger = new Logger(AppleStrategy.name);

  constructor(
    private readonly socialLoginUseCase: SocialLoginUseCase,
    private readonly appleOAuthService: AppleOAuthService,
  ) {
    super();

    // Validate required configuration
    this.validateConfiguration();
  }

  /**
   * Custom validation method for Apple Sign In
   * Called by Passport when authenticating with this strategy
   */
  async validate(request: Request): Promise<any> {
    try {
      this.logger.debug('Apple Sign In validation started');

      // Extract Apple Sign In data from request
      const { code, id_token, user, state } = request.body;

      // Validate required parameters
      if (!id_token) {
        throw new Error('Apple ID token is required');
      }

      // Extract nonce from state if present
      const nonce = this.extractNonceFromState(state);

      // Validate the Apple ID token
      const appleProfile = await this.appleOAuthService.validateIdToken(id_token, nonce);

      // Extract user information from Apple's user parameter (first-time sign-in only)
      const additionalUserInfo = this.parseAppleUserInfo(user);

      // Merge profile information
      const mergedProfile = this.mergeAppleProfileInfo(appleProfile, additionalUserInfo);

      // Extract client information from request
      const clientInfo = {
        userAgent: request.headers['user-agent'] || 'unknown',
        ipAddress: this.extractClientIP(request),
        deviceId: request.headers['x-device-id'] as string || undefined,
      };

      // Create social login request
      const socialLoginRequest = {
        provider: 'apple' as const,
        authorizationCode: code,
        idToken: id_token,
        profile: mergedProfile,
        clientInfo,
        state,
      };

      // Execute social login use case
      const result = await this.socialLoginUseCase.execute(socialLoginRequest);

      this.logger.log(`Apple Sign In successful for user: ${result.user.id}`);

      // Return user data to Passport
      return {
        id: result.user.id,
        email: result.user.email,
        name: result.user.name,
        provider: result.user.provider,
        isNewUser: result.user.isNewUser,
        tokens: result.tokens,
        session: result.session,
      };

    } catch (error) {
      this.logger.error('Apple Sign In validation failed', {
        error: error.message,
        stack: error.stack,
      });

      throw error;
    }
  }

  /**
   * Extract nonce from state parameter
   * State format: "originalState|redirectUri|nonce"
   */
  private extractNonceFromState(state?: string): string | undefined {
    if (!state) return undefined;

    const parts = state.split('|');
    if (parts.length >= 3) {
      // Try to decode base64 encoded nonce
      try {
        return Buffer.from(parts[2], 'base64').toString();
      } catch {
        return parts[2]; // Return as-is if not base64 encoded
      }
    }

    return undefined;
  }

  /**
   * Parse Apple user information from the 'user' parameter
   * This is only provided on first-time sign-in
   */
  private parseAppleUserInfo(userParam?: string): any {
    if (!userParam) return {};

    try {
      const userInfo = typeof userParam === 'string' ? JSON.parse(userParam) : userParam;
      
      return {
        name: this.constructAppleName(userInfo.name),
        email: userInfo.email,
        emailVerified: true, // Apple emails are always verified
      };
    } catch (error) {
      this.logger.warn('Failed to parse Apple user info', { error: error.message });
      return {};
    }
  }

  /**
   * Construct full name from Apple name object
   */
  private constructAppleName(nameObj?: any): string {
    if (!nameObj) return '';

    const parts = [];
    if (nameObj.firstName) parts.push(nameObj.firstName);
    if (nameObj.lastName) parts.push(nameObj.lastName);

    return parts.join(' ');
  }

  /**
   * Merge Apple profile information from ID token and user parameter
   */
  private mergeAppleProfileInfo(idTokenProfile: any, userInfo: any): any {
    return {
      id: idTokenProfile.id,
      email: userInfo.email || idTokenProfile.email,
      emailVerified: idTokenProfile.emailVerified || userInfo.emailVerified || true,
      name: userInfo.name || idTokenProfile.name,
      isPrivateEmail: idTokenProfile.isPrivateEmail,
      realUserStatus: idTokenProfile.realUserStatus,
      // Apple doesn't provide profile pictures in Sign In
      picture: null,
      // Store raw Apple data for debugging
      rawProfile: {
        idToken: idTokenProfile,
        userInfo: userInfo,
      },
    };
  }

  /**
   * Extract client IP address from request
   */
  private extractClientIP(request: Request): string {
    return (
      (request.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (request.headers['x-real-ip'] as string) ||
      request.connection?.remoteAddress ||
      request.socket?.remoteAddress ||
      'unknown'
    );
  }

  /**
   * Validate required configuration
   */
  private validateConfiguration(): void {
    const requiredEnvVars = [
      'APPLE_CLIENT_ID',
      'APPLE_TEAM_ID',
      'APPLE_KEY_ID',
      'APPLE_PRIVATE_KEY',
    ];

    const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

    if (missingVars.length > 0) {
      const error = `Missing required environment variables for Apple Sign In: ${missingVars.join(', ')}`;
      this.logger.error(error);
      throw new Error(error);
    }

    // Validate Apple Client ID format (should be a bundle identifier)
    const clientId = process.env.APPLE_CLIENT_ID;
    if (clientId && !clientId.includes('.')) {
      this.logger.warn('Apple Client ID should be a bundle identifier (e.g., com.example.app)');
    }

    // Validate Apple Team ID format (should be 10 characters)
    const teamId = process.env.APPLE_TEAM_ID;
    if (teamId && teamId.length !== 10) {
      this.logger.warn('Apple Team ID should be exactly 10 characters');
    }

    // Validate Apple Key ID format (should be 10 characters)
    const keyId = process.env.APPLE_KEY_ID;
    if (keyId && keyId.length !== 10) {
      this.logger.warn('Apple Key ID should be exactly 10 characters');
    }

    // Validate private key format
    const privateKey = process.env.APPLE_PRIVATE_KEY;
    if (privateKey && !privateKey.includes('BEGIN EC PRIVATE KEY')) {
      this.logger.warn('Apple Private Key should be in PEM format');
    }

    // Log configuration (without sensitive data)
    this.logger.log('Apple Sign In strategy configured', {
      clientId: clientId?.substring(0, 20) + '...',
      teamId: teamId?.substring(0, 3) + '...',
      keyId: keyId?.substring(0, 3) + '...',
      hasPrivateKey: !!privateKey,
    });
  }
}