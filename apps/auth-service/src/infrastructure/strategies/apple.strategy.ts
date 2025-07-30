import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-custom';
import { ConfigService } from '@nestjs/config';

// Use Cases
import { SocialLoginUseCase } from '../../domain/use-cases/social-login.use-case';

// Services
import { AppleOAuthService } from '../../domain/ports/apple-oauth.service';

// Domain
import { AuthProvider } from '../../domain/entities/user.entity';

export interface AppleAuthRequest {
  body: {
    code?: string;
    id_token?: string;
    state?: string;
    user?: string; // JSON string with user data (first sign in only)
  };
  headers: {
    [key: string]: string;
  };
  connection?: {
    remoteAddress?: string;
  };
  socket?: {
    remoteAddress?: string;
  };
}

@Injectable()
export class AppleStrategy extends PassportStrategy(Strategy, 'apple') {
  constructor(
    private readonly configService: ConfigService,
    private readonly socialLoginUseCase: SocialLoginUseCase,
    private readonly appleOAuthService: AppleOAuthService,
  ) {
    super();
  }

  /**
   * Validate Apple Sign In callback
   * Apple uses form POST for callbacks, so we need custom handling
   */
  async validate(request: AppleAuthRequest): Promise<any> {
    try {
      const { code, id_token: idToken, state, user } = request.body;

      if (!idToken) {
        throw new Error('No ID token provided by Apple');
      }

      // Verify ID token with Apple
      const isValidToken = await this.appleOAuthService.verifyIdToken(idToken);
      if (!isValidToken) {
        throw new Error('Invalid Apple ID token');
      }

      // Parse user data if provided (first time sign in)
      let userData;
      if (user) {
        try {
          userData = typeof user === 'string' ? JSON.parse(user) : user;
        } catch (error) {
          // Ignore parsing errors for user data
          userData = null;
        }
      }

      // Extract user info from ID token
      const userInfo = await this.appleOAuthService.extractUserInfo(idToken, userData);

      if (!userInfo.email) {
        throw new Error('No email found in Apple ID token');
      }

      // Extract client info from request
      const clientInfo = {
        userAgent: request.headers['user-agent'] || 'Unknown',
        ipAddress: this.getClientIpAddress(request),
        deviceId: request.headers['x-device-id'] || null,
      };

      // Process social login through use case
      const result = await this.socialLoginUseCase.execute({
        provider: AuthProvider.APPLE,
        providerId: userInfo.sub,
        email: userInfo.email,
        emailVerified: userInfo.email_verified,
        name: userInfo.name || userInfo.email.split('@')[0],
        profilePicture: undefined, // Apple doesn't provide profile pictures
        code,
        idToken,
        state,
        clientInfo,
      });

      // Return user and tokens
      return {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        sessionId: result.sessionId,
        isNewUser: result.isNewUser,
      };
    } catch (error) {
      throw error;
    }
  }

  /**
   * Extract client IP address from request
   */
  private getClientIpAddress(request: AppleAuthRequest): string {
    const forwarded = request.headers['x-forwarded-for'];
    const realIp = request.headers['x-real-ip'];
    
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
    
    if (realIp) {
      return realIp;
    }
    
    return request.connection?.remoteAddress || 
           request.socket?.remoteAddress || 
           'Unknown';
  }
}