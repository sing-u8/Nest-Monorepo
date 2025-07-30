import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';

// Use Cases
import { SocialLoginUseCase } from '../../domain/use-cases/social-login.use-case';

// Domain
import { AuthProvider } from '../../domain/entities/user.entity';

export interface GoogleProfile {
  id: string;
  displayName: string;
  name?: {
    familyName?: string;
    givenName?: string;
  };
  emails?: Array<{
    value: string;
    verified?: boolean;
  }>;
  photos?: Array<{
    value: string;
  }>;
  provider: string;
  _raw: string;
  _json: any;
}

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private readonly configService: ConfigService,
    private readonly socialLoginUseCase: SocialLoginUseCase,
  ) {
    super({
      clientID: configService.get<string>('oauth.google.clientId'),
      clientSecret: configService.get<string>('oauth.google.clientSecret'),
      callbackURL: configService.get<string>('oauth.google.callbackUrl'),
      scope: ['email', 'profile'],
      passReqToCallback: true,
    });
  }

  /**
   * Validate Google OAuth callback
   * This method is called after successful Google authentication
   */
  async validate(
    request: any,
    accessToken: string,
    refreshToken: string,
    profile: GoogleProfile,
    done: VerifyCallback,
  ): Promise<any> {
    try {
      // Extract user information from Google profile
      const email = profile.emails?.[0]?.value;
      const emailVerified = profile.emails?.[0]?.verified ?? false;
      const name = profile.displayName || 
                   `${profile.name?.givenName || ''} ${profile.name?.familyName || ''}`.trim();
      const profilePicture = profile.photos?.[0]?.value;

      if (!email) {
        return done(new Error('No email found in Google profile'), null);
      }

      // Extract client info from request
      const clientInfo = {
        userAgent: request.headers['user-agent'] || 'Unknown',
        ipAddress: this.getClientIpAddress(request),
        deviceId: request.headers['x-device-id'] || null,
      };

      // Process social login through use case
      const result = await this.socialLoginUseCase.execute({
        provider: AuthProvider.GOOGLE,
        providerId: profile.id,
        email,
        emailVerified,
        name: name || email.split('@')[0],
        profilePicture,
        accessToken,
        refreshToken,
        clientInfo,
      });

      // Return user and tokens
      // This will be available in the controller via req.user
      const user = {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        sessionId: result.sessionId,
        isNewUser: result.isNewUser,
      };

      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }

  /**
   * Extract client IP address from request
   */
  private getClientIpAddress(request: any): string {
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