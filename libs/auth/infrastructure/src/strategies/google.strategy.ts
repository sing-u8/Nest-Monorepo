import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { SocialLoginUseCase } from '@auth/domain';

/**
 * Google OAuth 2.0 Passport Strategy
 * 
 * Integrates with Passport.js to handle Google OAuth authentication.
 * This strategy is used for server-side Google OAuth flows where
 * the authorization code is exchanged for tokens server-side.
 * 
 * The strategy validates the Google OAuth tokens and creates/updates
 * user accounts using the SocialLoginUseCase.
 */
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor(private readonly socialLoginUseCase: SocialLoginUseCase) {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_REDIRECT_URI || '/auth/google/callback',
      scope: [
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
      ],
      passReqToCallback: true, // Pass request object to validate method
    });

    // Validate required environment variables
    this.validateConfiguration();
  }

  /**
   * Passport validate method
   * Called after successful OAuth authentication with Google
   */
  async validate(
    request: any,
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<void> {
    try {
      this.logger.debug(`Google OAuth validation for user: ${profile.id}`);

      // Extract client information from request
      const clientInfo = {
        userAgent: request.headers['user-agent'] || 'unknown',
        ipAddress: this.extractClientIP(request),
        deviceId: request.headers['x-device-id'] as string || undefined,
      };

      // Map Google profile to our profile format
      const mappedProfile = this.mapGoogleProfile(profile);

      // Create social login request
      const socialLoginRequest = {
        provider: 'google' as const,
        authorizationCode: request.query?.code || 'server-side-flow',
        idToken: profile._json?.id_token,
        accessToken,
        refreshToken,
        profile: mappedProfile,
        clientInfo,
      };

      // Execute social login use case
      const result = await this.socialLoginUseCase.execute(socialLoginRequest);

      this.logger.log(`Google OAuth successful for user: ${result.user.id}`);

      // Return user data to Passport
      // Passport will attach this to req.user
      done(null, {
        id: result.user.id,
        email: result.user.email,
        name: result.user.name,
        provider: result.user.provider,
        isNewUser: result.user.isNewUser,
        tokens: result.tokens,
        session: result.session,
      });

    } catch (error) {
      this.logger.error('Google OAuth validation failed', {
        error: error.message,
        profileId: profile.id,
        stack: error.stack,
      });

      // Return error to Passport
      done(error, null);
    }
  }

  /**
   * Map Google profile to our standardized profile format
   */
  private mapGoogleProfile(profile: any): any {
    const emails = profile.emails || [];
    const primaryEmail = emails.find((email: any) => email.type === 'primary') || emails[0];
    
    const photos = profile.photos || [];
    const primaryPhoto = photos[0];

    return {
      id: profile.id,
      email: primaryEmail?.value,
      emailVerified: primaryEmail?.verified ?? true, // Google emails are generally verified
      name: profile.displayName || this.constructName(profile.name),
      givenName: profile.name?.givenName,
      familyName: profile.name?.familyName,
      picture: primaryPhoto?.value,
      locale: profile._json?.locale,
      hostedDomain: profile._json?.hd, // Google Workspace domain
      profileUrl: profile.profileUrl,
      rawProfile: profile._json, // Store complete Google profile for debugging
    };
  }

  /**
   * Construct full name from name components
   */
  private constructName(name: any): string {
    if (!name) return '';
    
    const parts = [];
    if (name.givenName) parts.push(name.givenName);
    if (name.familyName) parts.push(name.familyName);
    
    return parts.join(' ') || '';
  }

  /**
   * Extract client IP address from request
   */
  private extractClientIP(request: any): string {
    return (
      request.headers['x-forwarded-for']?.split(',')[0] ||
      request.headers['x-real-ip'] ||
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
      'GOOGLE_CLIENT_ID',
      'GOOGLE_CLIENT_SECRET',
    ];

    const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

    if (missingVars.length > 0) {
      const error = `Missing required environment variables for Google OAuth: ${missingVars.join(', ')}`;
      this.logger.error(error);
      throw new Error(error);
    }

    // Validate client ID format (basic validation)
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (clientId && !clientId.endsWith('.googleusercontent.com')) {
      this.logger.warn('Google Client ID does not have expected format (.googleusercontent.com)');
    }

    // Log configuration (without sensitive data)
    this.logger.log('Google OAuth strategy configured', {
      clientId: clientId?.substring(0, 20) + '...',
      callbackURL: process.env.GOOGLE_REDIRECT_URI || '/auth/google/callback',
      scopes: [
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
      ],
    });
  }
}