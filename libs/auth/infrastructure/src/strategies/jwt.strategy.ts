import { Injectable, Logger, UnauthorizedException, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UserRepository } from '@auth/domain';

/**
 * JWT Passport Strategy
 * 
 * Passport strategy for validating JWT tokens and loading user information.
 * This strategy is used with the @UseGuards(AuthGuard('jwt')) decorator
 * to protect routes that require authentication.
 * 
 * The strategy extracts JWT tokens from the Authorization header,
 * validates them, and loads the corresponding user from the database.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(@Inject('UserRepository') private readonly userRepository: UserRepository) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env['JWT_PUBLIC_KEY'] || process.env['JWT_SECRET'],
      algorithms: ['RS256', 'HS256'], // Support both RSA and HMAC
      issuer: process.env['JWT_ISSUER'] || 'auth-service',
      audience: process.env['JWT_AUDIENCE'] || 'auth-service-api',
      passReqToCallback: true, // Pass request object to validate method
    });

    // Validate JWT configuration
    this.validateConfiguration();
  }

  /**
   * Passport validate method
   * Called after successful JWT token verification
   */
  async validate(request: any, payload: any): Promise<any> {
    try {
      this.logger.debug(`JWT validation for user: ${payload.sub}`);

      // Validate required payload fields
      if (!payload.sub || !payload.email) {
        this.logger.warn('Invalid JWT payload structure', { payload });
        throw new UnauthorizedException('Invalid token payload');
      }

      // Additional expiration check (redundant but safe)
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        this.logger.warn('JWT token expired', { exp: payload.exp, now });
        throw new UnauthorizedException('Token has expired');
      }

      // Load user from database to ensure they still exist and are active
      const user = await this.userRepository.findById(payload.sub);
      if (!user) {
        this.logger.warn(`User not found for JWT: ${payload.sub}`);
        throw new UnauthorizedException('User not found');
      }

      // Check if user account is active
      if (!user.isAccountActive()) {
        this.logger.warn(`Inactive user attempted access: ${payload.sub}`, {
          status: user.getStatus(),
        });
        throw new UnauthorizedException('User account is not active');
      }

      // Check if user email matches token (additional security)
      if (user.email !== payload.email) {
        this.logger.warn(`Email mismatch for user: ${payload.sub}`, {
          tokenEmail: payload.email,
          userEmail: user.email,
        });
        throw new UnauthorizedException('Token email mismatch');
      }

      // Extract additional information from request
      const clientInfo = {
        userAgent: request.headers['user-agent'] || 'unknown',
        ipAddress: this.extractClientIP(request),
        deviceId: request.headers['x-device-id'] as string || undefined,
      };

      this.logger.debug(`JWT validation successful for user: ${user.id}`);

      // Return user information that will be attached to request.user
      return {
        id: user.id,
        email: user.email,
        name: user.name,
        status: user.getStatus(),
        provider: user.provider,
        emailVerified: true, // JWT users are considered verified
        lastLoginAt: user.getUpdatedAt(),
        // Include token claims for additional context
        tokenClaims: {
          iat: payload.iat,
          exp: payload.exp,
          iss: payload.iss,
          aud: payload.aud,
          scope: payload.scope,
          permissions: payload.permissions,
        },
        // Include client information
        clientInfo,
      };

    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      this.logger.error('JWT validation error', {
        error: (error as Error).message,
        userId: payload?.sub,
        stack: (error as Error).stack,
      });

      throw new UnauthorizedException('JWT validation failed');
    }
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
   * Validate JWT configuration
   */
  private validateConfiguration(): void {
    const publicKey = process.env['JWT_PUBLIC_KEY'];
    const secret = process.env['JWT_SECRET'];

    if (!publicKey && !secret) {
      const error = 'JWT_PUBLIC_KEY or JWT_SECRET environment variable is required';
      this.logger.error(error);
      throw new Error(error);
    }

    // Warn if using HMAC in production
    if (secret && !publicKey && process.env['NODE_ENV'] === 'production') {
      this.logger.warn('Using HMAC (JWT_SECRET) in production. Consider using RSA (JWT_PUBLIC_KEY) for better security.');
    }

    // Validate RSA public key format
    if (publicKey && !publicKey.includes('BEGIN PUBLIC KEY')) {
      this.logger.warn('JWT_PUBLIC_KEY should be in PEM format');
    }

    // Log configuration (without sensitive data)
    this.logger.log('JWT strategy configured', {
      algorithm: publicKey ? 'RS256' : 'HS256',
      issuer: process.env['JWT_ISSUER'] || 'auth-service',
      audience: process.env['JWT_AUDIENCE'] || 'auth-service-api',
      hasPublicKey: !!publicKey,
      hasSecret: !!secret,
    });
  }
}