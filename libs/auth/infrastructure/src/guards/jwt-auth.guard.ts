import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

/**
 * JWT Authentication Guard
 * 
 * Validates JWT tokens in the Authorization header and populates
 * the request object with the decoded user information.
 * 
 * Expected header format: "Bearer <token>"
 * 
 * The decoded token payload should contain:
 * - sub: User ID
 * - email: User email
 * - iat: Issued at timestamp
 * - exp: Expiration timestamp
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);

  constructor(private readonly jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    
    try {
      // Extract token from Authorization header
      const token = this.extractTokenFromHeader(request);
      if (!token) {
        this.logger.warn('No authorization token provided');
        throw new UnauthorizedException('Missing authentication token');
      }

      // Verify and decode the JWT token
      const payload = await this.jwtService.verifyAsync(token);
      
      // Validate required payload fields
      if (!payload.sub || !payload.email) {
        this.logger.warn('Invalid token payload structure', { payload });
        throw new UnauthorizedException('Invalid token payload');
      }

      // Check token expiration (additional validation)
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        this.logger.warn('Token has expired', { exp: payload.exp, now });
        throw new UnauthorizedException('Token has expired');
      }

      // Attach user information to request object
      (request as any).user = {
        sub: payload.sub,
        email: payload.email,
        iat: payload.iat,
        exp: payload.exp,
        ...payload, // Include any additional claims
      };

      this.logger.debug(`Authentication successful for user: ${payload.sub}`);
      return true;

    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      // Handle JWT-specific errors
      if (error.name === 'JsonWebTokenError') {
        this.logger.warn('Invalid JWT token', { error: error.message });
        throw new UnauthorizedException('Invalid authentication token');
      }

      if (error.name === 'TokenExpiredError') {
        this.logger.warn('JWT token expired', { error: error.message });
        throw new UnauthorizedException('Authentication token has expired');
      }

      if (error.name === 'NotBeforeError') {
        this.logger.warn('JWT token not active yet', { error: error.message });
        throw new UnauthorizedException('Authentication token not yet active');
      }

      // Log unexpected errors
      this.logger.error('Unexpected authentication error', {
        error: error.message,
        stack: error.stack,
      });
      
      throw new UnauthorizedException('Authentication failed');
    }
  }

  /**
   * Extract JWT token from Authorization header
   * Expected format: "Bearer <token>"
   */
  private extractTokenFromHeader(request: Request): string | undefined {
    const authHeader = request.headers.authorization;
    
    if (!authHeader) {
      return undefined;
    }

    const [type, token] = authHeader.split(' ');
    
    if (type !== 'Bearer' || !token) {
      this.logger.warn('Invalid authorization header format', { authHeader });
      return undefined;
    }

    return token;
  }
}