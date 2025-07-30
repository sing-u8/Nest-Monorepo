import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';
import { Reflector } from '@nestjs/core';

export const IS_PUBLIC_KEY = 'isPublic';

/**
 * JWT Authentication Guard
 * Protects routes by validating JWT tokens
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtAuthGuard.name);

  constructor(private reflector: Reflector) {
    super();
  }

  /**
   * Check if the route can be activated
   */
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // Check if route is marked as public
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    // Call parent canActivate which triggers the JWT strategy
    return super.canActivate(context);
  }

  /**
   * Handle request after authentication
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    
    // Log authentication attempts for security monitoring
    if (err || !user) {
      const ip = this.getClientIp(request);
      const userAgent = request.headers['user-agent'] || 'Unknown';
      
      this.logger.warn(
        `Authentication failed - IP: ${ip}, User-Agent: ${userAgent}, Error: ${
          err?.message || info?.message || 'Unknown error'
        }`,
      );

      // Throw appropriate error
      if (info?.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Token has expired');
      }
      
      if (info?.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid token');
      }

      throw err || new UnauthorizedException('Authentication failed');
    }

    // Log successful authentication
    this.logger.debug(
      `Authentication successful - User ID: ${user.userId}, Session: ${user.sessionId}`,
    );

    return user;
  }

  /**
   * Extract client IP address from request
   */
  private getClientIp(request: any): string {
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

/**
 * Decorator to mark routes as public (no authentication required)
 */
export const Public = () => {
  return (target: any, propertyKey?: string, descriptor?: PropertyDescriptor) => {
    if (propertyKey && descriptor) {
      // Method decorator
      Reflect.defineMetadata(IS_PUBLIC_KEY, true, descriptor.value);
    } else {
      // Class decorator
      Reflect.defineMetadata(IS_PUBLIC_KEY, true, target);
    }
  };
};