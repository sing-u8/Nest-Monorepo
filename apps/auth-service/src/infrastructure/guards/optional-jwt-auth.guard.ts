import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';

/**
 * Optional JWT Authentication Guard
 * Validates JWT if present but allows unauthenticated access
 * Useful for endpoints that have different behavior for authenticated vs anonymous users
 */
@Injectable()
export class OptionalJwtAuthGuard extends AuthGuard('jwt') {
  /**
   * Always allow activation, but still process JWT if present
   */
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // Always return true to allow access
    // But still process the JWT validation in the background
    return super.canActivate(context) as Promise<boolean>;
  }

  /**
   * Handle request - don't throw errors for missing/invalid tokens
   */
  handleRequest(err: any, user: any, info: any) {
    // If there's a user, return it
    if (user) {
      return user;
    }

    // If there's no user (no token or invalid token), return null
    // This allows the route to handle anonymous users
    return null;
  }
}