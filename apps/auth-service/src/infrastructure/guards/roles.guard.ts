import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

// Repositories
import { UserRepository } from '../../domain/ports/user.repository';

export const ROLES_KEY = 'roles';

export enum UserRole {
  USER = 'USER',
  ADMIN = 'ADMIN',
  MODERATOR = 'MODERATOR',
  SUPER_ADMIN = 'SUPER_ADMIN',
}

/**
 * Decorator to specify required roles for a route
 */
export const Roles = (...roles: UserRole[]) => {
  return (target: any, propertyKey?: string, descriptor?: PropertyDescriptor) => {
    if (propertyKey && descriptor) {
      // Method decorator
      Reflect.defineMetadata(ROLES_KEY, roles, descriptor.value);
    } else {
      // Class decorator
      Reflect.defineMetadata(ROLES_KEY, roles, target);
    }
  };
};

/**
 * Role-based authorization guard
 * Checks if authenticated user has required roles
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private userRepository: UserRepository,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Get required roles from decorator
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles || requiredRoles.length === 0) {
      // No roles required, allow access
      return true;
    }

    // Get authenticated user from request
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user || !user.userId) {
      throw new ForbiddenException('User not authenticated');
    }

    // Fetch user with roles from database
    const fullUser = await this.userRepository.findById(user.userId);
    if (!fullUser) {
      throw new ForbiddenException('User not found');
    }

    // Check if user has any of the required roles
    // Note: This assumes User entity has a getRoles() method
    // In a real implementation, you might have a separate UserRole entity/table
    const userRoles = this.getUserRoles(fullUser);
    const hasRole = requiredRoles.some(role => userRoles.includes(role));

    if (!hasRole) {
      throw new ForbiddenException(
        `User does not have required roles: ${requiredRoles.join(', ')}`,
      );
    }

    return true;
  }

  /**
   * Get user roles
   * This is a placeholder - in a real implementation,
   * roles would be stored in the database
   */
  private getUserRoles(user: any): UserRole[] {
    // Default role for all users
    const roles = [UserRole.USER];

    // Check for admin email domains (example)
    if (user.getEmail().endsWith('@admin.example.com')) {
      roles.push(UserRole.ADMIN);
    }

    // Check for super admin (example)
    if (user.getEmail() === 'superadmin@example.com') {
      roles.push(UserRole.SUPER_ADMIN);
    }

    return roles;
  }
}