import { SetMetadata } from "@nestjs/common";

/**
 * Roles Decorator
 *
 * 역할 기반 접근 제어를 위한 데코레이터입니다.
 * 특정 역할을 가진 사용자만 접근할 수 있는 엔드포인트를 정의합니다.
 *
 * @example
 * ```typescript
 * @Get('admin/users')
 * @Roles(UserRole.ADMIN)
 * @UseGuards(JwtAuthGuard, RolesGuard)
 * async getAllUsers() {
 *   return this.userService.getAllUsers();
 * }
 * ```
 */

export enum UserRole {
	USER = "user",
	ADMIN = "admin",
	MODERATOR = "moderator",
}

export const ROLES_KEY = "roles";

export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);

/**
 * Admin Only Decorator
 *
 * 관리자만 접근할 수 있는 엔드포인트를 간편하게 표시합니다.
 */
export const AdminOnly = () => Roles(UserRole.ADMIN);

/**
 * Moderator Or Admin Decorator
 *
 * 운영자 또는 관리자만 접근할 수 있는 엔드포인트를 표시합니다.
 */
export const ModeratorOrAdmin = () => Roles(UserRole.MODERATOR, UserRole.ADMIN);
