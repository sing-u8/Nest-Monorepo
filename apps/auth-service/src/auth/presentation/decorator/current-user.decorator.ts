import { createParamDecorator, ExecutionContext } from "@nestjs/common";

/**
 * Current User Decorator
 *
 * JWT 인증을 통해 인증된 사용자 정보를 컨트롤러 메서드의 매개변수로 주입합니다.
 *
 * @example
 * ```typescript
 * @Get('profile')
 * @UseGuards(JwtAuthGuard)
 * async getProfile(@CurrentUser() user: CurrentUserInfo) {
 *   return user;
 * }
 * ```
 */

export interface CurrentUserInfo {
	userId: string;
	email: string;
	provider: string;
	isEmailVerified: boolean;
	iat?: number;
	exp?: number;
}

interface RequestWithUser {
	user?: CurrentUserInfo;
}

export const CurrentUser = createParamDecorator(
	<T extends keyof CurrentUserInfo>(
		data: T | undefined,
		ctx: ExecutionContext,
	): T extends undefined ? CurrentUserInfo : CurrentUserInfo[T] => {
		const request = ctx.switchToHttp().getRequest<RequestWithUser>();
		const user = request.user;

		if (!user) {
			throw new Error(
				"User not found in request. Make sure to use @CurrentUser() with authentication guard.",
			);
		}

		// 특정 필드만 반환하는 경우
		if (data) {
			return user[data] as any;
		}

		// 전체 사용자 정보 반환
		return user as any;
	},
);

/**
 * Optional Current User Decorator
 *
 * 인증이 선택적인 엔드포인트에서 사용합니다.
 * 사용자가 인증되어 있으면 사용자 정보를, 그렇지 않으면 null을 반환합니다.
 */
export const OptionalCurrentUser = createParamDecorator(
	<T extends keyof CurrentUserInfo>(
		data: T | undefined,
		ctx: ExecutionContext,
	): T extends undefined
		? CurrentUserInfo | null
		: CurrentUserInfo[T] | null => {
		const request = ctx.switchToHttp().getRequest<RequestWithUser>();
		const user = request.user;

		if (!user) {
			return null as any;
		}

		if (data) {
			return user[data] as any;
		}

		return user as any;
	},
);
