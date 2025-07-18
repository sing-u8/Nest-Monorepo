import { SetMetadata } from "@nestjs/common";

/**
 * Public Decorator
 *
 * 이 데코레이터가 적용된 엔드포인트는 JWT 인증을 건너뜁니다.
 * JwtAuthGuard에서 이 메타데이터를 확인하여 인증을 건너뛸지 결정합니다.
 *
 * @example
 * ```typescript
 * @Post('signup')
 * @Public()
 * async signUp(@Body() signUpDto: SignUpRequestDto) {
 *   return this.authService.signUp(signUpDto);
 * }
 * ```
 */

export const IS_PUBLIC_KEY = "isPublic";

export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
