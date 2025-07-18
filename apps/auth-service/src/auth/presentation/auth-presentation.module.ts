import { Module } from "@nestjs/common";
import { APP_FILTER, APP_INTERCEPTOR } from "@nestjs/core";
// Application Module (애플리케이션 서비스들을 위해 필요)
import { AuthApplicationModule } from "../application/auth-application.module";
// Infrastructure Module (가드들을 위해 필요)
import { AuthInfrastructureModule } from "../infrastructure/auth-infrastructure.module";
// Controllers
import { AuthController } from "./controller/auth.controller";
import { UserController } from "./controller/user.controller";

// Filters
import { DomainExceptionFilter, GlobalExceptionFilter } from "./filter";

// Interceptors
import { LoggingInterceptor, ResponseInterceptor } from "./interceptor";

/**
 * Auth Presentation Module
 *
 * 프레젠테이션 계층의 모든 컴포넌트를 관리합니다.
 * - 컨트롤러
 * - 예외 필터
 * - 인터셉터
 * - 커스텀 데코레이터
 */
@Module({
	imports: [
		// Application 계층 (애플리케이션 서비스들)
		AuthApplicationModule,
		// Infrastructure 계층 (가드들)
		AuthInfrastructureModule,
	],
	controllers: [
		// 컨트롤러들 활성화
		AuthController,
		UserController,
	],
	providers: [
		// 글로벌 예외 필터
		{
			provide: APP_FILTER,
			useClass: DomainExceptionFilter,
		},
		{
			provide: APP_FILTER,
			useClass: GlobalExceptionFilter,
		},

		// 글로벌 인터셉터
		{
			provide: APP_INTERCEPTOR,
			useClass: LoggingInterceptor,
		},
		{
			provide: APP_INTERCEPTOR,
			useClass: ResponseInterceptor,
		},
	],
	exports: [
		// Presentation 계층에서는 일반적으로 export할 것이 없음
		// Application Services는 AuthApplicationModule에서 제공
	],
})
export class AuthPresentationModule {}
