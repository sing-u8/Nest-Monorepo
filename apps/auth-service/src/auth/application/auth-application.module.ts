import { Module } from "@nestjs/common";
import { EventEmitterModule } from "@nestjs/event-emitter";
// Domain Services
import { PasswordDomainService, UserDomainService } from '@/auth/domain';
// Infrastructure Module (리포지토리와 외부 서비스 의존성)
import { AuthInfrastructureModule } from "../infrastructure/auth-infrastructure.module";

// Event Handlers
import {
	UserDeletedHandler,
	UserLoggedInHandler,
	UserRegisteredHandler,
} from "./event/handler";
// Application Services
import {
	AuthApplicationService,
	JwtApplicationService,
	PasswordApplicationService,
	SocialAuthApplicationService,
	UserApplicationService,
} from "./service";

/**
 * Auth Application Module
 *
 * 애플리케이션 계층의 모든 서비스와 이벤트 핸들러를 관리합니다.
 * - 애플리케이션 서비스들
 * - 도메인 서비스들
 * - 이벤트 핸들러들
 */
@Module({
	imports: [
		// Infrastructure 계층 (리포지토리, 외부 서비스, 가드 등)
		AuthInfrastructureModule,
	],
	providers: [
		// Application Services
		AuthApplicationService,
		UserApplicationService,
		PasswordApplicationService,
		SocialAuthApplicationService,
		JwtApplicationService,

		// Domain Services
		UserDomainService,
		PasswordDomainService,

		// Event Handlers
		UserRegisteredHandler,
		UserLoggedInHandler,
		UserDeletedHandler,
	],
	exports: [
		// Application Services만 export (외부에서 사용)
		AuthApplicationService,
		UserApplicationService,
		PasswordApplicationService,
		SocialAuthApplicationService,
		JwtApplicationService,

		// Domain Services도 export (필요 시)
		UserDomainService,
		PasswordDomainService,
	],
})
export class AuthApplicationModule {}
