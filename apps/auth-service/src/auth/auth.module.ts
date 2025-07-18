import { Module } from "@nestjs/common";
import { AuthApplicationModule } from "./application/auth-application.module";
import { AuthInfrastructureModule } from '@/auth/infrastructure/auth-infrastructure.module';
import { AuthPresentationModule } from '@/auth/presentation/auth-presentation.module';
// import { AuthInfrastructureModule } from "./infrastructure/auth-infrastructure.module";

/**
 * Auth Module
 *
 * 인증 도메인의 모든 계층을 통합 관리하는 루트 모듈
 * - Infrastructure 계층 (리포지토리, 외부 서비스, 가드 등)
 * - Application 계층 (애플리케이션 서비스, 이벤트 핸들러)
 * - Domain 계층 (도메인 서비스, 엔티티, VO 등)
 */
@Module({
	imports: [
		// presentation 계층 (컨트롤러, DTO 등)
		AuthPresentationModule,
		// Infrastructure 계층 (리포지토리, 외부 서비스, 가드 등)
		AuthInfrastructureModule,

		// Application 계층 (애플리케이션 서비스, 이벤트 핸들러)
		AuthApplicationModule,
	],
	exports: [
		// Application 서비스들만 외부에 노출
		AuthApplicationModule,
	],
})
export class AuthModule {}
