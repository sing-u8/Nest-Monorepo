import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { TypeOrmModule } from "@nestjs/typeorm";
// 리포지토리 Injection Token 임포트
import {
	REFRESH_TOKEN_REPOSITORY_TOKEN,
	USER_REPOSITORY_TOKEN,
} from '@/auth/domain';
import socialAuthConfig from "./config/social-auth.config";
import { RefreshTokenTypeOrmEntity } from "./database/entity/refresh-token.typeorm.entity";
import { UserTypeOrmEntity } from "./database/entity/user.typeorm.entity";
import { RefreshTokenTypeormRepository } from "./database/repository/refresh-token.typeorm.repository";
import { UserTypeormRepository } from "./database/repository/user.typeorm.repository";
import { AppleAuthService } from "./external-service/apple-auth.service";
import { EmailService } from "./external-service/email.service";
import { GoogleAuthService } from "./external-service/google-auth.service";
import { JwtAuthGuard } from "./guard/jwt-auth.guard";
import { OptionalAuthGuard } from "./guard/optional-auth.guard";
import { RefreshTokenGuard } from "./guard/refresh-token.guard";

/**
 * Auth Infrastructure Module
 *
 * 이 모듈의 책임:
 * - TypeORM 엔티티 등록
 * - 리포지토리 구현체 제공
 * - 외부 서비스 (소셜 로그인, 이메일 등) 관리
 * - 데이터베이스 관련 인프라 관리
 */
@Module({
	imports: [
		TypeOrmModule.forFeature([UserTypeOrmEntity, RefreshTokenTypeOrmEntity]),
		ConfigModule.forFeature(socialAuthConfig),
	],
	providers: [
		// 리포지토리 구현체들을 인터페이스에 바인딩 (Injection Token 사용)
		{
			provide: USER_REPOSITORY_TOKEN,
			useClass: UserTypeormRepository,
		},
		{
			provide: REFRESH_TOKEN_REPOSITORY_TOKEN,
			useClass: RefreshTokenTypeormRepository,
		},

		// 외부 서비스들
		EmailService,
		GoogleAuthService,
		AppleAuthService,

		// 가드들
		JwtAuthGuard,
		RefreshTokenGuard,
		OptionalAuthGuard,
	],
	exports: [
		// TypeORM 리포지토리들
		TypeOrmModule,

		// 리포지토리 Injection Token들
		USER_REPOSITORY_TOKEN,
		REFRESH_TOKEN_REPOSITORY_TOKEN,

		// 외부 서비스들
		EmailService,
		GoogleAuthService,
		AppleAuthService,

		// 가드들
		JwtAuthGuard,
		RefreshTokenGuard,
		OptionalAuthGuard,
	],
})
export class AuthInfrastructureModule {}
