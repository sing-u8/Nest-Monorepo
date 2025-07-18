import { registerAs } from "@nestjs/config";
import { TypeOrmModuleOptions } from "@nestjs/typeorm";

/**
 * 데이터베이스 설정 키
 */
export const databaseConfigKeys = {
	database: "DATABASE",
	testDatabase: "TEST_DATABASE",
};

/**
 * 데이터베이스 설정 팩토리
 *
 * @nestjs/config의 registerAs를 사용하여 타입 안전한 설정을 생성합니다.
 * 이 방식의 장점:
 * - 설정을 네임스페이스로 구분
 * - 타입 안전성 보장
 * - 테스트 시 설정 오버라이드 용이
 */
export const databaseConfig = registerAs(
	databaseConfigKeys.database,
	(): TypeOrmModuleOptions => ({
		type: "postgres", // 데이터베이스 타입 설정
		host: process.env.DATABASE_HOST,
		port: Number(process.env.DATABASE_PORT),
		username: process.env.DATABASE_USERNAME,
		password: process.env.DATABASE_PASSWORD,
		database: process.env.DATABASE_NAME,

		// 엔티티 경로 설정
		// TypeORM이 자동으로 엔티티를 찾을 수 있도록 패턴을 지정
		// entity: [`${__dirname}/../**/*.typeorm.entity{.ts,.js}`],
		// entity: [RefreshTokenTypeOrmEntity, UserTypeOrmEntity],
		autoLoadEntities: true,

		// 마이그레이션 설정
		// migration: [`${__dirname}/../**/migration/*{.ts,.js}`],

		// 개발 환경에서만 스키마 자동 동기화 활성화
		// 프로덕션에서는 반드시 false로 설정해야 합니다!
		synchronize: process.env.NODE_ENV === "development",

		// SQL 로깅 (개발 환경에서만)
		logging: process.env.NODE_ENV === "development",

		// 연결 풀 설정
		extra: {
			// 최대 연결 수
			max: 10,
			// 최소 연결 수
			min: 1,
			// 연결 타임아웃 (30초)
			connectionTimeoutMillis: 30000,
			// 유휴 연결 타임아웃 (30초)
			idleTimeoutMillis: 30000,
		},

		// SSL 설정 (프로덕션 환경)
		ssl:
			process.env.NODE_ENV === "production"
				? {
						rejectUnauthorized: false,
					}
				: false,
	}),
);

/**
 * 테스트용 데이터베이스 설정
 *
 * 테스트 실행 시 사용할 별도의 데이터베이스 설정입니다.
 * 메모리 DB나 별도의 테스트 DB를 사용할 수 있습니다.
 */
export const testDatabaseConfig = registerAs(
	databaseConfigKeys.testDatabase,
	(): TypeOrmModuleOptions => ({
		type: "postgres",
		host: process.env.DATABASE_HOST || "localhost",
		port: Number(process.env.DATABASE_PORT) || 5432,
		username: process.env.DATABASE_USERNAME || "test",
		password: process.env.DATABASE_PASSWORD || "test",
		database: process.env.DATABASE_NAME
			? `${process.env.DATABASE_NAME}_test`
			: "auth_db_test",

		entities: [`${__dirname}/../**/*.typeorm.entity{.ts,.js}`],

		// 테스트에서는 항상 스키마를 새로 생성
		synchronize: true,
		dropSchema: true, // 테스트 시작 시 기존 스키마 삭제
		logging: false, // 테스트 시 로깅 비활성화
	}),
);
