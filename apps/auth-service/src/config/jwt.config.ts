import { registerAs } from "@nestjs/config";
import { JwtModuleOptions } from "@nestjs/jwt";

/**
 * JWT 설정 키
 */
export const jwtConfigKeys = {
	jwt: "JWT",
	jwtModule: "JWT_MODULE",
};

/**
 * JWT 설정 타입 정의
 *
 * Access Token과 Refresh Token에 대한 설정을 분리하여
 * 각각 다른 만료 시간과 시크릿을 사용할 수 있습니다.
 */
export interface JwtConfig {
	accessToken: {
		secret: string;
		expiresIn: string;
	};
	refreshToken: {
		secret: string;
		expiresIn: string;
	};
}

/**
 * JWT 설정 팩토리
 *
 * Access Token과 Refresh Token을 분리하여 관리합니다.
 * 이렇게 하는 이유:
 * - 보안 강화: 각각 다른 시크릿 사용
 * - 유연성: 토큰별로 다른 만료 시간 설정 가능
 * - 확장성: 나중에 추가 토큰 타입 지원 가능
 */
export const jwtConfig = registerAs(
	jwtConfigKeys.jwt,
	(): JwtConfig => ({
		accessToken: {
			secret: process.env.JWT_SECRET || "default-access-secret",
			expiresIn: process.env.JWT_EXPIRES_IN || "1h",
		},
		refreshToken: {
			secret: process.env.REFRESH_TOKEN_SECRET || "default-refresh-secret",
			expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "7d",
		},
	}),
);

/**
 * NestJS JWT 모듈용 설정
 *
 * @nestjs/jwt 모듈에서 사용할 기본 설정입니다.
 * 주로 Access Token 생성에 사용됩니다.
 */
export const jwtModuleConfig = registerAs(
	jwtConfigKeys.jwtModule,
	(): JwtModuleOptions => ({
		secret: process.env.JWT_SECRET,
		signOptions: {
			expiresIn: process.env.JWT_EXPIRES_IN || "1h",
			issuer: "auth-service", // 토큰 발행자
			audience: "auth-service-client", // 토큰 대상
		},
		verifyOptions: {
			issuer: "auth-service",
			audience: "auth-service-client",
		},
	}),
);

/**
 * JWT 토큰 페이로드 타입 정의
 *
 * 토큰에 포함될 데이터의 구조를 정의합니다.
 * 보안을 위해 최소한의 정보만 포함합니다.
 */
export interface JwtPayload {
	sub: string; // Subject: 사용자 ID
	email: string; // 사용자 이메일
	iat?: number; // Issued At: 발행 시간
	exp?: number; // Expires: 만료 시간
	iss?: string; // Issuer: 발행자
	aud?: string; // Audience: 대상
	type?: "access" | "refresh"; // 토큰 타입
}

/**
 * Refresh Token 페이로드 타입
 *
 * Refresh Token은 더 적은 정보를 포함합니다.
 */
export interface RefreshTokenPayload {
	sub: string; // 사용자 ID
	tokenId: string; // 토큰 고유 ID (DB에 저장된 토큰과 매칭)
	iat?: number;
	exp?: number;
	type: "refresh";
}
