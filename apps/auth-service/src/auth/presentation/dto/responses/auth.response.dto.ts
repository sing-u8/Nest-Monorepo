import { Exclude, Expose } from "class-transformer";
import {
	IsBoolean,
	IsDate,
	IsNumber,
	IsOptional,
	IsString,
} from "class-validator";

/**
 * 기본 API 응답 구조
 */
export class BaseResponseDto<T = any> {
	@Expose()
	success: boolean;

	@Expose()
	message: string;

	@Expose()
	data?: T;

	@Expose()
	@IsOptional()
	error?: {
		code: string;
		message: string;
		details?: any;
	};

	@Expose()
	timestamp: string;

	constructor(partial: Partial<BaseResponseDto<T>>) {
		Object.assign(this, partial);
		this.timestamp = new Date().toISOString();
	}
}

/**
 * 토큰 정보 DTO
 */
export class TokenInfoDto {
	@Expose()
	@IsString()
	accessToken: string;

	@Expose()
	@IsString()
	refreshToken: string;

	@Expose()
	@IsString()
	tokenType: string = "Bearer";

	@Expose()
	@IsNumber()
	expiresIn: number; // seconds

	@Expose()
	@IsNumber()
	refreshExpiresIn: number; // seconds

	constructor(partial: Partial<TokenInfoDto>) {
		Object.assign(this, partial);
	}
}

/**
 * 사용자 정보 DTO (응답용)
 */
export class UserInfoDto {
	@Expose()
	@IsString()
	id: string;

	@Expose()
	@IsString()
	email: string;

	@Expose()
	@IsString()
	provider: string;

	@Expose()
	@IsBoolean()
	isEmailVerified: boolean;

	@Expose()
	@IsBoolean()
	isActive: boolean;

	@Expose()
	@IsOptional()
	@IsString()
	name?: string;

	@Expose()
	@IsOptional()
	@IsDate()
	lastLoginAt?: Date;

	@Expose()
	@IsDate()
	createdAt: Date;

	@Expose()
	@IsDate()
	updatedAt: Date;

	// 민감한 정보는 응답에서 제외
	@Exclude()
	passwordHash?: string;

	constructor(partial: Partial<UserInfoDto>) {
		Object.assign(this, partial);
	}
}

/**
 * 로그인/회원가입 응답 DTO
 */
export class AuthResponseDto {
	@Expose()
	user: UserInfoDto;

	@Expose()
	tokens: TokenInfoDto;

	@Expose()
	@IsBoolean()
	isNewUser: boolean;

	constructor(partial: Partial<AuthResponseDto>) {
		Object.assign(this, partial);
	}
}

/**
 * 토큰 갱신 응답 DTO
 */
export class RefreshTokenResponseDto {
	@Expose()
	tokens: TokenInfoDto;

	@Expose()
	user: UserInfoDto;

	constructor(partial: Partial<RefreshTokenResponseDto>) {
		Object.assign(this, partial);
	}
}

/**
 * 로그아웃 응답 DTO
 */
export class LogoutResponseDto {
	@Expose()
	@IsString()
	message: string;

	@Expose()
	@IsBoolean()
	success: boolean;

	constructor(message: string = "로그아웃이 완료되었습니다.") {
		this.message = message;
		this.success = true;
	}
}

/**
 * 비밀번호 재설정 요청 응답 DTO
 */
export class ResetPasswordRequestResponseDto {
	@Expose()
	@IsString()
	message: string;

	@Expose()
	@IsBoolean()
	success: boolean;

	constructor() {
		this.message = "비밀번호 재설정 링크가 이메일로 발송되었습니다.";
		this.success = true;
	}
}
