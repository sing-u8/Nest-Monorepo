import { Transform } from "class-transformer";
import {
	IsEmail,
	IsOptional,
	IsString,
	MaxLength,
	MinLength,
} from "class-validator";
import { Provider } from '@shared/enum/provider.enum';

/**
 * 회원가입 요청 DTO
 */
export class SignUpRequestDto {
	@IsEmail({}, { message: "유효한 이메일 주소를 입력해주세요." })
	@Transform(({ value }) => value?.toLowerCase().trim())
	email: string;

	@IsString({ message: "비밀번호는 문자열이어야 합니다." })
	@MinLength(8, { message: "비밀번호는 최소 8자 이상이어야 합니다." })
	@MaxLength(128, { message: "비밀번호는 최대 128자 이하여야 합니다." })
	password: string;
}

/**
 * 로그인 요청 DTO
 */
export class LoginRequestDto {
	@IsEmail({}, { message: "유효한 이메일 주소를 입력해주세요." })
	@Transform(({ value }) => value?.toLowerCase().trim())
	email: string;

	@IsString({ message: "비밀번호는 문자열이어야 합니다." })
	@MinLength(1, { message: "비밀번호를 입력해주세요." })
	password: string;
}

/**
 * 토큰 갱신 요청 DTO
 */
export class RefreshTokenRequestDto {
	@IsString({ message: "리프레시 토큰은 문자열이어야 합니다." })
	refreshToken: string;
}

/**
 * 인증 응답 DTO
 */
export class AuthResponseDto {
	accessToken: string;
	refreshToken: string;
	user: UserInfoDto;

	constructor(accessToken: string, refreshToken: string, user: UserInfoDto) {
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.user = user;
	}
}

/**
 * 사용자 정보 DTO
 */
export class UserInfoDto {
	id: string;
	email: string;
	provider: Provider;
	isActive: boolean;
	isEmailVerified: boolean;
	lastLoginAt?: Date;
	createdAt: Date;
	updatedAt: Date;

	constructor(
		id: string,
		email: string,
		provider: Provider,
		isActive: boolean,
		isEmailVerified: boolean,
		createdAt: Date,
		updatedAt: Date,
		lastLoginAt?: Date,
	) {
		this.id = id;
		this.email = email;
		this.provider = provider;
		this.isActive = isActive;
		this.isEmailVerified = isEmailVerified;
		this.createdAt = createdAt;
		this.updatedAt = updatedAt;
		this.lastLoginAt = lastLoginAt;
	}
}

/**
 * 토큰 응답 DTO
 */
export class TokenResponseDto {
	accessToken: string;
	refreshToken: string;
	expiresIn: number;
	tokenType: string = "Bearer";

	constructor(accessToken: string, refreshToken: string, expiresIn: number) {
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.expiresIn = expiresIn;
	}
}

/**
 * 로그아웃 요청 DTO
 */
export class LogoutRequestDto {
	@IsOptional()
	@IsString({ message: "리프레시 토큰은 문자열이어야 합니다." })
	refreshToken?: string;
}
