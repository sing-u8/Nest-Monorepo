import { Exclude, Expose, Type } from "class-transformer";
import {
	IsArray,
	IsBoolean,
	IsDate,
	IsNumber,
	IsOptional,
	IsString,
} from "class-validator";

/**
 * 페이지네이션 메타데이터
 */
export class PaginationMetaDto {
	@Expose()
	@IsNumber()
	page: number;

	@Expose()
	@IsNumber()
	limit: number;

	@Expose()
	@IsNumber()
	total: number;

	@Expose()
	@IsNumber()
	totalPages: number;

	@Expose()
	@IsBoolean()
	hasNext: boolean;

	@Expose()
	@IsBoolean()
	hasPrev: boolean;

	constructor(partial: Partial<PaginationMetaDto>) {
		Object.assign(this, partial);
	}
}

/**
 * 사용자 목록 응답 DTO
 */
export class UserListResponseDto {
	@Expose()
	@IsArray()
	@Type(() => UserDetailDto)
	users: UserDetailDto[];

	@Expose()
	@Type(() => PaginationMetaDto)
	meta: PaginationMetaDto;

	constructor(partial: Partial<UserListResponseDto>) {
		Object.assign(this, partial);
	}
}

/**
 * 사용자 상세 정보 DTO
 */
export class UserDetailDto {
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
	@IsOptional()
	@IsString()
	providerId?: string;

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

	@Expose()
	@IsOptional()
	@IsArray()
	linkedSocialAccounts?: SocialAccountDto[];

	// 민감한 정보는 응답에서 제외
	@Exclude()
	passwordHash?: string;

	constructor(partial: Partial<UserDetailDto>) {
		Object.assign(this, partial);
	}
}

/**
 * 소셜 계정 정보 DTO
 */
export class SocialAccountDto {
	@Expose()
	@IsString()
	provider: string;

	@Expose()
	@IsString()
	providerId: string;

	@Expose()
	@IsOptional()
	@IsString()
	email?: string;

	@Expose()
	@IsOptional()
	@IsString()
	name?: string;

	@Expose()
	@IsDate()
	linkedAt: Date;

	constructor(partial: Partial<SocialAccountDto>) {
		Object.assign(this, partial);
	}
}

/**
 * 사용자 프로필 업데이트 응답 DTO
 */
export class UserUpdateResponseDto {
	@Expose()
	@Type(() => UserDetailDto)
	user: UserDetailDto;

	@Expose()
	@IsString()
	message: string;

	constructor(
		user: UserDetailDto,
		message: string = "프로필이 성공적으로 업데이트되었습니다.",
	) {
		this.user = user;
		this.message = message;
	}
}

/**
 * 비밀번호 변경 응답 DTO
 */
export class ChangePasswordResponseDto {
	@Expose()
	@IsString()
	message: string;

	@Expose()
	@IsBoolean()
	success: boolean;

	constructor() {
		this.message = "비밀번호가 성공적으로 변경되었습니다.";
		this.success = true;
	}
}

/**
 * 계정 삭제 응답 DTO
 */
export class DeleteAccountResponseDto {
	@Expose()
	@IsString()
	message: string;

	@Expose()
	@IsBoolean()
	success: boolean;

	@Expose()
	@IsDate()
	deletedAt: Date;

	constructor() {
		this.message = "계정이 성공적으로 삭제되었습니다.";
		this.success = true;
		this.deletedAt = new Date();
	}
}

/**
 * 이메일 인증 응답 DTO
 */
export class EmailVerificationResponseDto {
	@Expose()
	@IsString()
	message: string;

	@Expose()
	@IsBoolean()
	success: boolean;

	@Expose()
	@IsBoolean()
	isVerified: boolean;

	constructor(isVerified: boolean) {
		this.isVerified = isVerified;
		this.success = true;
		this.message = isVerified
			? "이메일 인증이 완료되었습니다."
			: "이메일 인증 링크가 발송되었습니다.";
	}
}

/**
 * 사용자 통계 응답 DTO
 */
export class UserStatsResponseDto {
	@Expose()
	@IsNumber()
	totalUsers: number;

	@Expose()
	@IsNumber()
	activeUsers: number;

	@Expose()
	@IsNumber()
	inactiveUsers: number;

	@Expose()
	@IsNumber()
	verifiedUsers: number;

	@Expose()
	@IsNumber()
	unverifiedUsers: number;

	@Expose()
	@IsNumber()
	localUsers: number;

	@Expose()
	@IsNumber()
	socialUsers: number;

	@Expose()
	recentSignups: {
		today: number;
		thisWeek: number;
		thisMonth: number;
	};

	constructor(partial: Partial<UserStatsResponseDto>) {
		Object.assign(this, partial);
	}
}
