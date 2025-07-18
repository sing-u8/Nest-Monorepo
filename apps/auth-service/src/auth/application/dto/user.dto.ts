import { Transform } from "class-transformer";
import {
	IsBoolean,
	IsEmail,
	IsEnum,
	IsOptional,
	IsString,
	MaxLength,
	MinLength,
} from "class-validator";
import { Provider } from '@shared/enum/provider.enum';

/**
 * 사용자 생성 DTO
 */
export class CreateUserDto {
	@IsEmail({}, { message: "유효한 이메일 주소를 입력해주세요." })
	@Transform(({ value }) => value?.toLowerCase().trim())
	email: string;

	@IsOptional()
	@IsString({ message: "비밀번호는 문자열이어야 합니다." })
	@MinLength(8, { message: "비밀번호는 최소 8자 이상이어야 합니다." })
	@MaxLength(128, { message: "비밀번호는 최대 128자 이하여야 합니다." })
	password?: string;

	@IsOptional()
	@IsEnum(Provider, { message: "유효한 인증 제공자를 선택해주세요." })
	provider?: Provider = Provider.LOCAL;

	@IsOptional()
	@IsString({ message: "제공자 ID는 문자열이어야 합니다." })
	providerId?: string;
}

/**
 * 사용자 업데이트 DTO
 */
export class UpdateUserDto {
	@IsOptional()
	@IsEmail({}, { message: "유효한 이메일 주소를 입력해주세요." })
	@Transform(({ value }) => value?.toLowerCase().trim())
	email?: string;

	@IsOptional()
	@IsBoolean({ message: "계정 상태는 불린 값이어야 합니다." })
	isActive?: boolean;

	@IsOptional()
	@IsBoolean({ message: "이메일 인증 상태는 불린 값이어야 합니다." })
	isEmailVerified?: boolean;
}

/**
 * 비밀번호 변경 DTO
 */
export class ChangePasswordDto {
	@IsString({ message: "현재 비밀번호는 문자열이어야 합니다." })
	currentPassword: string;

	@IsString({ message: "새 비밀번호는 문자열이어야 합니다." })
	@MinLength(8, { message: "비밀번호는 최소 8자 이상이어야 합니다." })
	@MaxLength(128, { message: "비밀번호는 최대 128자 이하여야 합니다." })
	newPassword: string;
}

/**
 * 사용자 목록 조회 DTO
 */
export class GetUsersQueryDto {
	@IsOptional()
	@IsString({ message: "검색어는 문자열이어야 합니다." })
	search?: string;

	@IsOptional()
	@IsEnum(Provider, { message: "유효한 인증 제공자를 선택해주세요." })
	provider?: Provider;

	@IsOptional()
	@IsBoolean()
	@Transform(({ value }) => {
		if (value === "true") return true;
		if (value === "false") return false;
		return value;
	})
	isActive?: boolean;

	@IsOptional()
	@IsBoolean()
	@Transform(({ value }) => {
		if (value === "true") return true;
		if (value === "false") return false;
		return value;
	})
	isEmailVerified?: boolean;

	@IsOptional()
	@Transform(({ value }) => parseInt(value))
	page?: number = 1;

	@IsOptional()
	@Transform(({ value }) => parseInt(value))
	limit?: number = 10;

	@IsOptional()
	@IsString()
	sortBy?: string = "createdAt";

	@IsOptional()
	@IsEnum(["ASC", "DESC"], { message: "정렬 순서는 ASC 또는 DESC여야 합니다." })
	sortOrder?: "ASC" | "DESC" = "DESC";
}

/**
 * 사용자 상세 정보 DTO
 */
export class UserDetailDto {
	id: string;
	email: string;
	provider: Provider;
	providerId?: string;
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
		providerId?: string,
		lastLoginAt?: Date,
	) {
		this.id = id;
		this.email = email;
		this.provider = provider;
		this.providerId = providerId;
		this.isActive = isActive;
		this.isEmailVerified = isEmailVerified;
		this.createdAt = createdAt;
		this.updatedAt = updatedAt;
		this.lastLoginAt = lastLoginAt;
	}
}

/**
 * 사용자 목록 응답 DTO
 */
export class UsersResponseDto {
	users: UserDetailDto[];
	total: number;
	page: number;
	limit: number;
	totalPages: number;

	constructor(
		users: UserDetailDto[],
		total: number,
		page: number,
		limit: number,
	) {
		this.users = users;
		this.total = total;
		this.page = page;
		this.limit = limit;
		this.totalPages = Math.ceil(total / limit);
	}
}

/**
 * 이메일 인증 DTO
 */
export class VerifyEmailDto {
	@IsString({ message: "인증 토큰은 문자열이어야 합니다." })
	token: string;
}
