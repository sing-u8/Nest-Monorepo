import { Transform } from "class-transformer";
import {
	IsEmail,
	IsEnum,
	IsNotEmpty,
	IsOptional,
	IsString,
	MaxLength,
} from "class-validator";

export enum SocialProvider {
	GOOGLE = "google",
	APPLE = "apple",
}

/**
 * 소셜 로그인 요청 DTO
 */
export class SocialLoginRequestDto {
	@IsEnum(SocialProvider, {
		message: "지원되는 소셜 제공자를 선택해주세요. (google, apple)",
	})
	provider: SocialProvider;

	@IsString({ message: "액세스 토큰은 문자열이어야 합니다." })
	@IsNotEmpty({ message: "액세스 토큰을 입력해주세요." })
	@Transform(({ value }) => value?.trim())
	accessToken: string;

	@IsOptional()
	@IsString({ message: "ID 토큰은 문자열이어야 합니다." })
	@Transform(({ value }) => value?.trim())
	idToken?: string;

	@IsOptional()
	@IsString({ message: "디바이스 정보는 문자열이어야 합니다." })
	@MaxLength(255, { message: "디바이스 정보는 최대 255자까지 가능합니다." })
	@Transform(({ value }) => value?.trim())
	deviceInfo?: string;

	@IsOptional()
	@IsString({ message: "IP 주소는 문자열이어야 합니다." })
	@MaxLength(45, { message: "IP 주소는 최대 45자까지 가능합니다." })
	@Transform(({ value }) => value?.trim())
	ipAddress?: string;
}

/**
 * 소셜 계정 연결 요청 DTO
 */
export class LinkSocialAccountRequestDto {
	@IsEnum(SocialProvider, {
		message: "지원되는 소셜 제공자를 선택해주세요. (google, apple)",
	})
	provider: SocialProvider;

	@IsString({ message: "액세스 토큰은 문자열이어야 합니다." })
	@IsNotEmpty({ message: "액세스 토큰을 입력해주세요." })
	@Transform(({ value }) => value?.trim())
	accessToken: string;

	@IsOptional()
	@IsString({ message: "ID 토큰은 문자열이어야 합니다." })
	@Transform(({ value }) => value?.trim())
	idToken?: string;
}

/**
 * 소셜 계정 연결 해제 요청 DTO
 */
export class UnlinkSocialAccountRequestDto {
	@IsEnum(SocialProvider, {
		message: "지원되는 소셜 제공자를 선택해주세요. (google, apple)",
	})
	provider: SocialProvider;
}

/**
 * 비밀번호 변경 요청 DTO
 */
export class ChangePasswordRequestDto {
	@IsString({ message: "현재 비밀번호는 문자열이어야 합니다." })
	@IsNotEmpty({ message: "현재 비밀번호를 입력해주세요." })
	currentPassword: string;

	@IsString({ message: "새 비밀번호는 문자열이어야 합니다." })
	@IsNotEmpty({ message: "새 비밀번호를 입력해주세요." })
	newPassword: string;
}

/**
 * 비밀번호 재설정 요청 DTO
 */
export class ResetPasswordRequestDto {
	@IsEmail({}, { message: "유효한 이메일 주소를 입력해주세요." })
	@Transform(({ value }) => value?.toLowerCase().trim())
	email: string;
}

/**
 * 비밀번호 재설정 확인 DTO
 */
export class ConfirmResetPasswordRequestDto {
	@IsString({ message: "재설정 토큰은 문자열이어야 합니다." })
	@IsNotEmpty({ message: "재설정 토큰을 입력해주세요." })
	@Transform(({ value }) => value?.trim())
	token: string;

	@IsString({ message: "새 비밀번호는 문자열이어야 합니다." })
	@IsNotEmpty({ message: "새 비밀번호를 입력해주세요." })
	newPassword: string;
}
