import { Transform } from "class-transformer";
import { IsNotEmpty, IsOptional, IsString, MaxLength } from "class-validator";

/**
 * 토큰 갱신 요청 DTO
 */
export class RefreshTokenRequestDto {
	@IsString({ message: "리프레시 토큰은 문자열이어야 합니다." })
	@IsNotEmpty({ message: "리프레시 토큰을 입력해주세요." })
	@Transform(({ value }) => value?.trim())
	refreshToken: string;

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
 * 로그아웃 요청 DTO
 */
export class LogoutRequestDto {
	@IsOptional()
	@IsString({ message: "리프레시 토큰은 문자열이어야 합니다." })
	@Transform(({ value }) => value?.trim())
	refreshToken?: string;

	@IsOptional()
	@IsString({ message: "디바이스 정보는 문자열이어야 합니다." })
	@MaxLength(255, { message: "디바이스 정보는 최대 255자까지 가능합니다." })
	@Transform(({ value }) => value?.trim())
	deviceInfo?: string;
}
