import { Transform } from "class-transformer";
import {
	IsEmail,
	IsOptional,
	IsString,
	MaxLength,
	MinLength,
} from "class-validator";

/**
 * 로그인 요청 DTO
 */
export class LoginRequestDto {
	@IsEmail({}, { message: "유효한 이메일 주소를 입력해주세요." })
	@Transform(({ value }) => value?.toLowerCase().trim())
	email: string;

	@IsString({ message: "비밀번호는 문자열이어야 합니다." })
	@MinLength(1, { message: "비밀번호를 입력해주세요." })
	@MaxLength(128, { message: "비밀번호는 최대 128자까지 가능합니다." })
	password: string;

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
