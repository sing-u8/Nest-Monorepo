import { Transform } from "class-transformer";
import {
	IsEmail,
	IsOptional,
	IsString,
	MaxLength,
	MinLength,
} from "class-validator";

/**
 * 회원가입 요청 DTO
 */
export class SignUpRequestDto {
	@IsEmail({}, { message: "유효한 이메일 주소를 입력해주세요." })
	@Transform(({ value }) => value?.toLowerCase().trim())
	email: string;

	@IsString({ message: "비밀번호는 문자열이어야 합니다." })
	@MinLength(8, { message: "비밀번호는 최소 8자 이상이어야 합니다." })
	@MaxLength(128, { message: "비밀번호는 최대 128자까지 가능합니다." })
	password: string;

	@IsOptional()
	@IsString({ message: "이름은 문자열이어야 합니다." })
	@MinLength(1, { message: "이름은 최소 1자 이상이어야 합니다." })
	@MaxLength(50, { message: "이름은 최대 50자까지 가능합니다." })
	@Transform(({ value }) => value?.trim())
	name?: string;
}
