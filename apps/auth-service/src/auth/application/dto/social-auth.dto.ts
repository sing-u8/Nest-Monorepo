import { IsEnum, IsOptional, IsString, IsUrl } from "class-validator";
import { Provider } from '@shared/enum/provider.enum';

/**
 * 소셜 로그인 요청 DTO
 */
export class SocialLoginRequestDto {
	@IsEnum(Provider, { message: "지원되는 소셜 로그인 제공자를 선택해주세요." })
	provider: Provider.GOOGLE | Provider.APPLE;

	@IsString({ message: "인증 코드는 문자열이어야 합니다." })
	code: string;

	@IsOptional()
	@IsString({ message: "상태 값은 문자열이어야 합니다." })
	state?: string;

	@IsOptional()
	@IsUrl({}, { message: "유효한 리다이렉트 URL을 입력해주세요." })
	redirectUri?: string;
}

/**
 * 소셜 로그인 콜백 DTO
 */
export class SocialLoginCallbackDto {
	@IsString({ message: "인증 코드는 문자열이어야 합니다." })
	code: string;

	@IsOptional()
	@IsString({ message: "상태 값은 문자열이어야 합니다." })
	state?: string;

	@IsOptional()
	@IsString({ message: "에러 코드는 문자열이어야 합니다." })
	error?: string;

	@IsOptional()
	@IsString({ message: "에러 설명은 문자열이어야 합니다." })
	error_description?: string;
}

/**
 * 소셜 프로필 정보 DTO
 */
export class SocialProfileDto {
	id: string;
	email: string;
	name?: string;
	firstName?: string;
	lastName?: string;
	picture?: string;
	provider: Provider;

	constructor(
		id: string,
		email: string,
		provider: Provider,
		name?: string,
		firstName?: string,
		lastName?: string,
		picture?: string,
	) {
		this.id = id;
		this.email = email;
		this.provider = provider;
		this.name = name;
		this.firstName = firstName;
		this.lastName = lastName;
		this.picture = picture;
	}
}

/**
 * 구글 사용자 정보 DTO
 */
export class GoogleUserInfoDto {
	sub: string; // Google User ID
	email: string;
	email_verified: boolean;
	name?: string;
	given_name?: string;
	family_name?: string;
	picture?: string;
	locale?: string;

	constructor(data: Partial<GoogleUserInfoDto>) {
		this.sub = data.sub!;
		this.email = data.email!;
		this.email_verified = data.email_verified ?? false;
		this.name = data.name;
		this.given_name = data.given_name;
		this.family_name = data.family_name;
		this.picture = data.picture;
		this.locale = data.locale;
	}
}

/**
 * 애플 사용자 정보 DTO
 */
export class AppleUserInfoDto {
	sub: string; // Apple User ID
	email?: string;
	email_verified?: boolean;
	name?: {
		firstName?: string;
		lastName?: string;
	};

	constructor(data: Partial<AppleUserInfoDto>) {
		this.sub = data.sub!;
		this.email = data.email;
		this.email_verified = data.email_verified;
		this.name = data.name;
	}
}

/**
 * 계정 연결 요청 DTO
 */
export class LinkAccountRequestDto {
	@IsEnum(Provider, { message: "지원되는 소셜 로그인 제공자를 선택해주세요." })
	provider: Provider.GOOGLE | Provider.APPLE;

	@IsString({ message: "인증 코드는 문자열이어야 합니다." })
	code: string;

	@IsOptional()
	@IsString({ message: "상태 값은 문자열이어야 합니다." })
	state?: string;
}

/**
 * 계정 연결 해제 요청 DTO
 */
export class UnlinkAccountRequestDto {
	@IsEnum(Provider, { message: "지원되는 소셜 로그인 제공자를 선택해주세요." })
	provider: Provider.GOOGLE | Provider.APPLE;
}

/**
 * 소셜 계정 정보 DTO
 */
export class SocialAccountDto {
	provider: Provider;
	providerId: string;
	email?: string;
	isLinked: boolean;
	linkedAt?: Date;

	constructor(
		provider: Provider,
		providerId: string,
		isLinked: boolean,
		email?: string,
		linkedAt?: Date,
	) {
		this.provider = provider;
		this.providerId = providerId;
		this.isLinked = isLinked;
		this.email = email;
		this.linkedAt = linkedAt;
	}
}
