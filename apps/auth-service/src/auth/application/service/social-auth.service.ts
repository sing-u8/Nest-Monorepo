import { Injectable, Inject } from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { Provider } from '@shared/enum/provider.enum';
import { User } from '@/auth/domain';
import {
	UserAlreadyExistsException,
	UserNotFoundException,
} from '@/auth/domain';
import { IUserRepository, USER_REPOSITORY_TOKEN } from '@/auth/domain';
import { UserDomainService } from '@/auth/domain';
import { Email, UserId } from '@/auth/domain';
import {
	AppleUserInfoDto,
	AuthResponseDto,
	GoogleUserInfoDto,
	LinkAccountRequestDto,
	SocialAccountDto,
	SocialLoginRequestDto,
	SocialProfileDto,
	UnlinkAccountRequestDto,
	UserInfoDto,
} from "../dto";
import { UserLoggedInEvent, UserRegisteredEvent } from "../event/event";
import { JwtApplicationService } from "./jwt.service";

/**
 * 소셜 인증 애플리케이션 서비스
 * 소셜 로그인, 계정 연결/해제 등을 담당
 */
@Injectable()
export class SocialAuthApplicationService {
	@Inject(USER_REPOSITORY_TOKEN)
	private readonly userRepository: IUserRepository;

	constructor(
		private readonly userDomainService: UserDomainService,
		private readonly jwtService: JwtApplicationService,
		private readonly eventEmitter: EventEmitter2,
	) {}

	/**
	 * 소셜 로그인 처리
	 */
	async socialLogin(dto: SocialLoginRequestDto): Promise<AuthResponseDto> {
		// 1. 소셜 제공자에서 사용자 정보 가져오기
		const socialProfile = await this.getSocialProfile(dto.provider, dto.code);

		// 2. 이메일로 기존 사용자 조회
		const email = Email.create(socialProfile.email);
		let user = await this.userRepository.findByEmail(email);

		if (user) {
			// 기존 사용자가 있는 경우
			if (user.isLocalAccount()) {
				// 로컬 계정이 있는 경우 - 계정 연결 제안
				throw new UserAlreadyExistsException(
					`Local account exists. Please login and link your ${dto.provider} account.`,
				);
			}

			// 같은 소셜 계정인지 확인
			if (
				user.getProvider()?.getValue() !== dto.provider ||
				user.getProviderId() !== socialProfile.id
			) {
				// 다른 소셜 계정으로 등록된 이메일
				throw new UserAlreadyExistsException(
					`Email is already registered with ${user.getProvider()?.getValue()}.`,
				);
			}

			// 기존 소셜 계정으로 로그인
			user.updateLastLoginAt();
		} else {
			// 새 소셜 사용자 생성
			user = await this.userDomainService.createOrGetSocialUser(
				email,
				this.mapProviderToAuthProvider(dto.provider),
				socialProfile.id,
			);

			// 사용자 등록 이벤트 발행
			const registerEvent = new UserRegisteredEvent(
				user.getId(),
				user.getEmail().getValue(),
				dto.provider,
				user.isEmailVerified(),
			);
			this.eventEmitter.emit("user.registered", registerEvent);
		}

		// 사용자 저장
		const savedUser = await this.userRepository.save(user);

		// 토큰 생성
		const tokens = await this.jwtService.generateTokenPair(
			savedUser.getId(),
			savedUser.getEmail().getValue(),
		);

		// 로그인 이벤트 발행
		const loginEvent = new UserLoggedInEvent(
			savedUser.getId(),
			savedUser.getEmail().getValue(),
			"unknown-ip", // TODO: 실제 IP 추출
			"unknown-user-agent", // TODO: 실제 User-Agent 추출
			`${dto.provider}-oauth`,
		);
		this.eventEmitter.emit("user.logged.in", loginEvent);

		// 응답 생성
		const userInfo = this.createUserInfoDto(savedUser);
		return new AuthResponseDto(
			tokens.accessToken,
			tokens.refreshToken,
			userInfo,
		);
	}

	/**
	 * 소셜 계정 연결
	 */
	async linkAccount(userId: string, dto: LinkAccountRequestDto): Promise<void> {
		// 1. 현재 사용자 조회
		const userIdVO = UserId.create(userId);
		const user = await this.userRepository.findById(userIdVO);

		if (!user) {
			throw new UserNotFoundException(userId);
		}

		// 2. 소셜 제공자에서 사용자 정보 가져오기
		const socialProfile = await this.getSocialProfile(dto.provider, dto.code);

		// 3. 해당 소셜 계정이 다른 사용자에게 연결되어 있는지 확인
		const existingSocialUser =
			await this.userRepository.findByProviderAndProviderId(
				this.mapProviderToAuthProvider(dto.provider),
				socialProfile.id,
			);

		if (existingSocialUser && existingSocialUser.getId() !== user.getId()) {
			throw new Error("This social account is already linked to another user");
		}

		// 4. 계정 연결 (도메인 서비스 사용)
		await this.userDomainService.linkSocialAccount(
			userId,
			this.mapProviderToAuthProvider(dto.provider),
			socialProfile.id,
		);
	}

	/**
	 * 소셜 계정 연결 해제
	 */
	async unlinkAccount(
		userId: string,
		dto: UnlinkAccountRequestDto,
	): Promise<void> {
		// 1. 사용자 조회
		const userIdVO = UserId.create(userId);
		const user = await this.userRepository.findById(userIdVO);

		if (!user) {
			throw new UserNotFoundException(userId);
		}

		// 2. 연결 해제할 수 있는지 확인
		if (
			user.isSocialAccount() &&
			user.getProvider()?.getValue() === dto.provider
		) {
			// 유일한 로그인 방법인 소셜 계정을 해제하려는 경우
			if (!user.getPasswordHash()) {
				throw new Error(
					"Cannot unlink the only authentication method. Please set a password first.",
				);
			}
		}

		// 3. 연결 해제 처리
		// TODO: User 엔티티에 unlinkSocialAccount 메서드 구현 필요
		// 현재는 에러 발생
		throw new Error("Social account unlinking is not implemented yet");
	}

	/**
	 * 사용자의 연결된 소셜 계정 목록 조회
	 */
	async getLinkedAccounts(userId: string): Promise<SocialAccountDto[]> {
		// 1. 사용자 조회
		const userIdVO = UserId.create(userId);
		const user = await this.userRepository.findById(userIdVO);

		if (!user) {
			throw new UserNotFoundException(userId);
		}

		// 2. 연결된 계정 정보 구성
		const linkedAccounts: SocialAccountDto[] = [];

		if (user.isSocialAccount() && user.getProvider() && user.getProviderId()) {
			linkedAccounts.push(
				new SocialAccountDto(
					user.getProvider().getValue(),
					user.getProviderId(),
					true,
					user.getEmail().getValue(),
					user.getCreatedAt(),
				),
			);
		}

		return linkedAccounts;
	}

	/**
	 * 소셜 로그인 URL 생성
	 */
	async generateAuthUrl(provider: Provider): Promise<string> {
		// TODO: 실제 OAuth URL 생성 로직 구현
		const baseUrls = {
			[Provider.GOOGLE]: "https://accounts.google.com/oauth/authorize",
			[Provider.APPLE]: "https://appleid.apple.com/auth/authorize",
		};

		const clientIds = {
			[Provider.GOOGLE]: process.env.GOOGLE_CLIENT_ID,
			[Provider.APPLE]: process.env.APPLE_CLIENT_ID,
		};

		const redirectUris = {
			[Provider.GOOGLE]: process.env.GOOGLE_CALLBACK_URL,
			[Provider.APPLE]: process.env.APPLE_CALLBACK_URL,
		};

		const baseUrl = baseUrls[provider];
		const clientId = clientIds[provider];
		const redirectUri = redirectUris[provider];

		if (!baseUrl || !clientId || !redirectUri) {
			throw new Error(`${provider} OAuth is not configured`);
		}

		const params = new URLSearchParams({
			client_id: clientId,
			redirect_uri: redirectUri,
			response_type: "code",
			scope:
				provider === Provider.GOOGLE ? "openid email profile" : "email name",
			state: this.generateStateParameter(),
		});

		return `${baseUrl}?${params.toString()}`;
	}

	/**
	 * 소셜 제공자에서 사용자 프로필 정보 가져오기 (private)
	 */
	private async getSocialProfile(
		provider: Provider,
		code: string,
	): Promise<SocialProfileDto> {
		switch (provider) {
			case Provider.GOOGLE:
				return this.getGoogleProfile(code);
			case Provider.APPLE:
				return this.getAppleProfile(code);
			default:
				throw new Error(`Unsupported social provider: ${provider}`);
		}
	}

	/**
	 * Google 프로필 정보 가져오기 (private)
	 */
	private async getGoogleProfile(code: string): Promise<SocialProfileDto> {
		// TODO: 실제 Google OAuth API 호출 구현
		// 현재는 Mock 데이터 반환
		const mockProfile: GoogleUserInfoDto = {
			sub: `google_${Date.now()}`,
			email: "user@example.com",
			email_verified: true,
			name: "Test User",
			picture: "https://example.com/avatar.jpg",
		};

		return new SocialProfileDto(
			mockProfile.sub,
			mockProfile.email,
			Provider.GOOGLE,
			mockProfile.name,
			undefined,
			undefined,
			mockProfile.picture,
		);
	}

	/**
	 * Apple 프로필 정보 가져오기 (private)
	 */
	private async getAppleProfile(code: string): Promise<SocialProfileDto> {
		// TODO: 실제 Apple OAuth API 호출 구현
		// 현재는 Mock 데이터 반환
		const mockProfile: AppleUserInfoDto = {
			sub: `apple_${Date.now()}`,
			email: "user@example.com",
			name: {
				firstName: "Test",
				lastName: "User",
			},
		};

		return new SocialProfileDto(
			mockProfile.sub,
			mockProfile.email || "",
			Provider.APPLE,
			undefined,
			mockProfile.name?.firstName,
			mockProfile.name?.lastName,
		);
	}

	/**
	 * Provider enum을 AuthProvider로 매핑 (private)
	 */
	private mapProviderToAuthProvider(provider: Provider): any {
		// TODO: AuthProvider 타입 import 및 실제 매핑
		// 현재는 단순 반환
		return provider;
	}

	/**
	 * OAuth state 매개변수 생성 (private)
	 */
	private generateStateParameter(): string {
		return (
			Math.random().toString(36).substring(2, 15) +
			Math.random().toString(36).substring(2, 15)
		);
	}

	/**
	 * UserInfoDto 생성 헬퍼 (private)
	 */
	private createUserInfoDto(user: User): UserInfoDto {
		return new UserInfoDto(
			user.getId(),
			user.getEmail().getValue(),
			user.getProvider()?.getValue() || Provider.LOCAL,
			user.isActive(),
			user.isEmailVerified(),
			user.getCreatedAt(),
			user.getLastLoginAt(),
		);
	}
}
