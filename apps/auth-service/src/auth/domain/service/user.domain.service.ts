import { Inject, Injectable } from "@nestjs/common";
import * as bcrypt from "bcrypt";
import {
	InvalidCredentialsException,
	IUserRepository,
	USER_REPOSITORY_TOKEN,
	User,
	UserAlreadyExistsException,
} from "@/auth/domain";
import { AuthProvider, Email, Password, UserId } from "@/auth/domain/vo";

/**
 * 사용자 도메인 서비스
 * 복잡한 비즈니스 로직과 도메인 규칙을 처리
 */
@Injectable()
export class UserDomainService {

	private static readonly SALT_ROUNDS = 12;
	constructor(
		@Inject(USER_REPOSITORY_TOKEN)
		private readonly userRepository: IUserRepository
	) {}

	/**
	 * 새로운 로컬 사용자 생성
	 * 이메일 중복 검사와 비밀번호 해싱을 포함
	 */
	async createLocalUser(email: Email, password: Password): Promise<User> {
		// 이메일 중복 검사
		const existingUser = await this.userRepository.findByEmail(email);
		if (existingUser) {
			throw new UserAlreadyExistsException(email.getValue());
		}

		// 소셜 계정과 이메일 중복 검사
		const socialUserExists = await this.checkSocialUserWithEmail(email);
		if (socialUserExists) {
			throw new UserAlreadyExistsException(email.getValue());
		}

		// 비밀번호 해싱
		const hashedPassword = await this.hashPassword(password);

		// 사용자 생성 (해시된 비밀번호만 전달)
		const user = User.create({
			email,
			passwordHash: hashedPassword,
			provider: AuthProvider.createLocal(),
			isEmailVerified: false, // 로컬 계정은 이메일 인증 필요
		});

		return user;
	}

	/**
	 * 소셜 로그인 사용자 생성 또는 조회
	 */
	async createOrGetSocialUser(
		email: Email,
		provider: AuthProvider,
		providerId: string,
	): Promise<User> {
		// 동일한 제공자와 제공자 ID로 기존 사용자 조회
		const existingUser = await this.userRepository.findByProviderAndProviderId(
			provider,
			providerId,
		);

		if (existingUser) {
			return existingUser;
		}

		// 동일한 이메일의 로컬 계정이 있는지 확인
		const localUser = await this.userRepository.findByEmail(email);
		if (localUser && localUser.isLocalAccount()) {
			throw new UserAlreadyExistsException(
				`Local account already exists with email: ${email.getValue()}`,
			);
		}

		// 새로운 소셜 사용자 생성
		const user = User.createFromSocial(email, provider, providerId);
		return user;
	}

	/**
	 * 사용자 인증 (로컬 계정)
	 */
	async authenticateUser(email: Email, plainPassword: string): Promise<User> {
		const user = await this.userRepository.findByEmail(email);

		if (!user) {
			throw new InvalidCredentialsException();
		}

		if (!user.isLocalAccount()) {
			throw new InvalidCredentialsException(
				"This email is associated with a social account",
			);
		}

		if (!user.isActive()) {
			throw new InvalidCredentialsException("Account is not active");
		}

		// 비밀번호 검증
		const hashedPassword = user.getPasswordHash();
		if (!hashedPassword) {
			throw new InvalidCredentialsException("No password hash found");
		}

		const isPasswordValid = await this.verifyPassword(
			plainPassword,
			hashedPassword,
		);

		if (!isPasswordValid) {
			throw new InvalidCredentialsException();
		}

		// 로그인 시간 업데이트
		user.updateLastLoginAt();

		return user;
	}

	/**
	 * 비밀번호 해싱
	 */
	async hashPassword(password: Password): Promise<string> {
		return bcrypt.hash(password.getValue(), UserDomainService.SALT_ROUNDS);
	}

	/**
	 * 비밀번호 검증
	 */
	async verifyPassword(
		plainPassword: string,
		hashedPassword: string,
	): Promise<boolean> {
		return bcrypt.compare(plainPassword, hashedPassword);
	}

	/**
	 * 이메일로 소셜 사용자 존재 여부 확인
	 */
	private async checkSocialUserWithEmail(email: Email): Promise<boolean> {
		// Google 계정 확인
		const googleUser = await this.userRepository.findByProviderAndProviderId(
			AuthProvider.createGoogle(),
			email.getValue(), // 일부 소셜 제공자는 이메일을 ID로 사용
		);

		if (googleUser) return true;

		// Apple 계정 확인
		const appleUser = await this.userRepository.findByProviderAndProviderId(
			AuthProvider.createApple(),
			email.getValue(),
		);

		return !!appleUser;
	}

	/**
	 * 사용자 계정 병합 (소셜 → 로컬 또는 로컬 → 소셜)
	 * 복잡한 비즈니스 로직이므로 도메인 서비스에서 처리
	 */
	async linkSocialAccount(
		userId: string,
		provider: AuthProvider,
		providerId: string,
	): Promise<User> {
		const user = await this.userRepository.findById(UserId.create(userId));
		if (!user) {
			throw new Error("User not found");
		}

		// 이미 다른 소셜 계정이 연결되어 있는지 확인
		if (user.isSocialAccount() && !user.getProvider()?.equals(provider)) {
			throw new Error("Another social account is already linked");
		}

		// 해당 소셜 계정이 이미 다른 사용자에게 연결되어 있는지 확인
		const existingSocialUser =
			await this.userRepository.findByProviderAndProviderId(
				provider,
				providerId,
			);

		if (existingSocialUser && !existingSocialUser.equals(user)) {
			throw new Error("This social account is already linked to another user");
		}

		// 소셜 계정 연결 (실제 구현에서는 User 엔티티에 메서드 추가)
		// user.linkSocialAccount(provider, providerId);

		return user;
	}

	/**
	 * 비밀번호 변경
	 */
	async changePassword(
		userId: string,
		currentPassword: string,
		newPassword: Password,
	): Promise<User> {
		const user = await this.userRepository.findById(UserId.create(userId));
		if (!user) {
			throw new Error("User not found");
		}

		if (!user.isLocalAccount()) {
			throw new Error("Cannot change password for social accounts");
		}

		// 현재 비밀번호 검증
		const currentHashedPassword = user.getPasswordHash();
		if (!currentHashedPassword) {
			throw new InvalidCredentialsException("No password hash found");
		}

		const isCurrentPasswordValid = await this.verifyPassword(
			currentPassword,
			currentHashedPassword,
		);

		if (!isCurrentPasswordValid) {
			throw new InvalidCredentialsException("Current password is incorrect");
		}

		// 새 비밀번호 해싱
		const newHashedPassword = await this.hashPassword(newPassword);

		// 비밀번호 해시 업데이트
		user.changePasswordHash(newHashedPassword);

		return user;
	}

	/**
	 * 계정 삭제 전 검증
	 */
	async validateAccountDeletion(userId: string): Promise<void> {
		const user = await this.userRepository.findById(UserId.create(userId));
		if (!user) {
			throw new Error("User not found");
		}

		// 관리자 계정 삭제 방지 등의 비즈니스 규칙
		// if (user.isAdmin()) {
		//   throw new Error('Cannot delete admin account');
		// }

		// 활성 세션이 있는지 확인 등의 추가 검증
		// const activeSessions = await this.getActiveSessionCount(userId);
		// if (activeSessions > 1) {
		//   throw new Error('Please log out from all devices before deleting account');
		// }
	}
}
