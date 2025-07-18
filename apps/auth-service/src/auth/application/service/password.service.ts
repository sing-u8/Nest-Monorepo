import { Injectable, Inject } from "@nestjs/common";
import { User } from '@/auth/domain';
import {
	InvalidCredentialsException,
	UserNotFoundException,
} from '@/auth/domain';
import { IUserRepository, USER_REPOSITORY_TOKEN } from '@/auth/domain';
import { PasswordDomainService } from '@/auth/domain';
import { Email, Password, UserId } from '@/auth/domain';

/**
 * 비밀번호 관련 요청 DTO들
 */
export class ForgotPasswordDto {
	email: string;
}

export class ResetPasswordDto {
	token: string;
	newPassword: string;
}

export class ValidatePasswordStrengthDto {
	password: string;
}

export class PasswordStrengthResult {
	score: number; // 1-5 점수
	feedback: string[];
	isStrong: boolean;

	constructor(score: number, feedback: string[], isStrong: boolean) {
		this.score = score;
		this.feedback = feedback;
		this.isStrong = isStrong;
	}
}

/**
 * 비밀번호 애플리케이션 서비스
 * 비밀번호 재설정, 강도 검증, 정책 관리 등을 담당
 */
@Injectable()
export class PasswordApplicationService {
	@Inject(USER_REPOSITORY_TOKEN)
	private readonly userRepository: IUserRepository;

	constructor(
		private readonly passwordDomainService: PasswordDomainService,
	) {}

	/**
	 * 비밀번호 찾기 (재설정 이메일 발송)
	 */
	async forgotPassword(dto: ForgotPasswordDto): Promise<void> {
		// 이메일로 사용자 조회
		const email = Email.create(dto.email);
		const user = await this.userRepository.findByEmail(email);

		// 보안을 위해 사용자 존재 여부에 관계없이 성공 응답
		// 실제 사용자가 있는 경우에만 이메일 발송
		if (user?.isLocalAccount()) {
			await this.sendPasswordResetEmail(user);
		}

		// 항상 성공 응답 (보안)
	}

	/**
	 * 비밀번호 재설정
	 */
	async resetPassword(dto: ResetPasswordDto): Promise<void> {
		// 1. 재설정 토큰 검증
		const userId = await this.validateResetToken(dto.token);

		// 2. 사용자 조회
		const userIdVO = UserId.create(userId);
		const user = await this.userRepository.findById(userIdVO);

		if (!user) {
			throw new UserNotFoundException(userId);
		}

		// 3. 로컬 계정인지 확인
		if (!user.isLocalAccount()) {
			throw new Error("Cannot reset password for social accounts");
		}

		// 4. 새 비밀번호 해싱 및 업데이트
		const newPassword = Password.create(dto.newPassword);
		const newHashedPassword =
			await this.passwordDomainService.hashPassword(newPassword);

		user.changePasswordHash(newHashedPassword);

		// 5. 저장
		await this.userRepository.save(user);

		// 6. 재설정 토큰 무효화
		await this.invalidateResetToken(dto.token);

		// 7. 보안 알림 이메일 발송 (선택사항)
		await this.sendPasswordChangedNotification(user);
	}

	/**
	 * 비밀번호 강도 검증
	 */
	async validatePasswordStrength(
		dto: ValidatePasswordStrengthDto,
	): Promise<PasswordStrengthResult> {
		try {
			const password = Password.create(dto.password);

			// 도메인 서비스에서 비밀번호 강도 평가
			const strength =
				this.passwordDomainService.evaluatePasswordStrength(password);

			return new PasswordStrengthResult(
				strength.score,
				strength.feedback,
				strength.score >= 4, // 4점 이상을 강한 비밀번호로 간주
			);
		} catch (error) {
			// 비밀번호 검증 실패 시 가장 낮은 점수 반환
			return new PasswordStrengthResult(
				1,
				[
					error instanceof Error
						? error.message
						: "비밀번호가 유효하지 않습니다.",
				],
				false,
			);
		}
	}

	/**
	 * 임시 비밀번호 생성 및 설정
	 */
	async generateTemporaryPassword(userId: string): Promise<string> {
		// 사용자 조회
		const userIdVO = UserId.create(userId);
		const user = await this.userRepository.findById(userIdVO);

		if (!user) {
			throw new UserNotFoundException(userId);
		}

		// 로컬 계정인지 확인
		if (!user.isLocalAccount()) {
			throw new Error("Cannot generate temporary password for social accounts");
		}

		// 임시 비밀번호 생성
		const temporaryPassword =
			this.passwordDomainService.generateTemporaryPassword();

		// 해싱 및 설정
		const hashedPassword =
			await this.passwordDomainService.hashPassword(temporaryPassword);
		user.changePasswordHash(hashedPassword);

		// 저장
		await this.userRepository.save(user);

		// 임시 비밀번호 이메일 발송
		await this.sendTemporaryPasswordEmail(user, temporaryPassword.getValue());

		return temporaryPassword.getValue();
	}

	/**
	 * 비밀번호 정책 조회
	 */
	getPasswordPolicy(): {
		minLength: number;
		maxLength: number;
		requireUppercase: boolean;
		requireLowercase: boolean;
		requireNumbers: boolean;
		requireSpecialChars: boolean;
		forbidCommonPasswords: boolean;
		maxConsecutiveChars: number;
	} {
		return {
			minLength: 8,
			maxLength: 128,
			requireUppercase: true,
			requireLowercase: true,
			requireNumbers: true,
			requireSpecialChars: true,
			forbidCommonPasswords: true,
			maxConsecutiveChars: 3,
		};
	}

	/**
	 * 비밀번호 만료 확인
	 */
	async checkPasswordExpiry(userId: string): Promise<{
		isExpired: boolean;
		expiresAt?: Date;
		daysUntilExpiry?: number;
	}> {
		// TODO: 비밀번호 만료 정책 구현
		// 현재는 만료 없음으로 설정
		return {
			isExpired: false,
			expiresAt: undefined,
			daysUntilExpiry: undefined,
		};
	}

	/**
	 * 비밀번호 재설정 이메일 발송 (private)
	 */
	private async sendPasswordResetEmail(user: User): Promise<void> {
		// 1. 재설정 토큰 생성
		const resetToken = await this.generateResetToken(user.getId());

		// 2. 이메일 발송
		// TODO: 이메일 서비스 연동 (Phase 4에서 구현)
		console.log(`비밀번호 재설정 이메일 발송: ${user.getEmail().getValue()}`);
		console.log(`재설정 토큰: ${resetToken}`);
	}

	/**
	 * 재설정 토큰 생성 (private)
	 */
	private async generateResetToken(userId: string): Promise<string> {
		// TODO: JWT 또는 별도 토큰 생성 로직 구현
		// 현재는 간단한 토큰 생성
		const token = `reset_${userId}_${Date.now()}`;

		// TODO: 토큰을 Redis나 DB에 저장하여 유효성 관리
		return token;
	}

	/**
	 * 재설정 토큰 검증 (private)
	 */
	private async validateResetToken(token: string): Promise<string> {
		// TODO: 실제 토큰 검증 로직 구현
		// 현재는 토큰에서 사용자 ID 추출한다고 가정

		if (!token.startsWith("reset_")) {
			throw new Error("Invalid reset token format");
		}

		const parts = token.split("_");
		if (parts.length !== 3) {
			throw new Error("Invalid reset token format");
		}

		const userId = parts[1];
		const timestamp = parseInt(parts[2], 10);

		// 토큰 만료 확인 (24시간)
		const now = Date.now();
		const expiry = 24 * 60 * 60 * 1000; // 24시간

		if (now - timestamp > expiry) {
			throw new Error("Reset token has expired");
		}

		return userId;
	}

	/**
	 * 재설정 토큰 무효화 (private)
	 */
	private async invalidateResetToken(token: string): Promise<void> {
		// TODO: Redis나 DB에서 토큰 제거
		console.log(`재설정 토큰 무효화: ${token}`);
	}

	/**
	 * 비밀번호 변경 알림 이메일 발송 (private)
	 */
	private async sendPasswordChangedNotification(user: User): Promise<void> {
		// TODO: 이메일 서비스 연동
		console.log(
			`비밀번호 변경 알림 이메일 발송: ${user.getEmail().getValue()}`,
		);
	}

	/**
	 * 임시 비밀번호 이메일 발송 (private)
	 */
	private async sendTemporaryPasswordEmail(
		user: User,
		temporaryPassword: string,
	): Promise<void> {
		// TODO: 이메일 서비스 연동
		console.log(`임시 비밀번호 이메일 발송: ${user.getEmail().getValue()}`);
		console.log(`임시 비밀번호: ${temporaryPassword}`);
	}
}
