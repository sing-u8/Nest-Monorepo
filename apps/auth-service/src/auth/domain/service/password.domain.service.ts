import { Injectable } from "@nestjs/common";
import * as bcrypt from "bcrypt";
import { Password } from "@/auth/domain/vo";

/**
 * 비밀번호 도메인 서비스
 * 비밀번호 해싱, 검증, 정책 관련 로직을 처리
 */
@Injectable()
export class PasswordDomainService {
	private static readonly SALT_ROUNDS = 12;
	private static readonly PEPPER =
		process.env.PASSWORD_PEPPER || "default-pepper";

	/**
	 * 비밀번호 해싱
	 */
	async hashPassword(password: Password): Promise<string> {
		const passwordWithPepper =
			password.getValue() + PasswordDomainService.PEPPER;
		return bcrypt.hash(passwordWithPepper, PasswordDomainService.SALT_ROUNDS);
	}

	/**
	 * 비밀번호 검증
	 */
	async verifyPassword(
		plainPassword: string,
		hashedPassword: string,
	): Promise<boolean> {
		const passwordWithPepper = plainPassword + PasswordDomainService.PEPPER;
		return bcrypt.compare(passwordWithPepper, hashedPassword);
	}

	/**
	 * 비밀번호 강도 평가
	 */
	evaluatePasswordStrength(password: Password): {
		score: number;
		feedback: string[];
		isAcceptable: boolean;
	} {
		const strength = password.getStrength();
		const feedback: string[] = [];

		if (strength < 3) {
			feedback.push("비밀번호가 너무 약합니다");
			if (password.getValue().length < 12) {
				feedback.push("12자 이상으로 설정하세요");
			}
			feedback.push("특수문자와 숫자를 더 추가하세요");
		} else if (strength < 4) {
			feedback.push("비밀번호 강도가 보통입니다");
			feedback.push("더 안전하게 하려면 길이를 늘리거나 복잡성을 높이세요");
		} else {
			feedback.push("강력한 비밀번호입니다");
		}

		return {
			score: strength,
			feedback,
			isAcceptable: strength >= 3,
		};
	}

	/**
	 * 비밀번호 변경 가능 여부 확인
	 */
	canChangePassword(
		currentPassword: string,
		newPassword: Password,
		lastPasswordChange?: Date,
	): {
		canChange: boolean;
		reason?: string;
	} {
		// 현재 비밀번호와 동일한지 확인
		if (currentPassword === newPassword.getValue()) {
			return {
				canChange: false,
				reason: "새 비밀번호는 현재 비밀번호와 달라야 합니다",
			};
		}

		// 최근 비밀번호 변경 시간 확인 (예: 24시간 제한)
		if (lastPasswordChange) {
			const timeDiff = new Date().getTime() - lastPasswordChange.getTime();
			const hoursDiff = timeDiff / (1000 * 60 * 60);

			if (hoursDiff < 24) {
				return {
					canChange: false,
					reason: "비밀번호는 24시간마다 한 번만 변경할 수 있습니다",
				};
			}
		}

		// 비밀번호 강도 확인
		const strengthCheck = this.evaluatePasswordStrength(newPassword);
		if (!strengthCheck.isAcceptable) {
			return {
				canChange: false,
				reason: "비밀번호가 보안 정책을 만족하지 않습니다",
			};
		}

		return { canChange: true };
	}

	/**
	 * 임시 비밀번호 생성
	 */
	generateTemporaryPassword(): Password {
		const lowercase = "abcdefghijklmnopqrstuvwxyz";
		const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		const numbers = "0123456789";
		const symbols = "!@#$%^&*";

		let password = "";

		// 각 카테고리에서 최소 1개씩
		password += this.getRandomChar(uppercase);
		password += this.getRandomChar(lowercase);
		password += this.getRandomChar(numbers);
		password += this.getRandomChar(symbols);

		// 나머지 8자리 랜덤 생성
		const allChars = lowercase + uppercase + numbers + symbols;
		for (let i = 0; i < 8; i++) {
			password += this.getRandomChar(allChars);
		}

		// 문자 섞기
		const shuffled = password
			.split("")
			.sort(() => Math.random() - 0.5)
			.join("");

		return Password.create(shuffled);
	}

	/**
	 * 비밀번호 정책 검증
	 */
	validatePasswordPolicy(password: Password): {
		isValid: boolean;
		violations: string[];
	} {
		const violations: string[] = [];
		const value = password.getValue();

		// 금지된 패턴 확인
		const forbiddenPatterns = [
			/(.)\1{2,}/, // 3개 이상 연속된 동일 문자
			/123456/, // 순차적 숫자
			/abcdef/, // 순차적 알파벳
			/qwerty/i, // 키보드 패턴
			/password/i, // 'password' 포함
		];

		for (const pattern of forbiddenPatterns) {
			if (pattern.test(value)) {
				violations.push("금지된 패턴이 포함되어 있습니다");
				break;
			}
		}

		// 사전 단어 확인 (간단한 예시)
		const commonWords = ["password", "admin", "user", "test", "1234"];
		for (const word of commonWords) {
			if (value.toLowerCase().includes(word)) {
				violations.push("일반적인 단어가 포함되어 있습니다");
				break;
			}
		}

		return {
			isValid: violations.length === 0,
			violations,
		};
	}

	/**
	 * 랜덤 문자 선택 헬퍼
	 */
	private getRandomChar(chars: string): string {
		return chars.charAt(Math.floor(Math.random() * chars.length));
	}

	/**
	 * 비밀번호 만료 확인
	 */
	isPasswordExpired(
		lastPasswordChange: Date,
		maxAgeDays: number = 90,
	): boolean {
		const daysDiff =
			(new Date().getTime() - lastPasswordChange.getTime()) /
			(1000 * 60 * 60 * 24);
		return daysDiff > maxAgeDays;
	}

	/**
	 * 비밀번호 만료까지 남은 일수
	 */
	getDaysUntilPasswordExpiry(
		lastPasswordChange: Date,
		maxAgeDays: number = 90,
	): number {
		const daysDiff =
			(new Date().getTime() - lastPasswordChange.getTime()) /
			(1000 * 60 * 60 * 24);
		return Math.max(0, maxAgeDays - Math.floor(daysDiff));
	}
}
