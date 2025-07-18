import { ValueObject } from "@shared/type/common.type";
import { DomainException } from "../exception/domain.exception";

export class InvalidPasswordException extends DomainException {
	readonly code = "INVALID_PASSWORD";
	readonly statusCode = 400;

	constructor(reason: string) {
		super(`Invalid password: ${reason}`);
	}
}

export class Password implements ValueObject<Password> {
	private static readonly MIN_LENGTH = 8;
	private static readonly MAX_LENGTH = 128;
	private static readonly UPPERCASE_REGEX = /[A-Z]/;
	private static readonly LOWERCASE_REGEX = /[a-z]/;
	private static readonly NUMBER_REGEX = /[0-9]/;
	private static readonly SPECIAL_CHAR_REGEX = /[!@#$%^&*(),.?":{}|<>]/;

	private constructor(private readonly value: string) {
		this.validate(value);
	}

	static create(password: string): Password {
		return new Password(password);
	}

	private validate(password: string): void {
		if (!password || typeof password !== "string") {
			throw new InvalidPasswordException("Password is required");
		}

		if (password.length < Password.MIN_LENGTH) {
			throw new InvalidPasswordException(
				`Password must be at least ${Password.MIN_LENGTH} characters long`,
			);
		}

		if (password.length > Password.MAX_LENGTH) {
			throw new InvalidPasswordException(
				`Password must not exceed ${Password.MAX_LENGTH} characters`,
			);
		}

		if (!Password.UPPERCASE_REGEX.test(password)) {
			throw new InvalidPasswordException(
				"Password must contain at least one uppercase letter",
			);
		}

		if (!Password.LOWERCASE_REGEX.test(password)) {
			throw new InvalidPasswordException(
				"Password must contain at least one lowercase letter",
			);
		}

		if (!Password.NUMBER_REGEX.test(password)) {
			throw new InvalidPasswordException(
				"Password must contain at least one number",
			);
		}

		if (!Password.SPECIAL_CHAR_REGEX.test(password)) {
			throw new InvalidPasswordException(
				"Password must contain at least one special character",
			);
		}

		// 연속된 문자 체크
		// if (this.hasConsecutiveCharacters(password)) {
		// 	throw new InvalidPasswordException(
		// 		'Password must not contain more than 2 consecutive identical characters',
		// 	);
		// }
	}

	// private hasConsecutiveCharacters(password: string): boolean {
	// 	for (let i = 0; i < password.length - 2; i++) {
	// 		if (
	// 			password[i] === password[i + 1] &&
	// 			password[i + 1] === password[i + 2]
	// 		) {
	// 			return true;
	// 		}
	// 	}
	// 	return false;
	// }

	getValue(): string {
		return this.value;
	}

	getStrength(): number {
		let strength = 0;

		// 기본 요구사항 충족시 2점
		if (this.value.length >= Password.MIN_LENGTH) strength += 2;

		// 추가 조건들로 점수 증가
		if (this.value.length >= 12) strength += 1;
		if (/[A-Z].*[A-Z]/.test(this.value)) strength += 0.5;
		if (/[0-9].*[0-9]/.test(this.value)) strength += 0.5;
		if (/[!@#$%^&*(),.?":{}|<>].*[!@#$%^&*(),.?":{}|<>]/.test(this.value))
			strength += 1;

		return Math.min(5, Math.ceil(strength));
	}

	equals(other: Password): boolean {
		if (!(other instanceof Password)) {
			return false;
		}
		return this.value === other.getValue();
	}

	toJSON(): Record<string, any> {
		return {
			password: {
				length: this.value.length,
				strength: this.getStrength(),
			},
		};
	}
}
