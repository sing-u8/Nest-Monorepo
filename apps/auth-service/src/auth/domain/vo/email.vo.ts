import { ValueObject } from "@shared/type/common.type";
import { DomainException } from "../exception/domain.exception";

export class InvalidEmailException extends DomainException {
	readonly code = "INVALID_EMAIL";
	readonly statusCode = 400;

	constructor(email: string) {
		super(`Invalid email format: ${email}`, { email });
	}
}

export class Email implements ValueObject<Email> {
	private static readonly EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	private static readonly MAX_LENGTH = 254; // RFC 5321 표준

	private constructor(private readonly value: string) {
		this.validate(value);
	}

	static create(email: string): Email {
		return new Email(email);
	}

	private validate(email: string): void {
		if (!email || typeof email !== "string") {
			throw new InvalidEmailException(email);
		}

		const trimmedEmail = email.trim().toLowerCase();

		if (trimmedEmail.length === 0) {
			throw new InvalidEmailException(email);
		}

		if (trimmedEmail.length > Email.MAX_LENGTH) {
			throw new InvalidEmailException(email);
		}

		if (!Email.EMAIL_REGEX.test(trimmedEmail)) {
			throw new InvalidEmailException(email);
		}
	}

	getValue(): string {
		return this.value.trim().toLowerCase();
	}

	getDomain(): string {
		return this.getValue().split("@")[1];
	}

	getLocalPart(): string {
		return this.getValue().split("@")[0];
	}

	equals(other: Email): boolean {
		if (!(other instanceof Email)) {
			return false;
		}
		return this.getValue() === other.getValue();
	}

	toString(): string {
		return this.getValue();
	}

	toJSON(): Record<string, any> {
		return {
			email: this.getValue(),
		};
	}
}
