import { randomUUID } from "node:crypto";
import { ValueObject } from "@shared/type/common.type";
import { DomainException } from "../exception/domain.exception";

export class InvalidUserIdException extends DomainException {
	readonly code = "INVALID_USER_ID";
	readonly statusCode = 400;

	constructor(userId: string) {
		super(`Invalid user ID format: ${userId}`, { userId });
	}
}

export class UserId implements ValueObject<UserId> {
	private static readonly UUID_REGEX =
		/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

	private constructor(private readonly value: string) {
		this.validate(value);
	}

	static create(id: string): UserId {
		return new UserId(id);
	}

	static generate(): UserId {
		return new UserId(randomUUID());
	}

	private validate(id: string): void {
		if (!id || typeof id !== "string") {
			throw new InvalidUserIdException(id);
		}

		const trimmedId = id.trim();

		if (!UserId.UUID_REGEX.test(trimmedId)) {
			throw new InvalidUserIdException(id);
		}
	}

	getValue(): string {
		return this.value;
	}

	equals(other: UserId): boolean {
		if (!(other instanceof UserId)) {
			return false;
		}
		return this.value === other.getValue();
	}

	toString(): string {
		return this.value;
	}

	toJSON(): Record<string, any> {
		return { userId: this.value };
	}
}
