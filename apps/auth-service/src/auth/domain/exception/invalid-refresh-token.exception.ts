import { DomainException } from "./domain.exception";

export class InvalidRefreshTokenException extends DomainException {
	readonly code = "INVALID_REFRESH_TOKEN";
	readonly statusCode = 401;

	constructor(reason?: string) {
		const message = reason
			? `Invalid refresh token: ${reason}`
			: "Invalid refresh token";
		super(message, { reason });
	}
}
