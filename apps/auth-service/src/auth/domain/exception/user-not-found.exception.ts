import { DomainException } from "./domain.exception";

export class UserNotFoundException extends DomainException {
	readonly code = "USER_NOT_FOUND";
	readonly statusCode = 404;

	constructor(identifier: string, identifierType: "id" | "email" = "id") {
		super(`User not found with ${identifierType}: ${identifier}`, {
			identifier,
			identifierType,
		});
	}
}
