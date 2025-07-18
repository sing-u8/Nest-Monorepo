import { DomainException } from "./domain.exception";

export class UserAlreadyExistsException extends DomainException {
	readonly code = "USER_ALREADY_EXISTS";
	readonly statusCode = 409;

	constructor(email: string) {
		super(`User with email '${email}' already exists`, { email });
	}
}
