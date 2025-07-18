export abstract class DomainException extends Error {
	abstract readonly code: string;
	abstract readonly statusCode: number;

	protected constructor(
		message: string,
		public readonly details?: any,
	) {
		super(message);
		this.name = this.constructor.name;
	}

	toJSON() {
		return {
			name: this.name,
			code: this.code,
			message: this.message,
			statusCode: this.statusCode,
			details: this.details,
		};
	}
}
