import { Provider, ProviderUtils } from "@shared/enum/provider.enum";
import { ValueObject } from "@shared/type/common.type";
import { DomainException } from "../exception/domain.exception";

export class InvalidProviderException extends DomainException {
	readonly code = "INVALID_PROVIDER";
	readonly statusCode = 400;

	constructor(provider: string) {
		super(`Invalid authentication provider: ${provider}`, { provider });
	}
}

export class AuthProvider implements ValueObject<AuthProvider> {
	private constructor(private readonly value: Provider) {
		this.validate(value);
	}

	static create(provider: string): AuthProvider {
		return new AuthProvider(provider as Provider);
	}

	static createLocal(): AuthProvider {
		return new AuthProvider(Provider.LOCAL);
	}

	static createGoogle(): AuthProvider {
		return new AuthProvider(Provider.GOOGLE);
	}

	static createApple(): AuthProvider {
		return new AuthProvider(Provider.APPLE);
	}

	private validate(provider: Provider): void {
		if (!ProviderUtils.isValidProvider(provider)) {
			throw new InvalidProviderException(provider);
		}
	}

	getValue(): Provider {
		return this.value;
	}

	isLocal(): boolean {
		return ProviderUtils.isLocalProvider(this.value);
	}

	isSocial(): boolean {
		return ProviderUtils.isSocialProvider(this.value);
	}

	isGoogle(): boolean {
		return this.value === Provider.GOOGLE;
	}

	isApple(): boolean {
		return this.value === Provider.APPLE;
	}

	equals(other: AuthProvider): boolean {
		if (!(other instanceof AuthProvider)) {
			return false;
		}
		return this.value === other.getValue();
	}

	toString(): string {
		return this.value;
	}

	toJSON(): Record<string, any> {
		return { provider: this.value };
	}
}
