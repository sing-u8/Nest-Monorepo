export enum Provider {
	LOCAL = "local",
	GOOGLE = "google",
	APPLE = "apple",
}

export const SOCIAL_PROVIDERS = [Provider.GOOGLE, Provider.APPLE] as const;

export type SocialProvider = (typeof SOCIAL_PROVIDERS)[number];

// biome-ignore lint/complexity/noStaticOnlyClass:only static methods are needed
export class ProviderUtils {
	static isValidProvider(value: string): value is Provider {
		return Object.values(Provider).includes(value as Provider);
	}

	static isSocialProvider(provider: Provider): provider is SocialProvider {
		return SOCIAL_PROVIDERS.includes(provider as SocialProvider);
	}

	static isLocalProvider(provider: Provider): boolean {
		return provider === Provider.LOCAL;
	}
}
