import { Provider } from "../enum/provider.enum";

export type UserId = string;
export type Email = string;
export type HashedPassword = string;
export type PlainPassword = string;
export type JwtToken = string;
export type RefreshToken = string;
export type ProviderId = string;
export type DeviceInfo = string;
export type IpAddress = string;

export interface DomainEntityProps {
	id: UserId;
	createdAt: Date;
	updatedAt: Date;
}

export interface CreateUserProps {
	email: Email;
	password?: PlainPassword;
	provider?: Provider;
	providerId?: ProviderId;
}

export interface CreateRefreshTokenProps {
	userId: UserId;
	token: RefreshToken;
	expiresAt: Date;
	deviceInfo?: DeviceInfo;
	ipAddress?: IpAddress;
}

export interface TokenPair {
	accessToken: JwtToken;
	refreshToken: RefreshToken;
}

export interface AuthResult {
	user: {
		id: UserId;
		email: Email;
		provider: Provider;
		isEmailVerified: boolean;
		lastLoginAt?: Date;
	};
	tokens: TokenPair;
}
