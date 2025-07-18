import { randomUUID } from "node:crypto";
import { DomainEntity } from "@shared/type/common.type";
import { UserId } from "@/auth/domain/vo";

export interface CreateRefreshTokenProps {
	userId: UserId;
	token: string;
	expiresAt: Date;
	deviceInfo?: string;
	ipAddress?: string;
}

export interface RefreshTokenProps extends CreateRefreshTokenProps {
	id: string;
	isActive: boolean;
	lastUsedAt?: Date;
	createdAt: Date;
}

export class RefreshToken implements DomainEntity<RefreshToken> {
	private constructor(private props: RefreshTokenProps) {
		this.validate();
	}

	static create(props: CreateRefreshTokenProps): RefreshToken {
		return new RefreshToken({
			id: randomUUID(),
			userId: props.userId,
			token: props.token,
			expiresAt: props.expiresAt,
			deviceInfo: props.deviceInfo,
			ipAddress: props.ipAddress,
			isActive: true,
			createdAt: new Date(),
		});
	}

	static fromPersistence(props: RefreshTokenProps): RefreshToken {
		return new RefreshToken(props);
	}

	private validate(): void {
		if (!this.props.userId) {
			throw new Error("User ID is required");
		}

		if (!this.props.token || this.props.token.trim().length === 0) {
			throw new Error("Token is required");
		}

		if (!this.props.expiresAt) {
			throw new Error("Expiration date is required");
		}

		if (this.props.expiresAt <= new Date()) {
			throw new Error("Token expiration date must be in the future");
		}
	}

	isExpired(): boolean {
		return new Date() >= this.props.expiresAt;
	}

	isValid(): boolean {
		return this.props.isActive && !this.isExpired();
	}

	markAsUsed(): void {
		if (!this.isValid()) {
			throw new Error("Cannot use invalid or expired token");
		}

		this.props.lastUsedAt = new Date();
	}

	deactivate(): void {
		this.props.isActive = false;
	}

	refresh(newExpiresAt: Date): void {
		if (!this.isValid()) {
			throw new Error("Cannot refresh invalid token");
		}

		if (newExpiresAt <= new Date()) {
			throw new Error("New expiration date must be in the future");
		}

		this.props.expiresAt = newExpiresAt;
		this.props.lastUsedAt = new Date();
	}

	isSameDevice(deviceInfo: string): boolean {
		return this.props.deviceInfo === deviceInfo;
	}

	getRemainingTime(): number {
		if (this.isExpired()) {
			return 0;
		}
		return this.props.expiresAt.getTime() - new Date().getTime();
	}

	getRemainingMinutes(): number {
		return Math.floor(this.getRemainingTime() / (1000 * 60));
	}

	// Getters
	getId(): string {
		return this.props.id;
	}

	getUserId(): UserId {
		return this.props.userId;
	}

	getToken(): string {
		return this.props.token;
	}

	getExpiresAt(): Date {
		return this.props.expiresAt;
	}

	getDeviceInfo(): string | undefined {
		return this.props.deviceInfo;
	}

	getIpAddress(): string | undefined {
		return this.props.ipAddress;
	}

	getIsActive(): boolean {
		return this.props.isActive;
	}

	getLastUsedAt(): Date | undefined {
		return this.props.lastUsedAt;
	}

	getCreatedAt(): Date {
		return this.props.createdAt;
	}

	equals(other: RefreshToken): boolean {
		if (!(other instanceof RefreshToken)) {
			return false;
		}
		return this.props.id === other.props.id;
	}

	toJSON(): Record<string, any> {
		return {
			id: this.props.id,
			userId: this.props.userId.getValue(),
			token: this.props.token,
			expiresAt: this.props.expiresAt.toISOString(),
			deviceInfo: this.props.deviceInfo,
			ipAddress: this.props.ipAddress,
			isActive: this.props.isActive,
			lastUsedAt: this.props.lastUsedAt?.toISOString(),
			createdAt: this.props.createdAt.toISOString(),
			isExpired: this.isExpired(),
			isValid: this.isValid(),
			remainingMinutes: this.getRemainingMinutes(),
		};
	}
}
