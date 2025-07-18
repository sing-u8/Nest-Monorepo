export enum UserStatus {
	ACTIVE = "active",
	INACTIVE = "inactive",
	SUSPENDED = "suspended",
	PENDING_VERIFICATION = "pending_verification",
}

// biome-ignore lint/complexity/noStaticOnlyClass:only static methods are needed
export class UserStatusUtils {
	static isValidStatus(value: string): value is UserStatus {
		return Object.values(UserStatus).includes(value as UserStatus);
	}

	static isActiveStatus(status: UserStatus): boolean {
		return status === UserStatus.ACTIVE;
	}

	static isInactiveStatus(status: UserStatus): boolean {
		return [
			UserStatus.INACTIVE,
			UserStatus.SUSPENDED,
			UserStatus.PENDING_VERIFICATION,
		].includes(status);
	}
}
