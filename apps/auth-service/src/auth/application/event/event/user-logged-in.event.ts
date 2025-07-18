/**
 * 사용자 로그인 이벤트
 */
export class UserLoggedInEvent {
	readonly eventName = "user.logged.in";
	readonly occurredOn: Date;

	constructor(
		public readonly userId: string,
		public readonly email: string,
		public readonly ipAddress?: string,
		public readonly userAgent?: string,
		public readonly deviceInfo?: string,
	) {
		this.occurredOn = new Date();
	}

	/**
	 * 이벤트를 평면 객체로 변환
	 */
	toPlainObject() {
		return {
			eventName: this.eventName,
			occurredOn: this.occurredOn,
			userId: this.userId,
			email: this.email,
			ipAddress: this.ipAddress,
			userAgent: this.userAgent,
			deviceInfo: this.deviceInfo,
		};
	}
}
