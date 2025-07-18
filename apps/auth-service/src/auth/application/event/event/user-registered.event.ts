import { Provider } from '@shared/enum/provider.enum';

/**
 * 사용자 등록 이벤트
 */
export class UserRegisteredEvent {
	readonly eventName = "user.registered";
	readonly occurredOn: Date;

	constructor(
		public readonly userId: string,
		public readonly email: string,
		public readonly provider: Provider,
		public readonly isEmailVerified: boolean = false,
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
			provider: this.provider,
			isEmailVerified: this.isEmailVerified,
		};
	}
}
