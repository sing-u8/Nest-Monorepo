import { Provider } from '@shared/enum/provider.enum';

/**
 * 사용자 삭제 이벤트
 */
export class UserDeletedEvent {
	readonly eventName = "user.deleted";
	readonly occurredOn: Date;

	constructor(
		public readonly userId: string,
		public readonly email: string,
		public readonly provider: Provider,
		public readonly deletedBy?: string, // 삭제를 수행한 사용자 ID (관리자 또는 본인)
		public readonly reason?: string, // 삭제 사유
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
			deletedBy: this.deletedBy,
			reason: this.reason,
		};
	}
}
