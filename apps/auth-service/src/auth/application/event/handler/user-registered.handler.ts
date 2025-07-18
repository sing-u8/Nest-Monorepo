import { Injectable } from "@nestjs/common";
import { OnEvent } from "@nestjs/event-emitter";
import { UserRegisteredEvent } from "../event/user-registered.event";

/**
 * 사용자 등록 이벤트 핸들러
 */
@Injectable()
export class UserRegisteredHandler {
	/**
	 * 사용자 등록 이벤트 처리
	 */
	@OnEvent("user.registered")
	async handleUserRegistered(event: UserRegisteredEvent): Promise<void> {
		console.log("사용자 등록 이벤트 처리:", event.toPlainObject());

		try {
			// 1. 이메일 인증이 필요한 경우 인증 이메일 발송
			if (!event.isEmailVerified) {
				await this.sendEmailVerification(event.userId, event.email);
			}

			// 2. 환영 이메일 발송
			await this.sendWelcomeEmail(event.userId, event.email);

			// 3. 사용자 등록 통계 업데이트
			await this.updateUserRegistrationStats(event.provider);

			// 4. 기타 후속 처리 (예: 슬랙 알림, 분석 데이터 수집 등)
			await this.notifyAdmins(event);
		} catch (error) {
			console.error("사용자 등록 이벤트 처리 중 오류:", error);
			// 이벤트 처리 실패 시 재시도 로직이나 오류 로깅
			// 실제 구현에서는 retry queue나 dead letter queue 사용
		}
	}

	/**
	 * 이메일 인증 메일 발송
	 */
	private async sendEmailVerification(
		userId: string,
		email: string,
	): Promise<void> {
		// TODO: 이메일 서비스 연동 (Phase 4에서 구현)
		console.log(`이메일 인증 메일 발송: ${email} (userId: ${userId})`);
	}

	/**
	 * 환영 이메일 발송
	 */
	private async sendWelcomeEmail(userId: string, email: string): Promise<void> {
		// TODO: 이메일 서비스 연동 (Phase 4에서 구현)
		console.log(`환영 이메일 발송: ${email} (userId: ${userId})`);
	}

	/**
	 * 사용자 등록 통계 업데이트
	 */
	private async updateUserRegistrationStats(provider: string): Promise<void> {
		// TODO: 통계 서비스 연동
		console.log(`사용자 등록 통계 업데이트: provider=${provider}`);
	}

	/**
	 * 관리자에게 알림
	 */
	private async notifyAdmins(event: UserRegisteredEvent): Promise<void> {
		// TODO: 알림 서비스 연동 (슬랙, 디스코드 등)
		console.log("관리자 알림:", event.toPlainObject());
	}
}
