import { Injectable } from "@nestjs/common";
import { OnEvent } from "@nestjs/event-emitter";
import { Provider } from '@shared/enum/provider.enum';
import { UserDeletedEvent } from "../event/user-deleted.event";

/**
 * 사용자 삭제 이벤트 핸들러
 */
@Injectable()
export class UserDeletedHandler {
	/**
	 * 사용자 삭제 이벤트 처리
	 */
	@OnEvent("user.deleted")
	async handleUserDeleted(event: UserDeletedEvent): Promise<void> {
		console.log("사용자 삭제 이벤트 처리:", event.toPlainObject());

		try {
			// 1. 관련 데이터 정리
			await this.cleanupUserData(event.userId);

			// 2. 외부 서비스 연동 해제
			await this.revokeExternalServices(event);

			// 3. 삭제 로그 기록
			await this.logUserDeletion(event);

			// 4. 관리자 알림
			await this.notifyAdmins(event);

			// 5. 통계 업데이트
			await this.updateDeletionStats(event);

			// 6. 백업 및 아카이브 (필요한 경우)
			await this.archiveUserData(event);
		} catch (error) {
			console.error("사용자 삭제 이벤트 처리 중 오류:", error);
			// 삭제 이벤트 처리 실패 시 복구 불가능하므로
			// 관리자에게 긴급 알림 발송
			await this.sendCriticalAlert(event, error);
		}
	}

	/**
	 * 사용자 관련 데이터 정리
	 */
	private async cleanupUserData(userId: string): Promise<void> {
		try {
			// 1. 세션 및 토큰 무효화
			await this.revokeAllUserTokens(userId);

			// 2. 캐시 데이터 삭제
			await this.clearUserCache(userId);

			// 3. 임시 파일 삭제
			await this.deleteTempFiles(userId);

			// 4. 사용자 설정 삭제
			await this.deleteUserPreferences(userId);

			console.log(`사용자 데이터 정리 완료: userId=${userId}`);
		} catch (error) {
			console.error(`사용자 데이터 정리 실패: userId=${userId}`, error);
			throw error;
		}
	}

	/**
	 * 모든 사용자 토큰 무효화
	 */
	private async revokeAllUserTokens(userId: string): Promise<void> {
		// TODO: 리프레시 토큰 리포지토리를 통해 모든 토큰 삭제
		console.log(`모든 토큰 무효화: userId=${userId}`);
	}

	/**
	 * 사용자 캐시 데이터 삭제
	 */
	private async clearUserCache(userId: string): Promise<void> {
		// TODO: Redis 등 캐시 서비스에서 사용자 관련 데이터 삭제
		console.log(`사용자 캐시 삭제: userId=${userId}`);
	}

	/**
	 * 임시 파일 삭제
	 */
	private async deleteTempFiles(userId: string): Promise<void> {
		// TODO: 파일 저장소에서 사용자 임시 파일 삭제
		console.log(`임시 파일 삭제: userId=${userId}`);
	}

	/**
	 * 사용자 설정 삭제
	 */
	private async deleteUserPreferences(userId: string): Promise<void> {
		// TODO: 사용자 설정 저장소에서 데이터 삭제
		console.log(`사용자 설정 삭제: userId=${userId}`);
	}

	/**
	 * 외부 서비스 연동 해제
	 */
	private async revokeExternalServices(event: UserDeletedEvent): Promise<void> {
		try {
			// 1. 소셜 로그인 연동 해제
			if (event.provider !== Provider.LOCAL) {
				await this.revokeSocialLogin(event.userId, event.provider);
			}

			// 2. 외부 API 액세스 토큰 무효화
			await this.revokeExternalApiTokens(event.userId);

			// 3. 써드파티 서비스 구독 해제
			await this.unsubscribeThirdPartyServices(event.userId);

			console.log(`외부 서비스 연동 해제 완료: userId=${event.userId}`);
		} catch (error) {
			console.error(
				`외부 서비스 연동 해제 실패: userId=${event.userId}`,
				error,
			);
			// 외부 서비스 연동 해제 실패는 치명적이지 않으므로 로깅만 하고 계속 진행
		}
	}

	/**
	 * 소셜 로그인 연동 해제
	 */
	private async revokeSocialLogin(
		userId: string,
		provider: string,
	): Promise<void> {
		// TODO: 구글, 애플 등 소셜 로그인 제공자에게 연동 해제 요청
		console.log(
			`소셜 로그인 연동 해제: userId=${userId}, provider=${provider}`,
		);
	}

	/**
	 * 외부 API 액세스 토큰 무효화
	 */
	private async revokeExternalApiTokens(userId: string): Promise<void> {
		// TODO: 외부 API 토큰 무효화
		console.log(`외부 API 토큰 무효화: userId=${userId}`);
	}

	/**
	 * 써드파티 서비스 구독 해제
	 */
	private async unsubscribeThirdPartyServices(userId: string): Promise<void> {
		// TODO: 이메일 구독, 푸시 알림 등 써드파티 서비스 구독 해제
		console.log(`써드파티 서비스 구독 해제: userId=${userId}`);
	}

	/**
	 * 삭제 로그 기록
	 */
	private async logUserDeletion(event: UserDeletedEvent): Promise<void> {
		const deletionLog = {
			userId: event.userId,
			email: event.email,
			provider: event.provider,
			deletedBy: event.deletedBy,
			reason: event.reason,
			deletedAt: event.occurredOn,
		};

		// TODO: 삭제 로그 저장소에 기록 (감사 로그)
		console.log("사용자 삭제 로그 기록:", deletionLog);
	}

	/**
	 * 관리자 알림
	 */
	private async notifyAdmins(event: UserDeletedEvent): Promise<void> {
		const notification = {
			type: "USER_DELETED",
			userId: event.userId,
			email: event.email,
			provider: event.provider,
			deletedBy: event.deletedBy,
			reason: event.reason,
			timestamp: event.occurredOn,
		};

		// TODO: 관리자 알림 서비스 (슬랙, 이메일 등)
		console.log("관리자 알림 발송:", notification);
	}

	/**
	 * 삭제 통계 업데이트
	 */
	private async updateDeletionStats(event: UserDeletedEvent): Promise<void> {
		// TODO: 사용자 삭제 통계 업데이트
		console.log(
			`삭제 통계 업데이트: provider=${event.provider}, reason=${event.reason}`,
		);
	}

	/**
	 * 사용자 데이터 아카이브
	 */
	private async archiveUserData(event: UserDeletedEvent): Promise<void> {
		// 법적 요구사항이나 비즈니스 요구사항에 따라
		// 사용자 데이터를 완전히 삭제하지 않고 아카이브할 수 있음

		const archiveData = {
			userId: event.userId,
			email: event.email,
			provider: event.provider,
			deletedAt: event.occurredOn,
			deletedBy: event.deletedBy,
			reason: event.reason,
		};

		// TODO: 아카이브 저장소에 기록 (별도의 안전한 저장소)
		console.log("사용자 데이터 아카이브:", archiveData);
	}

	/**
	 * 긴급 알림 발송
	 */
	private async sendCriticalAlert(
		event: UserDeletedEvent,
		error: Error,
	): Promise<void> {
		const alert = {
			level: "CRITICAL",
			message: "사용자 삭제 이벤트 처리 중 오류 발생",
			userId: event.userId,
			email: event.email,
			error: error.message,
			timestamp: new Date(),
		};

		// TODO: 긴급 알림 시스템 (PagerDuty, 온콜 알림 등)
		console.error("긴급 알림:", alert);
	}
}
