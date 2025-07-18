import { Injectable } from "@nestjs/common";
import { OnEvent } from "@nestjs/event-emitter";
import { UserLoggedInEvent } from "../event/user-logged-in.event";

/**
 * 사용자 로그인 이벤트 핸들러
 */
@Injectable()
export class UserLoggedInHandler {
	/**
	 * 사용자 로그인 이벤트 처리
	 */
	@OnEvent("user.logged.in")
	async handleUserLoggedIn(event: UserLoggedInEvent): Promise<void> {
		console.log("사용자 로그인 이벤트 처리:", event.toPlainObject());

		try {
			// 1. 로그인 로그 기록
			await this.logUserLogin(event);

			// 2. 보안 검사 (의심스러운 로그인 감지)
			await this.performSecurityChecks(event);

			// 3. 로그인 통계 업데이트
			await this.updateLoginStats(event.userId);

			// 4. 최근 활동 기록 업데이트
			await this.updateUserActivity(event.userId);

			// 5. 푸시 알림 (필요한 경우)
			await this.sendLoginNotification(event);
		} catch (error) {
			console.error("사용자 로그인 이벤트 처리 중 오류:", error);
			// 로그인 이벤트 처리 실패는 사용자 경험에 영향을 주지 않도록
			// 조용히 로깅하고 넘어감
		}
	}

	/**
	 * 로그인 로그 기록
	 */
	private async logUserLogin(event: UserLoggedInEvent): Promise<void> {
		const loginLog = {
			userId: event.userId,
			email: event.email,
			ipAddress: event.ipAddress,
			userAgent: event.userAgent,
			deviceInfo: event.deviceInfo,
			loginTime: event.occurredOn,
		};

		// TODO: 로그인 로그 저장소에 기록 (Phase 4에서 구현)
		console.log("로그인 로그 기록:", loginLog);
	}

	/**
	 * 보안 검사 수행
	 */
	private async performSecurityChecks(event: UserLoggedInEvent): Promise<void> {
		// 1. IP 주소 기반 위치 검사
		const isNewLocation = await this.checkNewLocation(
			event.userId,
			event.ipAddress,
		);

		// 2. 디바이스 검사
		const isNewDevice = await this.checkNewDevice(
			event.userId,
			event.deviceInfo,
		);

		// 3. 비정상적인 로그인 패턴 검사
		const isSuspiciousActivity = await this.checkSuspiciousActivity(
			event.userId,
		);

		// 4. 보안 알림이 필요한 경우
		if (isNewLocation || isNewDevice || isSuspiciousActivity) {
			await this.sendSecurityAlert(event, {
				newLocation: isNewLocation,
				newDevice: isNewDevice,
				suspicious: isSuspiciousActivity,
			});
		}
	}

	/**
	 * 새로운 위치에서의 로그인 검사
	 */
	private async checkNewLocation(
		userId: string,
		ipAddress?: string,
	): Promise<boolean> {
		if (!ipAddress) return false;

		// TODO: IP 위치 정보 서비스 연동 및 이전 로그인 위치와 비교
		console.log(`새로운 위치 검사: userId=${userId}, ip=${ipAddress}`);
		return false; // 임시로 false 반환
	}

	/**
	 * 새로운 디바이스에서의 로그인 검사
	 */
	private async checkNewDevice(
		userId: string,
		deviceInfo?: string,
	): Promise<boolean> {
		if (!deviceInfo) return false;

		// TODO: 디바이스 핑거프린팅 및 이전 디바이스와 비교
		console.log(`새로운 디바이스 검사: userId=${userId}, device=${deviceInfo}`);
		return false; // 임시로 false 반환
	}

	/**
	 * 의심스러운 활동 검사
	 */
	private async checkSuspiciousActivity(userId: string): Promise<boolean> {
		// TODO: 로그인 패턴 분석 (시간대, 빈도 등)
		console.log(`의심스러운 활동 검사: userId=${userId}`);
		return false; // 임시로 false 반환
	}

	/**
	 * 보안 알림 발송
	 */
	private async sendSecurityAlert(
		event: UserLoggedInEvent,
		alerts: {
			newLocation: boolean;
			newDevice: boolean;
			suspicious: boolean;
		},
	): Promise<void> {
		// TODO: 이메일 또는 푸시 알림 발송
		console.log("보안 알림 발송:", {
			userId: event.userId,
			email: event.email,
			alerts,
		});
	}

	/**
	 * 로그인 통계 업데이트
	 */
	private async updateLoginStats(userId: string): Promise<void> {
		// TODO: 로그인 통계 서비스 연동
		console.log(`로그인 통계 업데이트: userId=${userId}`);
	}

	/**
	 * 사용자 활동 기록 업데이트
	 */
	private async updateUserActivity(userId: string): Promise<void> {
		// TODO: 사용자 활동 추적 서비스 연동
		console.log(`사용자 활동 기록 업데이트: userId=${userId}`);
	}

	/**
	 * 로그인 알림 발송
	 */
	private async sendLoginNotification(event: UserLoggedInEvent): Promise<void> {
		// TODO: 푸시 알림 서비스 연동
		console.log(`로그인 알림 발송: userId=${event.userId}`);
	}
}
