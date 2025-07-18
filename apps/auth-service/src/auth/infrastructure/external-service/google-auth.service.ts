import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";

export interface GoogleUserInfo {
	id: string;
	email: string;
	name: string;
	picture?: string;
	verified_email: boolean;
}

@Injectable()
export class GoogleAuthService {
	private readonly logger = new Logger(GoogleAuthService.name);

	constructor(private readonly configService: ConfigService) {}

	generateAuthUrl(): string {
		// Google OAuth URL 생성 로직
		return "https://accounts.google.com/oauth/authorize";
	}

	async getUserInfo(accessToken: string): Promise<GoogleUserInfo> {
		// 사용자 정보 조회 로직
		return {
			id: "mock_id",
			email: "test@example.com",
			name: "Test User",
			verified_email: true,
		};
	}
}
