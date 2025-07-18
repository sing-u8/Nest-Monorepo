import { registerAs } from "@nestjs/config";

export interface SocialAuthConfig {
	google: {
		clientId: string;
		clientSecret: string;
		callbackUrl: string;
	};
	apple: {
		clientId: string;
		teamId: string;
		keyId: string;
		privateKey: string;
		callbackUrl: string;
	};
}

export default registerAs(
	"socialAuth",
	(): SocialAuthConfig => ({
		google: {
			clientId: process.env.GOOGLE_CLIENT_ID || "",
			clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
			callbackUrl:
				process.env.GOOGLE_CALLBACK_URL ||
				"http://localhost:3000/api/auth/google/callback",
		},
		apple: {
			clientId: process.env.APPLE_CLIENT_ID || "",
			teamId: process.env.APPLE_TEAM_ID || "",
			keyId: process.env.APPLE_KEY_ID || "",
			privateKey: process.env.APPLE_PRIVATE_KEY || "",
			callbackUrl:
				process.env.APPLE_CALLBACK_URL ||
				"http://localhost:3000/api/auth/apple/callback",
		},
	}),
);
