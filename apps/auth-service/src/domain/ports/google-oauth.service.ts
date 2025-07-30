export interface GoogleUserInfo {
  id: string;
  email: string;
  name: string;
  picture?: string;
  emailVerified: boolean;
}

export interface GoogleOAuthService {
  exchangeCodeForTokens(code: string): Promise<{
    accessToken: string;
    refreshToken?: string;
    idToken: string;
  }>;
  getUserInfo(accessToken: string): Promise<GoogleUserInfo>;
  verifyIdToken(idToken: string): Promise<GoogleUserInfo>;
  revokeToken(token: string): Promise<void>;
  refreshAccessToken(refreshToken: string): Promise<{
    accessToken: string;
    refreshToken?: string;
  }>;
}