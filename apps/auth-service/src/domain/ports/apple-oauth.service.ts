export interface AppleUserInfo {
  id: string;
  email: string;
  name?: string;
  emailVerified: boolean;
  isPrivateEmail?: boolean;
}

export interface AppleIdTokenPayload {
  sub: string;
  email: string;
  email_verified: string | boolean;
  is_private_email?: string | boolean;
  aud: string;
  iss: string;
  iat: number;
  exp: number;
}

export interface AppleOAuthService {
  verifyIdToken(idToken: string): Promise<AppleIdTokenPayload>;
  extractUserInfo(idToken: string, userInfo?: any): Promise<AppleUserInfo>;
  validateNonce(idToken: string, expectedNonce: string): Promise<boolean>;
  revokeToken(token: string): Promise<void>;
}