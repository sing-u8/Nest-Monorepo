import { TokenType } from '@auth/shared/types/auth.types';

export interface TokenPayload {
  userId: string;
  email: string;
  type: TokenType;
  sessionId?: string;
  [key: string]: any;
}

export interface TokenService {
  generateToken(payload: TokenPayload, expiresIn?: string | number): Promise<string>;
  verifyToken(token: string): Promise<TokenPayload>;
  decodeToken(token: string): TokenPayload | null;
  isTokenExpired(token: string): boolean;
  generateTokenPair(payload: TokenPayload): Promise<{
    accessToken: string;
    refreshToken: string;
  }>;
  revokeToken(token: string): Promise<void>;
  isTokenRevoked(token: string): Promise<boolean>;
}