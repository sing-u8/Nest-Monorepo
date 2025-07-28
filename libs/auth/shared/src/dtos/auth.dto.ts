import { AuthProvider, ClientInfo } from '../types/auth.types';

/**
 * User Registration Request DTO
 */
export interface RegisterUserRequest {
  email: string;
  password: string;
  name: string;
  profilePicture?: string;
}

/**
 * User Registration Response DTO
 */
export interface RegisterUserResponse {
  user: {
    id: string;
    email: string;
    name: string;
    profilePicture?: string;
    provider: AuthProvider;
    createdAt: Date;
  };
  tokens: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  };
}

/**
 * User Login Request DTO
 */
export interface LoginUserRequest {
  email: string;
  password: string;
  clientInfo?: ClientInfo;
  rememberMe?: boolean;
}

/**
 * User Login Response DTO
 */
export interface LoginUserResponse {
  user: {
    id: string;
    email: string;
    name: string;
    profilePicture?: string;
    provider: AuthProvider;
    lastLoginAt: Date;
  };
  tokens: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  };
  session: {
    id: string;
    expiresAt: Date;
  };
}

/**
 * Social Login Request DTO
 */
export interface SocialLoginRequest {
  provider: AuthProvider.GOOGLE | AuthProvider.APPLE;
  code?: string;
  idToken?: string;
  accessToken?: string;
  clientInfo?: ClientInfo;
  userInfo?: {
    name?: {
      firstName?: string;
      lastName?: string;
    };
  };
}

/**
 * Social Login Response DTO
 */
export interface SocialLoginResponse {
  user: {
    id: string;
    email: string;
    name: string;
    profilePicture?: string;
    provider: AuthProvider;
    isNewUser: boolean;
  };
  tokens: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  };
  session: {
    id: string;
    expiresAt: Date;
  };
}

/**
 * Token Refresh Request DTO
 */
export interface RefreshTokenRequest {
  refreshToken: string;
  clientInfo?: ClientInfo;
}

/**
 * Token Refresh Response DTO
 */
export interface RefreshTokenResponse {
  tokens: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  };
}

/**
 * Logout Request DTO
 */
export interface LogoutRequest {
  refreshToken?: string;
  sessionToken?: string;
  logoutAllDevices?: boolean;
}

/**
 * Logout Response DTO
 */
export interface LogoutResponse {
  success: boolean;
  message: string;
}

/**
 * Validate Token Request DTO
 */
export interface ValidateTokenRequest {
  token: string;
  tokenType: 'access' | 'refresh';
}

/**
 * Validate Token Response DTO
 */
export interface ValidateTokenResponse {
  isValid: boolean;
  user?: {
    id: string;
    email: string;
    name: string;
  };
  expiresAt?: Date;
  error?: string;
}