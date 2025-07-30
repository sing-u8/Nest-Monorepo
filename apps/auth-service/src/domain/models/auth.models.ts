import { AuthProvider, ClientInfo } from '@auth/shared/types/auth.types';

// Register User Use Case Models
export interface RegisterUserRequest {
  email: string;
  password: string;
  name: string;
  profilePicture?: string;
}

export interface RegisterUserResponse {
  userId: string;
  email: string;
  name: string;
  profilePicture?: string;
  isActive: boolean;
  createdAt: Date;
}

// Login User Use Case Models
export interface LoginUserRequest {
  email: string;
  password: string;
  clientInfo?: ClientInfo;
}

export interface LoginUserResponse {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  user: {
    id: string;
    email: string;
    name: string;
    profilePicture?: string;
    isActive: boolean;
  };
  expiresAt: Date;
}

// Social Login Use Case Models
export interface SocialLoginRequest {
  provider: AuthProvider;
  authorizationCode?: string; // For Google
  idToken?: string; // For Apple
  userInfo?: any; // Additional user info from client
  clientInfo?: ClientInfo;
}

export interface SocialLoginResponse {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  user: {
    id: string;
    email: string;
    name: string;
    profilePicture?: string;
    provider: AuthProvider;
    isActive: boolean;
  };
  isNewUser: boolean;
  expiresAt: Date;
}

// Refresh Token Use Case Models
export interface RefreshTokenRequest {
  refreshToken: string;
  clientInfo?: ClientInfo;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  expiresAt: Date;
}

// Update Profile Use Case Models
export interface UpdateProfileRequest {
  userId: string;
  name?: string;
  profilePicture?: string;
}

export interface UpdateProfileResponse {
  userId: string;
  email: string;
  name: string;
  profilePicture?: string;
  updatedAt: Date;
}

// Logout Use Case Models
export interface LogoutRequest {
  sessionId: string;
  userId: string;
}

export interface LogoutResponse {
  success: boolean;
  message: string;
}

// Common Error Response
export interface ErrorResponse {
  code: string;
  message: string;
  details?: any;
  timestamp: Date;
}