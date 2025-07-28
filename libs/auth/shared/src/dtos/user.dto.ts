import { AuthProvider, UserStatus } from '../types';

/**
 * Update Profile Request DTO
 */
export interface UpdateProfileRequest {
  name?: string;
  profilePicture?: string;
}

/**
 * Update Profile Response DTO
 */
export interface UpdateProfileResponse {
  user: {
    id: string;
    email: string;
    name: string;
    profilePicture?: string;
    updatedAt: Date;
  };
}

/**
 * Change Password Request DTO
 */
export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

/**
 * Change Password Response DTO
 */
export interface ChangePasswordResponse {
  success: boolean;
  message: string;
}

/**
 * Get User Profile Request DTO
 */
export interface GetUserProfileRequest {
  userId: string;
}

/**
 * Get User Profile Response DTO
 */
export interface GetUserProfileResponse {
  user: {
    id: string;
    email: string;
    name: string;
    profilePicture?: string;
    provider: AuthProvider;
    status: UserStatus;
    createdAt: Date;
    updatedAt: Date;
    lastLoginAt?: Date;
  };
}

/**
 * Deactivate Account Request DTO
 */
export interface DeactivateAccountRequest {
  password?: string; // Required for local accounts
  reason?: string;
}

/**
 * Deactivate Account Response DTO
 */
export interface DeactivateAccountResponse {
  success: boolean;
  message: string;
  deactivatedAt: Date;
}

/**
 * Upload Profile Picture Request DTO
 */
export interface UploadProfilePictureRequest {
  file: {
    buffer: Buffer;
    mimetype: string;
    originalname: string;
    size: number;
  };
}

/**
 * Upload Profile Picture Response DTO
 */
export interface UploadProfilePictureResponse {
  profilePicture: string;
  uploadedAt: Date;
}

/**
 * User Session Info DTO
 */
export interface UserSessionInfo {
  id: string;
  deviceId?: string;
  platform?: string;
  ipAddress?: string;
  userAgent?: string;
  isCurrentSession: boolean;
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  status: 'active' | 'inactive' | 'expired' | 'idle';
}

/**
 * Get User Sessions Request DTO
 */
export interface GetUserSessionsRequest {
  userId: string;
  includeExpired?: boolean;
}

/**
 * Get User Sessions Response DTO
 */
export interface GetUserSessionsResponse {
  sessions: UserSessionInfo[];
  totalCount: number;
  activeCount: number;
}

/**
 * Terminate Session Request DTO
 */
export interface TerminateSessionRequest {
  sessionId?: string;
  terminateAll?: boolean;
}

/**
 * Terminate Session Response DTO
 */
export interface TerminateSessionResponse {
  success: boolean;
  message: string;
  terminatedCount: number;
}