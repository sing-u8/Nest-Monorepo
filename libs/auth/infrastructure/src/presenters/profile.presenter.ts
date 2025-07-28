import { Injectable } from '@nestjs/common';
import { ProfilePresenter as ProfilePresenterPort } from '@auth/domain';
import {
  GetProfileResponse,
  UpdateProfileResponse,
  UploadProfilePictureResponse,
  ErrorResponse,
  UserProfileWithSessions,
  UpdateProfileResult,
  UploadProfilePictureResult,
} from '@auth/shared';

/**
 * Profile Presenter Implementation
 * 
 * Implements the ProfilePresenter port interface to format profile
 * responses consistently across the application. This presenter follows
 * the Clean Architecture pattern by implementing the port defined in
 * the domain layer.
 * 
 * All responses follow a consistent format:
 * - success: boolean
 * - message: string
 * - data?: any (for successful operations)
 * - error?: string (for failed operations)
 * - details?: any (for additional error information)
 */
@Injectable()
export class ProfilePresenter implements ProfilePresenterPort {

  // Success Response Presenters

  presentGetProfileSuccess(response: UserProfileWithSessions): GetProfileResponse {
    return {
      success: true,
      message: 'Profile retrieved successfully',
      data: {
        user: {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
          profilePicture: response.user.profilePicture,
          bio: response.user.bio,
          location: response.user.location,
          website: response.user.website,
          provider: response.user.provider,
          emailVerified: response.user.emailVerified,
          status: response.user.status,
          createdAt: response.user.createdAt,
          updatedAt: response.user.updatedAt,
          lastLoginAt: response.user.lastLoginAt,
        },
        sessions: response.sessions.map(session => ({
          id: session.id,
          deviceInfo: session.deviceInfo,
          ipAddress: session.ipAddress,
          lastActivity: session.lastActivity,
          createdAt: session.createdAt,
          isCurrentSession: session.isCurrentSession,
        })),
        accountSummary: {
          totalSessions: response.accountSummary.totalSessions,
          activeSessions: response.accountSummary.activeSessions,
          lastPasswordChange: response.accountSummary.lastPasswordChange,
          accountAge: response.accountSummary.accountAge,
        },
      },
    };
  }

  presentUpdateProfileSuccess(response: UpdateProfileResult): UpdateProfileResponse {
    return {
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
          profilePicture: response.user.profilePicture,
          bio: response.user.bio,
          location: response.user.location,
          website: response.user.website,
          updatedAt: response.user.updatedAt,
        },
        changes: response.changes.map(change => ({
          field: change.field,
          oldValue: change.oldValue,
          newValue: change.newValue,
        })),
      },
    };
  }

  presentUploadProfilePictureSuccess(response: UploadProfilePictureResult): UploadProfilePictureResponse {
    return {
      success: true,
      message: 'Profile picture uploaded successfully',
      data: {
        user: {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
          profilePicture: response.user.profilePicture,
          updatedAt: response.user.updatedAt,
        },
        upload: {
          originalName: response.upload.originalName,
          fileName: response.upload.fileName,
          size: response.upload.size,
          mimeType: response.upload.mimeType,
          url: response.upload.url,
        },
      },
    };
  }

  presentDeleteProfilePictureSuccess(response: any): UpdateProfileResponse {
    return {
      success: true,
      message: 'Profile picture deleted successfully',
      data: {
        user: {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
          profilePicture: response.user.profilePicture, // Should be null
          updatedAt: response.user.updatedAt,
        },
        changes: [{
          field: 'profilePicture',
          oldValue: 'previous_profile_picture_url',
          newValue: null,
        }],
      },
    };
  }

  // Legacy interface methods (for compatibility with existing presenter port)

  presentUserProfile(response: any): void {
    // This method is for the old interface - we now return values directly
    throw new Error('Use presentGetProfileSuccess instead');
  }

  presentProfileUpdateSuccess(response: any): void {
    // This method is for the old interface - we now return values directly
    throw new Error('Use presentUpdateProfileSuccess instead');
  }

  presentProfilePictureUploadSuccess(response: any): void {
    // This method is for the old interface - we now return values directly
    throw new Error('Use presentUploadProfilePictureSuccess instead');
  }

  // Error Response Presenters

  presentUserNotFound(userId?: string): ErrorResponse {
    return {
      success: false,
      error: 'USER_NOT_FOUND',
      message: 'User profile not found',
      details: {
        userId,
        suggestion: 'Please check the user ID and try again',
      },
    };
  }

  presentValidationError(error: string): ErrorResponse {
    return {
      success: false,
      error: 'VALIDATION_ERROR',
      message: 'Invalid profile data',
      details: {
        error,
        suggestion: 'Please check your input and try again',
      },
    };
  }

  presentUnauthorized(): ErrorResponse {
    return {
      success: false,
      error: 'UNAUTHORIZED',
      message: 'Invalid or expired authentication token',
      details: {
        suggestion: 'Please log in again to continue',
      },
    };
  }

  presentInternalError(): ErrorResponse {
    return {
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred',
      details: {
        suggestion: 'Please try again later',
      },
    };
  }

  presentProfileUpdateValidationError(errors: Record<string, string[]>): ErrorResponse {
    const formattedErrors = Object.entries(errors).map(([field, messages]) => ({
      field,
      messages,
    }));

    return {
      success: false,
      error: 'VALIDATION_ERROR',
      message: 'Profile update validation failed',
      details: {
        errors: formattedErrors,
        totalErrors: formattedErrors.length,
        suggestion: 'Please correct the validation errors and try again',
      },
    };
  }

  presentPasswordChangeSuccess(response: any): any {
    return {
      success: true,
      message: 'Password changed successfully',
      data: {
        user: {
          id: response.user.id,
          email: response.user.email,
          passwordChangedAt: response.passwordChangedAt,
        },
        tokensRevoked: response.tokensRevoked || 0,
        sessionsTerminated: response.sessionsTerminated || 0,
      },
    };
  }

  presentPasswordChangeFailure(error: string): ErrorResponse {
    return {
      success: false,
      error: 'PASSWORD_CHANGE_ERROR',
      message: 'Failed to change password',
      details: {
        error,
        suggestion: 'Please check your current password and try again',
      },
    };
  }

  presentInvalidCurrentPassword(): ErrorResponse {
    return {
      success: false,
      error: 'INVALID_CURRENT_PASSWORD',
      message: 'Current password is incorrect',
      details: {
        suggestion: 'Please enter your correct current password',
      },
    };
  }

  presentAccountDeactivationSuccess(response: any): any {
    return {
      success: true,
      message: 'Account deactivated successfully',
      data: {
        user: {
          id: response.user.id,
          email: response.user.email,
          status: response.user.status,
          deactivatedAt: response.deactivatedAt,
        },
        tokensRevoked: response.tokensRevoked || 0,
        sessionsTerminated: response.sessionsTerminated || 0,
      },
    };
  }

  presentAccountDeactivationFailure(error: string): ErrorResponse {
    return {
      success: false,
      error: 'ACCOUNT_DEACTIVATION_ERROR',
      message: 'Failed to deactivate account',
      details: {
        error,
        suggestion: 'Please try again or contact support',
      },
    };
  }

  presentProfilePictureUploadFailure(error: string): ErrorResponse {
    return {
      success: false,
      error: 'PROFILE_PICTURE_UPLOAD_ERROR',
      message: 'Failed to upload profile picture',
      details: {
        error,
        suggestion: 'Please check the file format and size, then try again',
      },
    };
  }

  presentInvalidFileFormat(allowedFormats: string[]): ErrorResponse {
    return {
      success: false,
      error: 'INVALID_FILE_FORMAT',
      message: 'Invalid file format for profile picture',
      details: {
        allowedFormats,
        suggestion: `Please use one of the following formats: ${allowedFormats.join(', ')}`,
      },
    };
  }

  presentFileSizeExceeded(maxSize: number): ErrorResponse {
    const maxSizeMB = Math.round(maxSize / (1024 * 1024));
    
    return {
      success: false,
      error: 'FILE_SIZE_EXCEEDED',
      message: 'Profile picture file size is too large',
      details: {
        maxSize,
        maxSizeFormatted: `${maxSizeMB}MB`,
        suggestion: `Please choose a file smaller than ${maxSizeMB}MB`,
      },
    };
  }

  presentUserSessions(response: any): any {
    return {
      success: true,
      message: 'User sessions retrieved successfully',
      data: {
        sessions: response.sessions.map((session: any) => ({
          id: session.id,
          deviceInfo: session.deviceInfo,
          ipAddress: session.ipAddress,
          lastActivity: session.lastActivity,
          createdAt: session.createdAt,
          isCurrentSession: session.isCurrentSession,
          status: session.status,
        })),
        totalSessions: response.totalSessions,
        activeSessions: response.activeSessions,
      },
    };
  }

  presentSessionTerminationSuccess(response: any): any {
    return {
      success: true,
      message: response.allSessions 
        ? 'All sessions terminated successfully'
        : 'Session terminated successfully',
      data: {
        sessionsTerminated: response.sessionsTerminated || 1,
        tokensRevoked: response.tokensRevoked || 0,
        allSessions: response.allSessions || false,
      },
    };
  }

  presentSessionTerminationFailure(error: string): ErrorResponse {
    return {
      success: false,
      error: 'SESSION_TERMINATION_ERROR',
      message: 'Failed to terminate session',
      details: {
        error,
        suggestion: 'Please try again or contact support',
      },
    };
  }

  presentSessionNotFound(sessionId: string): ErrorResponse {
    return {
      success: false,
      error: 'SESSION_NOT_FOUND',
      message: 'Session not found',
      details: {
        sessionId,
        suggestion: 'Please check the session ID and try again',
      },
    };
  }

  presentUnauthorizedAccess(): ErrorResponse {
    return {
      success: false,
      error: 'UNAUTHORIZED_ACCESS',
      message: 'You are not authorized to access this resource',
      details: {
        suggestion: 'Please log in with appropriate permissions',
      },
    };
  }

  presentForbiddenAction(action: string): ErrorResponse {
    return {
      success: false,
      error: 'FORBIDDEN_ACTION',
      message: `You are not allowed to perform this action: ${action}`,
      details: {
        action,
        suggestion: 'Please contact support if you believe this is an error',
      },
    };
  }

  presentProfileError(error: string, code?: string): ErrorResponse {
    return {
      success: false,
      error: code || 'PROFILE_ERROR',
      message: 'Profile operation failed',
      details: {
        error,
        suggestion: 'Please try again or contact support',
      },
    };
  }

  presentServerError(error: string): ErrorResponse {
    return {
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected error occurred',
      details: {
        suggestion: 'Please try again later. If the problem persists, contact support.',
      },
    };
  }
}