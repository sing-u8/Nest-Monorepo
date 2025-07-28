import {
  GetUserProfileResponse,
  UpdateProfileResponse,
  ChangePasswordResponse,
  DeactivateAccountResponse,
  UploadProfilePictureResponse,
  GetUserSessionsResponse,
  TerminateSessionResponse,
} from '@auth/shared';

/**
 * Profile Presenter Port Interface
 * 
 * This interface defines how user profile operations results should be presented.
 * Infrastructure layer must implement this interface for different output formats.
 */
export interface ProfilePresenter {
  /**
   * Present user profile information
   * @param response - User profile data
   */
  presentUserProfile(response: GetUserProfileResponse): void;

  /**
   * Present user not found error
   * @param userId - User ID that was not found
   */
  presentUserNotFound(userId: string): void;

  /**
   * Present successful profile update
   * @param response - Updated profile data
   */
  presentProfileUpdateSuccess(response: UpdateProfileResponse): void;

  /**
   * Present profile update validation errors
   * @param errors - Validation errors
   */
  presentProfileUpdateValidationError(errors: Record<string, string[]>): void;

  /**
   * Present successful password change
   * @param response - Password change response
   */
  presentPasswordChangeSuccess(response: ChangePasswordResponse): void;

  /**
   * Present password change failure
   * @param error - Error message
   */
  presentPasswordChangeFailure(error: string): void;

  /**
   * Present current password validation error
   */
  presentInvalidCurrentPassword(): void;

  /**
   * Present successful account deactivation
   * @param response - Deactivation response
   */
  presentAccountDeactivationSuccess(response: DeactivateAccountResponse): void;

  /**
   * Present account deactivation failure
   * @param error - Error message
   */
  presentAccountDeactivationFailure(error: string): void;

  /**
   * Present successful profile picture upload
   * @param response - Upload response
   */
  presentProfilePictureUploadSuccess(response: UploadProfilePictureResponse): void;

  /**
   * Present profile picture upload failure
   * @param error - Error message
   */
  presentProfilePictureUploadFailure(error: string): void;

  /**
   * Present invalid file format error
   * @param allowedFormats - List of allowed formats
   */
  presentInvalidFileFormat(allowedFormats: string[]): void;

  /**
   * Present file size exceeded error
   * @param maxSize - Maximum allowed size in bytes
   */
  presentFileSizeExceeded(maxSize: number): void;

  /**
   * Present user sessions information
   * @param response - Sessions data
   */  
  presentUserSessions(response: GetUserSessionsResponse): void;

  /**
   * Present successful session termination
   * @param response - Termination response
   */
  presentSessionTerminationSuccess(response: TerminateSessionResponse): void;

  /**
   * Present session termination failure
   * @param error - Error message
   */
  presentSessionTerminationFailure(error: string): void;

  /**
   * Present session not found error
   * @param sessionId - Session ID that was not found
   */
  presentSessionNotFound(sessionId: string): void;

  /**
   * Present unauthorized access error
   */
  presentUnauthorizedAccess(): void;

  /**
   * Present forbidden action error
   * @param action - Action that was forbidden
   */
  presentForbiddenAction(action: string): void;

  /**
   * Present general profile error
   * @param error - Error message
   * @param code - Error code
   */
  presentProfileError(error: string, code?: string): void;

  /**
   * Present server error
   * @param error - Error message
   */
  presentServerError(error: string): void;
}