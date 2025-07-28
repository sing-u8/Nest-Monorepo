import { Test, TestingModule } from '@nestjs/testing';
import { ProfilePresenter } from './profile.presenter';
import {
  GetProfileResponse,
  UpdateProfileResponse,
  UploadProfilePictureResponse,
  ErrorResponse,
  UserProfileWithSessions,
  UpdateProfileResult,
  UploadProfilePictureResult,
} from '@auth/shared';

describe('ProfilePresenter', () => {
  let presenter: ProfilePresenter;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ProfilePresenter],
    }).compile();

    presenter = module.get<ProfilePresenter>(ProfilePresenter);
  });

  describe('Success Response Presenters', () => {
    describe('presentGetProfileSuccess', () => {
      it('should present get profile success response', () => {
        const mockResponse: UserProfileWithSessions = {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
            profilePicture: 'https://example.com/avatar.jpg',
            bio: 'Software developer',
            location: 'San Francisco, CA',
            website: 'https://johndoe.dev',
            provider: 'local',
            emailVerified: true,
            status: 'active',
            createdAt: new Date('2024-01-01'),
            updatedAt: new Date('2024-01-02'),
            lastLoginAt: new Date('2024-01-02'),
          },
          sessions: [
            {
              id: 'session-123',
              deviceInfo: 'Chrome on Windows',
              ipAddress: '192.168.1.1',
              lastActivity: new Date('2024-01-02'),
              createdAt: new Date('2024-01-01'),
              isCurrentSession: true,
            },
          ],
          accountSummary: {
            totalSessions: 3,
            activeSessions: 2,
            lastPasswordChange: new Date('2024-01-01'),
            accountAge: '30 days',
          },
        };

        const result = presenter.presentGetProfileSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'Profile retrieved successfully',
          data: {
            user: {
              id: 'user-123',
              email: 'user@example.com',
              name: 'John Doe',
              profilePicture: 'https://example.com/avatar.jpg',
              bio: 'Software developer',
              location: 'San Francisco, CA',
              website: 'https://johndoe.dev',
              provider: 'local',
              emailVerified: true,
              status: 'active',
              createdAt: new Date('2024-01-01'),
              updatedAt: new Date('2024-01-02'),
              lastLoginAt: new Date('2024-01-02'),
            },
            sessions: [
              {
                id: 'session-123',
                deviceInfo: 'Chrome on Windows',
                ipAddress: '192.168.1.1',
                lastActivity: new Date('2024-01-02'),
                createdAt: new Date('2024-01-01'),
                isCurrentSession: true,
              },
            ],
            accountSummary: {
              totalSessions: 3,
              activeSessions: 2,
              lastPasswordChange: new Date('2024-01-01'),
              accountAge: '30 days',
            },
          },
        });
      });
    });

    describe('presentUpdateProfileSuccess', () => {
      it('should present update profile success response', () => {
        const mockResponse: UpdateProfileResult = {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Smith',
            profilePicture: 'https://example.com/avatar.jpg',
            bio: 'Senior Software Developer',
            location: 'New York, NY',
            website: 'https://johnsmith.dev',
            updatedAt: new Date('2024-01-02'),
          },
          changes: [
            {
              field: 'name',
              oldValue: 'John Doe',
              newValue: 'John Smith',
            },
            {
              field: 'bio',
              oldValue: 'Software developer',
              newValue: 'Senior Software Developer',
            },
            {
              field: 'location',
              oldValue: 'San Francisco, CA',
              newValue: 'New York, NY',
            },
          ],
        };

        const result = presenter.presentUpdateProfileSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'Profile updated successfully',
          data: {
            user: {
              id: 'user-123',
              email: 'user@example.com',
              name: 'John Smith',
              profilePicture: 'https://example.com/avatar.jpg',
              bio: 'Senior Software Developer',
              location: 'New York, NY',
              website: 'https://johnsmith.dev',
              updatedAt: new Date('2024-01-02'),
            },
            changes: [
              {
                field: 'name',
                oldValue: 'John Doe',
                newValue: 'John Smith',
              },
              {
                field: 'bio',
                oldValue: 'Software developer',
                newValue: 'Senior Software Developer',
              },
              {
                field: 'location',
                oldValue: 'San Francisco, CA',
                newValue: 'New York, NY',
              },
            ],
          },
        });
      });
    });

    describe('presentUploadProfilePictureSuccess', () => {
      it('should present upload profile picture success response', () => {
        const mockResponse: UploadProfilePictureResult = {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
            profilePicture: 'https://storage.example.com/profiles/user-123.jpg',
            updatedAt: new Date('2024-01-02'),
          },
          upload: {
            originalName: 'profile.jpg',
            fileName: 'user-123-1640995200000.jpg',
            size: 245760,
            mimeType: 'image/jpeg',
            url: 'https://storage.example.com/profiles/user-123.jpg',
          },
        };

        const result = presenter.presentUploadProfilePictureSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'Profile picture uploaded successfully',
          data: {
            user: {
              id: 'user-123',
              email: 'user@example.com',
              name: 'John Doe',
              profilePicture: 'https://storage.example.com/profiles/user-123.jpg',
              updatedAt: new Date('2024-01-02'),
            },
            upload: {
              originalName: 'profile.jpg',
              fileName: 'user-123-1640995200000.jpg',
              size: 245760,
              mimeType: 'image/jpeg',
              url: 'https://storage.example.com/profiles/user-123.jpg',
            },
          },
        });
      });
    });

    describe('presentDeleteProfilePictureSuccess', () => {
      it('should present delete profile picture success response', () => {
        const mockResponse = {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
            profilePicture: null,
            updatedAt: new Date('2024-01-02'),
          },
        };

        const result = presenter.presentDeleteProfilePictureSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'Profile picture deleted successfully',
          data: {
            user: {
              id: 'user-123',
              email: 'user@example.com',
              name: 'John Doe',
              profilePicture: null,
              updatedAt: new Date('2024-01-02'),
            },
            changes: [{
              field: 'profilePicture',
              oldValue: 'previous_profile_picture_url',
              newValue: null,
            }],
          },
        });
      });
    });

    describe('presentPasswordChangeSuccess', () => {
      it('should present password change success response', () => {
        const mockResponse = {
          user: {
            id: 'user-123',
            email: 'user@example.com',
          },
          passwordChangedAt: new Date('2024-01-02'),
          tokensRevoked: 3,
          sessionsTerminated: 2,
        };

        const result = presenter.presentPasswordChangeSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'Password changed successfully',
          data: {
            user: {
              id: 'user-123',
              email: 'user@example.com',
              passwordChangedAt: new Date('2024-01-02'),
            },
            tokensRevoked: 3,
            sessionsTerminated: 2,
          },
        });
      });

      it('should use default values if not provided', () => {
        const mockResponse = {
          user: { id: 'user-123', email: 'user@example.com' },
          passwordChangedAt: new Date(),
        };

        const result = presenter.presentPasswordChangeSuccess(mockResponse);

        expect(result.data.tokensRevoked).toBe(0);
        expect(result.data.sessionsTerminated).toBe(0);
      });
    });

    describe('presentUserSessions', () => {
      it('should present user sessions response', () => {
        const mockResponse = {
          sessions: [
            {
              id: 'session-123',
              deviceInfo: 'Chrome on Windows',
              ipAddress: '192.168.1.1',
              lastActivity: new Date('2024-01-02'),
              createdAt: new Date('2024-01-01'),
              isCurrentSession: true,
              status: 'active',
            },
            {
              id: 'session-456',
              deviceInfo: 'Safari on iPhone',
              ipAddress: '192.168.1.2',
              lastActivity: new Date('2024-01-01'),
              createdAt: new Date('2024-01-01'),
              isCurrentSession: false,
              status: 'active',
            },
          ],
          totalSessions: 5,
          activeSessions: 2,
        };

        const result = presenter.presentUserSessions(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'User sessions retrieved successfully',
          data: {
            sessions: [
              {
                id: 'session-123',
                deviceInfo: 'Chrome on Windows',
                ipAddress: '192.168.1.1',
                lastActivity: new Date('2024-01-02'),
                createdAt: new Date('2024-01-01'),
                isCurrentSession: true,
                status: 'active',
              },
              {
                id: 'session-456',
                deviceInfo: 'Safari on iPhone',
                ipAddress: '192.168.1.2',
                lastActivity: new Date('2024-01-01'),
                createdAt: new Date('2024-01-01'),
                isCurrentSession: false,
                status: 'active',
              },
            ],
            totalSessions: 5,
            activeSessions: 2,
          },
        });
      });
    });

    describe('presentSessionTerminationSuccess', () => {
      it('should present single session termination success', () => {
        const mockResponse = {
          sessionsTerminated: 1,
          tokensRevoked: 2,
          allSessions: false,
        };

        const result = presenter.presentSessionTerminationSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'Session terminated successfully',
          data: {
            sessionsTerminated: 1,
            tokensRevoked: 2,
            allSessions: false,
          },
        });
      });

      it('should present all sessions termination success', () => {
        const mockResponse = {
          sessionsTerminated: 3,
          tokensRevoked: 5,
          allSessions: true,
        };

        const result = presenter.presentSessionTerminationSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'All sessions terminated successfully',
          data: {
            sessionsTerminated: 3,
            tokensRevoked: 5,
            allSessions: true,
          },
        });
      });

      it('should use default values if not provided', () => {
        const mockResponse = {};

        const result = presenter.presentSessionTerminationSuccess(mockResponse);

        expect(result.data.sessionsTerminated).toBe(1);
        expect(result.data.tokensRevoked).toBe(0);
        expect(result.data.allSessions).toBe(false);
      });
    });
  });

  describe('Error Response Presenters', () => {
    describe('presentUserNotFound', () => {
      it('should present user not found error with userId', () => {
        const result = presenter.presentUserNotFound('user-123');

        expect(result).toEqual({
          success: false,
          error: 'USER_NOT_FOUND',
          message: 'User profile not found',
          details: {
            userId: 'user-123',
            suggestion: 'Please check the user ID and try again',
          },
        });
      });

      it('should present user not found error without userId', () => {
        const result = presenter.presentUserNotFound();

        expect(result).toEqual({
          success: false,
          error: 'USER_NOT_FOUND',
          message: 'User profile not found',
          details: {
            userId: undefined,
            suggestion: 'Please check the user ID and try again',
          },
        });
      });
    });

    describe('presentValidationError', () => {
      it('should present validation error', () => {
        const result = presenter.presentValidationError('Name must be at least 2 characters');

        expect(result).toEqual({
          success: false,
          error: 'VALIDATION_ERROR',
          message: 'Invalid profile data',
          details: {
            error: 'Name must be at least 2 characters',
            suggestion: 'Please check your input and try again',
          },
        });
      });
    });

    describe('presentProfileUpdateValidationError', () => {
      it('should present profile update validation errors', () => {
        const errors = {
          name: ['Name is required', 'Name must be at least 2 characters'],
          website: ['Must be a valid URL'],
          bio: ['Bio cannot exceed 500 characters'],
        };

        const result = presenter.presentProfileUpdateValidationError(errors);

        expect(result).toEqual({
          success: false,
          error: 'VALIDATION_ERROR',
          message: 'Profile update validation failed',
          details: {
            errors: [
              { field: 'name', messages: ['Name is required', 'Name must be at least 2 characters'] },
              { field: 'website', messages: ['Must be a valid URL'] },
              { field: 'bio', messages: ['Bio cannot exceed 500 characters'] },
            ],
            totalErrors: 3,
            suggestion: 'Please correct the validation errors and try again',
          },
        });
      });
    });

    describe('presentInvalidFileFormat', () => {
      it('should present invalid file format error', () => {
        const allowedFormats = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
        const result = presenter.presentInvalidFileFormat(allowedFormats);

        expect(result).toEqual({
          success: false,
          error: 'INVALID_FILE_FORMAT',
          message: 'Invalid file format for profile picture',
          details: {
            allowedFormats: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
            suggestion: 'Please use one of the following formats: jpg, jpeg, png, gif, webp',
          },
        });
      });
    });

    describe('presentFileSizeExceeded', () => {
      it('should present file size exceeded error', () => {
        const maxSize = 5 * 1024 * 1024; // 5MB
        const result = presenter.presentFileSizeExceeded(maxSize);

        expect(result).toEqual({
          success: false,
          error: 'FILE_SIZE_EXCEEDED',
          message: 'Profile picture file size is too large',
          details: {
            maxSize: 5242880,
            maxSizeFormatted: '5MB',
            suggestion: 'Please choose a file smaller than 5MB',
          },
        });
      });
    });

    describe('presentPasswordChangeFailure', () => {
      it('should present password change failure', () => {
        const result = presenter.presentPasswordChangeFailure('Current password is incorrect');

        expect(result).toEqual({
          success: false,
          error: 'PASSWORD_CHANGE_ERROR',
          message: 'Failed to change password',
          details: {
            error: 'Current password is incorrect',
            suggestion: 'Please check your current password and try again',
          },
        });
      });
    });

    describe('presentInvalidCurrentPassword', () => {
      it('should present invalid current password error', () => {
        const result = presenter.presentInvalidCurrentPassword();

        expect(result).toEqual({
          success: false,
          error: 'INVALID_CURRENT_PASSWORD',
          message: 'Current password is incorrect',
          details: {
            suggestion: 'Please enter your correct current password',
          },
        });
      });
    });

    describe('presentSessionNotFound', () => {
      it('should present session not found error', () => {
        const result = presenter.presentSessionNotFound('session-123');

        expect(result).toEqual({
          success: false,
          error: 'SESSION_NOT_FOUND',
          message: 'Session not found',
          details: {
            sessionId: 'session-123',
            suggestion: 'Please check the session ID and try again',
          },
        });
      });
    });

    describe('presentUnauthorizedAccess', () => {
      it('should present unauthorized access error', () => {
        const result = presenter.presentUnauthorizedAccess();

        expect(result).toEqual({
          success: false,
          error: 'UNAUTHORIZED_ACCESS',
          message: 'You are not authorized to access this resource',
          details: {
            suggestion: 'Please log in with appropriate permissions',
          },
        });
      });
    });

    describe('presentForbiddenAction', () => {
      it('should present forbidden action error', () => {
        const result = presenter.presentForbiddenAction('delete account');

        expect(result).toEqual({
          success: false,
          error: 'FORBIDDEN_ACTION',
          message: 'You are not allowed to perform this action: delete account',
          details: {
            action: 'delete account',
            suggestion: 'Please contact support if you believe this is an error',
          },
        });
      });
    });

    describe('presentProfileError', () => {
      it('should present profile error with code', () => {
        const result = presenter.presentProfileError('Something went wrong', 'PROFILE_UPDATE_FAILED');

        expect(result).toEqual({
          success: false,
          error: 'PROFILE_UPDATE_FAILED',
          message: 'Profile operation failed',
          details: {
            error: 'Something went wrong',
            suggestion: 'Please try again or contact support',
          },
        });
      });

      it('should present profile error without code', () => {
        const result = presenter.presentProfileError('Something went wrong');

        expect(result).toEqual({
          success: false,
          error: 'PROFILE_ERROR',
          message: 'Profile operation failed',
          details: {
            error: 'Something went wrong',
            suggestion: 'Please try again or contact support',
          },
        });
      });
    });

    describe('presentServerError', () => {
      it('should present server error', () => {
        const result = presenter.presentServerError('Database connection failed');

        expect(result).toEqual({
          success: false,
          error: 'INTERNAL_SERVER_ERROR',
          message: 'An unexpected error occurred',
          details: {
            suggestion: 'Please try again later. If the problem persists, contact support.',
          },
        });
      });
    });
  });

  describe('Legacy interface methods', () => {
    it('should throw error for presentUserProfile', () => {
      expect(() => presenter.presentUserProfile({})).toThrow('Use presentGetProfileSuccess instead');
    });

    it('should throw error for presentProfileUpdateSuccess', () => {
      expect(() => presenter.presentProfileUpdateSuccess({})).toThrow('Use presentUpdateProfileSuccess instead');
    });

    it('should throw error for presentProfilePictureUploadSuccess', () => {
      expect(() => presenter.presentProfilePictureUploadSuccess({})).toThrow('Use presentUploadProfilePictureSuccess instead');
    });
  });
});