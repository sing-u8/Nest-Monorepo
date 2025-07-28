import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, UnauthorizedException, NotFoundException, InternalServerErrorException } from '@nestjs/common';
import { Request } from 'express';
import { ProfileController } from './profile.controller';
import { UpdateProfileUseCase, GetUserProfileUseCase, ProfilePresenter } from '@auth/domain';
import {
  UpdateProfileRequest,
  UpdateProfileResponse,
  GetProfileResponse,
  UploadProfilePictureRequest,
  UploadProfilePictureResponse,
} from '@auth/shared';

describe('ProfileController', () => {
  let controller: ProfileController;
  let updateProfileUseCase: jest.Mocked<UpdateProfileUseCase>;
  let getUserProfileUseCase: jest.Mocked<GetUserProfileUseCase>;
  let profilePresenter: jest.Mocked<ProfilePresenter>;
  let mockRequest: Partial<Request>;

  beforeEach(async () => {
    // Create mocked use cases and presenter
    updateProfileUseCase = {
      execute: jest.fn(),
    } as any;

    getUserProfileUseCase = {
      execute: jest.fn(),
    } as any;

    profilePresenter = {
      presentGetProfileSuccess: jest.fn(),
      presentUpdateProfileSuccess: jest.fn(),
      presentUploadProfilePictureSuccess: jest.fn(),
      presentDeleteProfilePictureSuccess: jest.fn(),
      presentUserNotFound: jest.fn(),
      presentUnauthorized: jest.fn(),
      presentValidationError: jest.fn(),
      presentInternalError: jest.fn(),
    } as any;

    // Create mock Express request
    mockRequest = {
      headers: {
        'user-agent': 'Mozilla/5.0 Test Browser',
        'x-forwarded-for': '192.168.1.1',
        'x-device-id': 'device-123',
      },
      connection: {
        remoteAddress: '192.168.1.1',
      },
      user: {
        sub: 'user-123',
        email: 'user@example.com',
      },
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ProfileController],
      providers: [
        {
          provide: 'UpdateProfileUseCase',
          useValue: updateProfileUseCase,
        },
        {
          provide: 'GetUserProfileUseCase',
          useValue: getUserProfileUseCase,
        },
        {
          provide: 'ProfilePresenter',
          useValue: profilePresenter,
        },
      ],
    }).compile();

    controller = module.get<ProfileController>(ProfileController);

    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('getProfile', () => {
    const mockProfileResult = {
      user: {
        id: 'user-123',
        email: 'user@example.com',
        name: 'John Doe',
        profilePicture: 'https://storage.example.com/profiles/user-123.jpg',
        provider: 'local',
        emailVerified: true,
        status: 'active',
        createdAt: new Date('2024-01-01'),
        updatedAt: new Date('2024-01-01'),
        lastLoginAt: new Date('2024-01-01'),
      },
      sessions: [
        {
          id: 'session-123',
          deviceInfo: 'Chrome on Windows',
          ipAddress: '192.168.1.1',
          lastActivity: new Date('2024-01-01'),
          createdAt: new Date('2024-01-01'),
          isCurrentSession: true,
        },
      ],
      accountSummary: {
        totalSessions: 3,
        activeSessions: 2,
        lastPasswordChange: new Date('2024-01-01'),
        accountAge: '90 days',
      },
    };

    it('should return user profile successfully', async () => {
      const mockResponse: GetProfileResponse = {
        success: true,
        message: 'Profile retrieved successfully',
        data: mockProfileResult,
      };

      getUserProfileUseCase.execute.mockResolvedValue(mockProfileResult);
      profilePresenter.presentGetProfileSuccess.mockReturnValue(mockResponse);

      const result = await controller.getProfile(mockRequest as Request);

      expect(getUserProfileUseCase.execute).toHaveBeenCalledWith({
        userId: 'user-123',
      });
      expect(profilePresenter.presentGetProfileSuccess).toHaveBeenCalledWith(mockProfileResult);
      expect(result).toEqual(mockResponse);
    });

    it('should handle user not found error', async () => {
      const error = new Error('User not found');
      getUserProfileUseCase.execute.mockRejectedValue(error);
      profilePresenter.presentUserNotFound.mockReturnValue({
        success: false,
        error: 'USER_NOT_FOUND',
        message: 'User profile not found',
      });

      await expect(controller.getProfile(mockRequest as Request)).rejects.toThrow(NotFoundException);
      expect(profilePresenter.presentUserNotFound).toHaveBeenCalled();
    });

    it('should handle unauthorized access', async () => {
      const error = new Error('Unauthorized access');
      getUserProfileUseCase.execute.mockRejectedValue(error);
      profilePresenter.presentUnauthorized.mockReturnValue({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'Invalid or expired authentication token',
      });

      await expect(controller.getProfile(mockRequest as Request)).rejects.toThrow(UnauthorizedException);
      expect(profilePresenter.presentUnauthorized).toHaveBeenCalled();
    });

    it('should handle invalid token payload', async () => {
      const invalidRequest = {
        ...mockRequest,
        user: null,
      } as Request;

      await expect(controller.getProfile(invalidRequest)).rejects.toThrow(UnauthorizedException);
    });

    it('should handle internal server errors', async () => {
      const error = new Error('Database connection failed');
      getUserProfileUseCase.execute.mockRejectedValue(error);
      profilePresenter.presentInternalError.mockReturnValue({
        success: false,
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      });

      await expect(controller.getProfile(mockRequest as Request)).rejects.toThrow(InternalServerErrorException);
      expect(profilePresenter.presentInternalError).toHaveBeenCalled();
    });
  });

  describe('updateProfile', () => {
    const mockUpdateRequest: UpdateProfileRequest = {
      name: 'John Smith',
      bio: 'Software developer with 5 years of experience',
      location: 'San Francisco, CA',
      website: 'https://johnsmith.dev',
    };

    const mockUpdateResult = {
      user: {
        id: 'user-123',
        email: 'user@example.com',
        name: 'John Smith',
        bio: 'Software developer with 5 years of experience',
        location: 'San Francisco, CA',
        website: 'https://johnsmith.dev',
        profilePicture: 'https://storage.example.com/profiles/user-123.jpg',
        updatedAt: new Date('2024-01-01'),
      },
      changes: [
        {
          field: 'name',
          oldValue: 'John Doe',
          newValue: 'John Smith',
        },
        {
          field: 'bio',
          oldValue: null,
          newValue: 'Software developer with 5 years of experience',
        },
      ],
    };

    it('should update profile successfully', async () => {
      const mockResponse: UpdateProfileResponse = {
        success: true,
        message: 'Profile updated successfully',
        data: mockUpdateResult,
      };

      updateProfileUseCase.execute.mockResolvedValue(mockUpdateResult);
      profilePresenter.presentUpdateProfileSuccess.mockReturnValue(mockResponse);

      const result = await controller.updateProfile(mockUpdateRequest, mockRequest as Request);

      expect(updateProfileUseCase.execute).toHaveBeenCalledWith({
        ...mockUpdateRequest,
        userId: 'user-123',
        clientInfo: {
          userAgent: 'Mozilla/5.0 Test Browser',
          ipAddress: '192.168.1.1',
          deviceId: 'device-123',
        },
      });
      expect(profilePresenter.presentUpdateProfileSuccess).toHaveBeenCalledWith(mockUpdateResult);
      expect(result).toEqual(mockResponse);
    });

    it('should handle validation errors', async () => {
      const error = new Error('Validation failed: Invalid name length');
      updateProfileUseCase.execute.mockRejectedValue(error);
      profilePresenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Invalid profile data',
        details: [
          {
            field: 'name',
            message: 'Name must be between 2 and 100 characters',
          },
        ],
      });

      await expect(
        controller.updateProfile(mockUpdateRequest, mockRequest as Request)
      ).rejects.toThrow(BadRequestException);
      expect(profilePresenter.presentValidationError).toHaveBeenCalledWith('Validation failed: Invalid name length');
    });

    it('should handle user not found error', async () => {
      const error = new Error('User not found');
      updateProfileUseCase.execute.mockRejectedValue(error);
      profilePresenter.presentUserNotFound.mockReturnValue({
        success: false,
        error: 'USER_NOT_FOUND',
        message: 'User profile not found',
      });

      await expect(
        controller.updateProfile(mockUpdateRequest, mockRequest as Request)
      ).rejects.toThrow(NotFoundException);
      expect(profilePresenter.presentUserNotFound).toHaveBeenCalled();
    });

    it('should extract client info correctly', async () => {
      updateProfileUseCase.execute.mockResolvedValue(mockUpdateResult);
      profilePresenter.presentUpdateProfileSuccess.mockReturnValue({} as any);

      await controller.updateProfile(mockUpdateRequest, mockRequest as Request);

      expect(updateProfileUseCase.execute).toHaveBeenCalledWith({
        ...mockUpdateRequest,
        userId: 'user-123',
        clientInfo: {
          userAgent: 'Mozilla/5.0 Test Browser',
          ipAddress: '192.168.1.1',
          deviceId: 'device-123',
        },
      });
    });
  });

  describe('uploadProfilePicture', () => {
    const mockFile: Express.Multer.File = {
      fieldname: 'file',
      originalname: 'profile.jpg',
      encoding: '7bit',
      mimetype: 'image/jpeg',
      size: 245760,
      buffer: Buffer.from('mock-image-data'),
      destination: '',
      filename: '',
      path: '',
      stream: null as any,
    };

    const mockUploadResult = {
      user: {
        id: 'user-123',
        email: 'user@example.com',
        name: 'John Doe',
        profilePicture: 'https://storage.example.com/profiles/user-123.jpg',
        updatedAt: new Date('2024-01-01'),
      },
      upload: {
        originalName: 'profile.jpg',
        fileName: 'user-123-1640995200000.jpg',
        size: 245760,
        mimeType: 'image/jpeg',
        url: 'https://storage.example.com/profiles/user-123.jpg',
      },
    };

    it('should upload profile picture successfully', async () => {
      const mockResponse: UploadProfilePictureResponse = {
        success: true,
        message: 'Profile picture uploaded successfully',
        data: mockUploadResult,
      };

      updateProfileUseCase.execute.mockResolvedValue(mockUploadResult);
      profilePresenter.presentUploadProfilePictureSuccess.mockReturnValue(mockResponse);

      const result = await controller.uploadProfilePicture(mockFile, mockRequest as Request);

      expect(updateProfileUseCase.execute).toHaveBeenCalledWith({
        userId: 'user-123',
        file: {
          originalName: 'profile.jpg',
          mimeType: 'image/jpeg',
          size: 245760,
          buffer: Buffer.from('mock-image-data'),
        },
        clientInfo: {
          userAgent: 'Mozilla/5.0 Test Browser',
          ipAddress: '192.168.1.1',
          deviceId: 'device-123',
        },
      });
      expect(profilePresenter.presentUploadProfilePictureSuccess).toHaveBeenCalledWith(mockUploadResult);
      expect(result).toEqual(mockResponse);
    });

    it('should handle missing file', async () => {
      profilePresenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Profile picture file is required',
      });

      await expect(
        controller.uploadProfilePicture(null as any, mockRequest as Request)
      ).rejects.toThrow(BadRequestException);
      expect(profilePresenter.presentValidationError).toHaveBeenCalledWith('Profile picture file is required');
    });

    it('should handle file upload errors', async () => {
      const error = new Error('File processing failed');
      updateProfileUseCase.execute.mockRejectedValue(error);
      profilePresenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'File processing failed',
      });

      await expect(
        controller.uploadProfilePicture(mockFile, mockRequest as Request)
      ).rejects.toThrow(BadRequestException);
      expect(profilePresenter.presentValidationError).toHaveBeenCalledWith('File processing failed');
    });

    it('should handle user not found error', async () => {
      const error = new Error('User not found');
      updateProfileUseCase.execute.mockRejectedValue(error);
      profilePresenter.presentUserNotFound.mockReturnValue({
        success: false,
        error: 'USER_NOT_FOUND',
        message: 'User profile not found',
      });

      await expect(
        controller.uploadProfilePicture(mockFile, mockRequest as Request)
      ).rejects.toThrow(NotFoundException);
      expect(profilePresenter.presentUserNotFound).toHaveBeenCalled();
    });
  });

  describe('deleteProfilePicture', () => {
    const mockDeleteResult = {
      user: {
        id: 'user-123',
        email: 'user@example.com',
        name: 'John Doe',
        profilePicture: null,
        updatedAt: new Date('2024-01-01'),
      },
    };

    it('should delete profile picture successfully', async () => {
      const mockResponse: UpdateProfileResponse = {
        success: true,
        message: 'Profile picture deleted successfully',
        data: mockDeleteResult,
      };

      updateProfileUseCase.execute.mockResolvedValue(mockDeleteResult);
      profilePresenter.presentDeleteProfilePictureSuccess.mockReturnValue(mockResponse);

      const result = await controller.deleteProfilePicture(mockRequest as Request);

      expect(updateProfileUseCase.execute).toHaveBeenCalledWith({
        userId: 'user-123',
        profilePicture: null,
        clientInfo: {
          userAgent: 'Mozilla/5.0 Test Browser',
          ipAddress: '192.168.1.1',
          deviceId: 'device-123',
        },
      });
      expect(profilePresenter.presentDeleteProfilePictureSuccess).toHaveBeenCalledWith(mockDeleteResult);
      expect(result).toEqual(mockResponse);
    });

    it('should handle user not found error', async () => {
      const error = new Error('User not found');
      updateProfileUseCase.execute.mockRejectedValue(error);
      profilePresenter.presentUserNotFound.mockReturnValue({
        success: false,
        error: 'USER_NOT_FOUND',
        message: 'User profile not found',
      });

      await expect(controller.deleteProfilePicture(mockRequest as Request)).rejects.toThrow(NotFoundException);
      expect(profilePresenter.presentUserNotFound).toHaveBeenCalled();
    });

    it('should handle unauthorized access', async () => {
      const error = new Error('Unauthorized access');
      updateProfileUseCase.execute.mockRejectedValue(error);
      profilePresenter.presentUnauthorized.mockReturnValue({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'Invalid or expired authentication token',
      });

      await expect(controller.deleteProfilePicture(mockRequest as Request)).rejects.toThrow(UnauthorizedException);
      expect(profilePresenter.presentUnauthorized).toHaveBeenCalled();
    });
  });

  describe('helper methods', () => {
    it('should extract client IP from various headers', () => {
      const testCases = [
        {
          headers: { 'x-forwarded-for': '203.0.113.1,192.168.1.1' },
          expected: '203.0.113.1',
        },
        {
          headers: { 'x-real-ip': '203.0.113.2' },
          expected: '203.0.113.2',
        },
        {
          headers: {},
          connection: { remoteAddress: '203.0.113.3' },
          expected: '203.0.113.3',
        },
        {
          headers: {},
          connection: {},
          socket: { remoteAddress: '203.0.113.4' },
          expected: '203.0.113.4',
        },
        {
          headers: {},
          connection: {},
          socket: {},
          expected: 'unknown',
        },
      ];

      for (const testCase of testCases) {
        const req = {
          headers: testCase.headers,
          connection: testCase.connection || {},
          socket: testCase.socket || {},
          user: { sub: 'user-123' },
        } as Request;

        // Test through a public method that uses extractClientIP
        updateProfileUseCase.execute.mockResolvedValue({} as any);
        profilePresenter.presentUpdateProfileSuccess.mockReturnValue({} as any);

        controller.updateProfile({ name: 'Test' }, req);

        expect(updateProfileUseCase.execute).toHaveBeenCalledWith(
          expect.objectContaining({
            clientInfo: expect.objectContaining({
              ipAddress: testCase.expected,
            }),
          })
        );

        jest.clearAllMocks();
      }
    });

    it('should handle missing user in request', () => {
      const reqWithoutUser = {
        headers: {},
        connection: {},
        socket: {},
      } as Request;

      expect(() => {
        // This should trigger the extractUserIdFromRequest method
        controller.getProfile(reqWithoutUser);
      }).rejects.toThrow(UnauthorizedException);
    });

    it('should handle invalid user payload', () => {
      const reqWithInvalidUser = {
        headers: {},
        connection: {},
        socket: {},
        user: { email: 'test@example.com' }, // Missing sub
      } as any;

      expect(() => {
        controller.getProfile(reqWithInvalidUser);
      }).rejects.toThrow(UnauthorizedException);
    });
  });
});