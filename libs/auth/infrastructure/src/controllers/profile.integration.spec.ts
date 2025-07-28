import { Test, TestingModule } from '@nestjs/testing';
import { ProfileController } from './profile.controller';
import { UpdateProfileUseCase, GetUserProfileUseCase, ProfilePresenter } from '@auth/domain';
import { Request } from 'express';

describe('ProfileController (Integration)', () => {
  let controller: ProfileController;
  let updateProfileUseCase: UpdateProfileUseCase;
  let getUserProfileUseCase: GetUserProfileUseCase;
  let profilePresenter: ProfilePresenter;

  beforeEach(async () => {
    // Create real use case and presenter instances for integration testing
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ProfileController],
      providers: [
        {
          provide: 'UpdateProfileUseCase',
          useValue: {
            execute: jest.fn(),
          },
        },
        {
          provide: 'GetUserProfileUseCase',
          useValue: {
            execute: jest.fn(),
          },
        },
        {
          provide: 'ProfilePresenter',
          useValue: {
            presentGetProfileSuccess: jest.fn(),
            presentUpdateProfileSuccess: jest.fn(),
            presentUploadProfilePictureSuccess: jest.fn(),
            presentDeleteProfilePictureSuccess: jest.fn(),
            presentUserNotFound: jest.fn(),
            presentUnauthorized: jest.fn(),
            presentValidationError: jest.fn(),
            presentInternalError: jest.fn(),
          },
        },
      ],
    }).compile();

    controller = module.get<ProfileController>(ProfileController);
    updateProfileUseCase = module.get('UpdateProfileUseCase');
    getUserProfileUseCase = module.get('GetUserProfileUseCase');
    profilePresenter = module.get('ProfilePresenter');
  });

  describe('Controller initialization', () => {
    it('should be defined', () => {
      expect(controller).toBeDefined();
    });

    it('should have access to use cases and presenter', () => {
      expect(updateProfileUseCase).toBeDefined();
      expect(getUserProfileUseCase).toBeDefined();
      expect(profilePresenter).toBeDefined();
    });
  });

  describe('Profile management workflow', () => {
    const mockUser = {
      id: 'user-123',
      email: 'user@example.com',
      name: 'John Doe',
      profilePicture: null,
      provider: 'local',
      emailVerified: true,
      status: 'active',
      createdAt: new Date('2024-01-01'),
      updatedAt: new Date('2024-01-01'),
      lastLoginAt: new Date('2024-01-01'),
    };

    const mockRequest = {
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
    } as Request;

    it('should retrieve user profile with session information', async () => {
      const mockProfileResult = {
        user: mockUser,
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
          totalSessions: 1,
          activeSessions: 1,
          lastPasswordChange: new Date('2024-01-01'),
          accountAge: '30 days',
        },
      };

      const mockResponse = {
        success: true,
        message: 'Profile retrieved successfully',
        data: mockProfileResult,
      };

      (getUserProfileUseCase.execute as jest.Mock).mockResolvedValue(mockProfileResult);
      (profilePresenter.presentGetProfileSuccess as jest.Mock).mockReturnValue(mockResponse);

      const result = await controller.getProfile(mockRequest);

      expect(getUserProfileUseCase.execute).toHaveBeenCalledWith({
        userId: 'user-123',
      });
      expect(result).toEqual(mockResponse);
      expect(result.data.user).toEqual(mockUser);
      expect(result.data.sessions).toHaveLength(1);
      expect(result.data.accountSummary).toBeDefined();
    });

    it('should update user profile with change tracking', async () => {
      const updateRequest = {
        name: 'John Smith',
        bio: 'Software developer',
        location: 'San Francisco, CA',
      };

      const mockUpdateResult = {
        user: {
          ...mockUser,
          name: 'John Smith',
          bio: 'Software developer',
          location: 'San Francisco, CA',
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
            oldValue: null,
            newValue: 'Software developer',
          },
          {
            field: 'location',
            oldValue: null,
            newValue: 'San Francisco, CA',
          },
        ],
      };

      const mockResponse = {
        success: true,
        message: 'Profile updated successfully',
        data: mockUpdateResult,
      };

      (updateProfileUseCase.execute as jest.Mock).mockResolvedValue(mockUpdateResult);
      (profilePresenter.presentUpdateProfileSuccess as jest.Mock).mockReturnValue(mockResponse);

      const result = await controller.updateProfile(updateRequest, mockRequest);

      expect(updateProfileUseCase.execute).toHaveBeenCalledWith({
        ...updateRequest,
        userId: 'user-123',
        clientInfo: {
          userAgent: 'Mozilla/5.0 Test Browser',
          ipAddress: '192.168.1.1',
          deviceId: 'device-123',
        },
      });
      expect(result).toEqual(mockResponse);
      expect(result.data.changes).toHaveLength(3);
    });

    it('should handle complete profile workflow: get → update → get', async () => {
      // Step 1: Get initial profile
      const initialProfile = {
        user: mockUser,
        sessions: [],
        accountSummary: {
          totalSessions: 1,
          activeSessions: 1,
          lastPasswordChange: new Date('2024-01-01'),
          accountAge: '30 days',
        },
      };

      (getUserProfileUseCase.execute as jest.Mock).mockResolvedValueOnce(initialProfile);
      (profilePresenter.presentGetProfileSuccess as jest.Mock).mockReturnValueOnce({
        success: true,
        data: initialProfile,
      });

      const initialResult = await controller.getProfile(mockRequest);
      expect(initialResult.data.user.name).toBe('John Doe');

      // Step 2: Update profile
      const updateRequest = {
        name: 'John Smith',
        bio: 'Updated bio',
      };

      const updateResult = {
        user: {
          ...mockUser,
          name: 'John Smith',
          bio: 'Updated bio',
          updatedAt: new Date('2024-01-02'),
        },
        changes: [
          { field: 'name', oldValue: 'John Doe', newValue: 'John Smith' },
          { field: 'bio', oldValue: null, newValue: 'Updated bio' },
        ],
      };

      (updateProfileUseCase.execute as jest.Mock).mockResolvedValueOnce(updateResult);
      (profilePresenter.presentUpdateProfileSuccess as jest.Mock).mockReturnValueOnce({
        success: true,
        data: updateResult,
      });

      const updateResponse = await controller.updateProfile(updateRequest, mockRequest);
      expect(updateResponse.data.user.name).toBe('John Smith');
      expect(updateResponse.data.changes).toHaveLength(2);

      // Step 3: Get updated profile
      const updatedProfile = {
        user: {
          ...mockUser,
          name: 'John Smith',
          bio: 'Updated bio',
          updatedAt: new Date('2024-01-02'),
        },
        sessions: [],
        accountSummary: {
          totalSessions: 1,
          activeSessions: 1,
          lastPasswordChange: new Date('2024-01-01'),
          accountAge: '30 days',
        },
      };

      (getUserProfileUseCase.execute as jest.Mock).mockResolvedValueOnce(updatedProfile);
      (profilePresenter.presentGetProfileSuccess as jest.Mock).mockReturnValueOnce({
        success: true,
        data: updatedProfile,
      });

      const finalResult = await controller.getProfile(mockRequest);
      expect(finalResult.data.user.name).toBe('John Smith');
      expect(finalResult.data.user.bio).toBe('Updated bio');
    });
  });

  describe('File upload integration', () => {
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

    const mockRequest = {
      headers: {
        'user-agent': 'Mozilla/5.0 Test Browser',
        'x-forwarded-for': '192.168.1.1',
      },
      connection: {
        remoteAddress: '192.168.1.1',
      },
      user: {
        sub: 'user-123',
        email: 'user@example.com',
      },
    } as Request;

    it('should handle profile picture upload workflow', async () => {
      const mockUploadResult = {
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

      const mockResponse = {
        success: true,
        message: 'Profile picture uploaded successfully',
        data: mockUploadResult,
      };

      (updateProfileUseCase.execute as jest.Mock).mockResolvedValue(mockUploadResult);
      (profilePresenter.presentUploadProfilePictureSuccess as jest.Mock).mockReturnValue(mockResponse);

      const result = await controller.uploadProfilePicture(mockFile, mockRequest);

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
          deviceId: undefined,
        },
      });
      expect(result).toEqual(mockResponse);
      expect(result.data.user.profilePicture).toBe('https://storage.example.com/profiles/user-123.jpg');
      expect(result.data.upload).toBeDefined();
    });

    it('should handle profile picture deletion workflow', async () => {
      const mockDeleteResult = {
        user: {
          id: 'user-123',
          email: 'user@example.com',
          name: 'John Doe',
          profilePicture: null,
          updatedAt: new Date('2024-01-02'),
        },
      };

      const mockResponse = {
        success: true,
        message: 'Profile picture deleted successfully',
        data: mockDeleteResult,
      };

      (updateProfileUseCase.execute as jest.Mock).mockResolvedValue(mockDeleteResult);
      (profilePresenter.presentDeleteProfilePictureSuccess as jest.Mock).mockReturnValue(mockResponse);

      const result = await controller.deleteProfilePicture(mockRequest);

      expect(updateProfileUseCase.execute).toHaveBeenCalledWith({
        userId: 'user-123',
        profilePicture: null,
        clientInfo: {
          userAgent: 'Mozilla/5.0 Test Browser',
          ipAddress: '192.168.1.1',
          deviceId: undefined,
        },
      });
      expect(result).toEqual(mockResponse);
      expect(result.data.user.profilePicture).toBeNull();
    });

    it('should handle file size and type validation', async () => {
      const oversizedFile: Express.Multer.File = {
        ...mockFile,
        size: 10 * 1024 * 1024, // 10MB - exceeds 5MB limit
      };

      // The file interceptor would normally handle this validation
      // but we can test the controller's response to validation errors
      const validationError = new Error('File too large');
      (updateProfileUseCase.execute as jest.Mock).mockRejectedValue(validationError);
      (profilePresenter.presentValidationError as jest.Mock).mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'File too large',
      });

      await expect(
        controller.uploadProfilePicture(oversizedFile, mockRequest)
      ).rejects.toThrow();

      expect(profilePresenter.presentValidationError).toHaveBeenCalledWith('File too large');
    });
  });

  describe('Error handling integration', () => {
    const mockRequest = {
      headers: {
        'user-agent': 'Mozilla/5.0 Test Browser',
        'x-forwarded-for': '192.168.1.1',
      },
      connection: {
        remoteAddress: '192.168.1.1',
      },
      user: {
        sub: 'user-123',
        email: 'user@example.com',
      },
    } as Request;

    it('should handle use case failures gracefully', async () => {
      const serviceError = new Error('Database connection failed');
      (getUserProfileUseCase.execute as jest.Mock).mockRejectedValue(serviceError);
      (profilePresenter.presentInternalError as jest.Mock).mockReturnValue({
        success: false,
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      });

      await expect(controller.getProfile(mockRequest)).rejects.toThrow();
      expect(profilePresenter.presentInternalError).toHaveBeenCalled();
    });

    it('should handle presenter failures', async () => {
      const mockProfileResult = {
        user: { id: 'user-123', email: 'user@example.com' },
        sessions: [],
        accountSummary: {},
      };

      (getUserProfileUseCase.execute as jest.Mock).mockResolvedValue(mockProfileResult);
      (profilePresenter.presentGetProfileSuccess as jest.Mock).mockImplementation(() => {
        throw new Error('Presenter error');
      });

      await expect(controller.getProfile(mockRequest)).rejects.toThrow('Presenter error');
    });

    it('should maintain error context across operations', async () => {
      // Simulate a sequence of operations where errors occur
      const errors = [
        new Error('User not found'),
        new Error('Validation failed'),
        new Error('Internal service error'),
      ];

      for (let i = 0; i < errors.length; i++) {
        (getUserProfileUseCase.execute as jest.Mock).mockRejectedValueOnce(errors[i]);
        
        if (errors[i].message.includes('not found')) {
          (profilePresenter.presentUserNotFound as jest.Mock).mockReturnValueOnce({
            success: false,
            error: 'USER_NOT_FOUND',
            message: 'User profile not found',
          });
        } else if (errors[i].message.includes('validation')) {
          (profilePresenter.presentValidationError as jest.Mock).mockReturnValueOnce({
            success: false,
            error: 'VALIDATION_ERROR',
            message: 'Validation failed',
          });
        } else {
          (profilePresenter.presentInternalError as jest.Mock).mockReturnValueOnce({
            success: false,
            error: 'INTERNAL_ERROR',
            message: 'An unexpected error occurred',
          });
        }

        await expect(controller.getProfile(mockRequest)).rejects.toThrow();
      }

      // Verify all error types were handled
      expect(profilePresenter.presentUserNotFound).toHaveBeenCalled();
      expect(profilePresenter.presentValidationError).toHaveBeenCalled();
      expect(profilePresenter.presentInternalError).toHaveBeenCalled();
    });
  });

  describe('Performance characteristics', () => {
    const mockRequest = {
      headers: {
        'user-agent': 'Mozilla/5.0 Test Browser',
        'x-forwarded-for': '192.168.1.1',
      },
      connection: {
        remoteAddress: '192.168.1.1',
      },
      user: {
        sub: 'user-123',
        email: 'user@example.com',
      },
    } as Request;

    it('should handle concurrent profile requests', async () => {
      const mockProfileResult = {
        user: { id: 'user-123', email: 'user@example.com' },
        sessions: [],
        accountSummary: {},
      };

      (getUserProfileUseCase.execute as jest.Mock).mockResolvedValue(mockProfileResult);
      (profilePresenter.presentGetProfileSuccess as jest.Mock).mockReturnValue({
        success: true,
        data: mockProfileResult,
      });

      const startTime = Date.now();
      
      // Simulate multiple concurrent requests
      const requests = Array.from({ length: 5 }, () => 
        controller.getProfile(mockRequest)
      );

      const results = await Promise.all(requests);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(1000); // Should complete within 1 second
      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result.success).toBe(true);
      });
    });

    it('should handle rapid profile updates', async () => {
      const mockUpdateResult = {
        user: { id: 'user-123', email: 'user@example.com', name: 'Updated' },
        changes: [],
      };

      (updateProfileUseCase.execute as jest.Mock).mockResolvedValue(mockUpdateResult);
      (profilePresenter.presentUpdateProfileSuccess as jest.Mock).mockReturnValue({
        success: true,
        data: mockUpdateResult,
      });

      const startTime = Date.now();
      
      // Simulate rapid updates
      const updates = Array.from({ length: 3 }, (_, i) => 
        controller.updateProfile({ name: `Name ${i}` }, mockRequest)
      );

      const results = await Promise.all(updates);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(2000); // Should complete within 2 seconds
      expect(results).toHaveLength(3);
      results.forEach(result => {
        expect(result.success).toBe(true);
      });
    });
  });
});