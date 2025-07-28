import {
  Controller,
  Get,
  Put,
  Post,
  Body,
  UseGuards,
  Req,
  HttpStatus,
  HttpCode,
  BadRequestException,
  UnauthorizedException,
  NotFoundException,
  InternalServerErrorException,
  ValidationPipe,
  UsePipes,
  UseInterceptors,
  UploadedFile,
  Inject,
  Logger,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiBearerAuth, ApiConsumes } from '@nestjs/swagger';
import { Request } from 'express';
import { UpdateProfileUseCase, GetUserProfileUseCase, ProfilePresenter } from '@auth/domain';
import { JwtAuthGuard } from '../guards';
import {
  UpdateProfileRequest,
  UpdateProfileResponse,
  GetProfileResponse,
  UploadProfilePictureRequest,
  UploadProfilePictureResponse,
} from '@auth/shared';

/**
 * Profile Controller
 * 
 * Handles user profile management operations:
 * - Get user profile information
 * - Update user profile (name, etc.)
 * - Upload and update profile picture
 * 
 * All endpoints require JWT authentication and include
 * comprehensive validation and error handling.
 */
@ApiTags('User Profile')
@Controller('profile')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
@UsePipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
  validateCustomDecorators: true,
}))
export class ProfileController {
  private readonly logger = new Logger(ProfileController.name);

  constructor(
    @Inject('UpdateProfileUseCase')
    private readonly updateProfileUseCase: UpdateProfileUseCase,

    @Inject('GetUserProfileUseCase')
    private readonly getUserProfileUseCase: GetUserProfileUseCase,

    @Inject('ProfilePresenter')
    private readonly profilePresenter: ProfilePresenter,
  ) {}

  /**
   * Get user profile
   * GET /profile
   */
  @Get()
  @ApiOperation({
    summary: 'Get user profile',
    description: 'Retrieve the authenticated user\'s profile information',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Profile retrieved successfully',
    type: GetProfileResponse,
    schema: {
      example: {
        success: true,
        message: 'Profile retrieved successfully',
        data: {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
            profilePicture: 'https://storage.example.com/profiles/user-123.jpg',
            provider: 'local',
            emailVerified: true,
            status: 'active',
            createdAt: '2024-01-01T00:00:00.000Z',
            updatedAt: '2024-01-01T00:00:00.000Z',
            lastLoginAt: '2024-01-01T00:00:00.000Z',
          },
          sessions: [
            {
              id: 'session-123',
              deviceInfo: 'Chrome on Windows',
              ipAddress: '192.168.1.1',
              lastActivity: '2024-01-01T00:00:00.000Z',
              createdAt: '2024-01-01T00:00:00.000Z',
              isCurrentSession: true,
            },
          ],
          accountSummary: {
            totalSessions: 3,
            activeSessions: 2,
            lastPasswordChange: '2024-01-01T00:00:00.000Z',
            accountAge: '90 days',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired token',
    schema: {
      example: {
        success: false,
        error: 'UNAUTHORIZED',
        message: 'Invalid or expired authentication token',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User profile not found',
    schema: {
      example: {
        success: false,
        error: 'USER_NOT_FOUND',
        message: 'User profile not found',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
  })
  async getProfile(@Req() req: Request): Promise<GetProfileResponse> {
    try {
      const userId = this.extractUserIdFromRequest(req);
      
      this.logger.log(`Getting profile for user: ${userId}`);

      const result = await this.getUserProfileUseCase.execute({ userId });

      this.logger.log(`Profile retrieved successfully for user: ${userId}`);
      return this.profilePresenter.presentGetProfileSuccess(result);

    } catch (error) {
      this.logger.error('Failed to get user profile:', error);

      if (error.message?.includes('not found')) {
        throw new NotFoundException(
          this.profilePresenter.presentUserNotFound()
        );
      }

      if (error.message?.includes('unauthorized') || error.message?.includes('invalid token')) {
        throw new UnauthorizedException(
          this.profilePresenter.presentUnauthorized()
        );
      }

      throw new InternalServerErrorException(
        this.profilePresenter.presentInternalError()
      );
    }
  }

  /**
   * Update user profile
   * PUT /profile
   */
  @Put()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Update user profile',
    description: 'Update the authenticated user\'s profile information (name, etc.)',
  })
  @ApiBody({
    type: UpdateProfileRequest,
    description: 'Profile update data',
    examples: {
      'update-name': {
        summary: 'Update name',
        description: 'Example of updating user name',
        value: {
          name: 'John Smith',
        },
      },
      'complete-update': {
        summary: 'Complete profile update',
        description: 'Example of updating multiple profile fields',
        value: {
          name: 'John Smith',
          bio: 'Software developer with 5 years of experience',
          location: 'San Francisco, CA',
          website: 'https://johnsmith.dev',
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Profile updated successfully',
    type: UpdateProfileResponse,
    schema: {
      example: {
        success: true,
        message: 'Profile updated successfully',
        data: {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Smith',
            bio: 'Software developer with 5 years of experience',
            location: 'San Francisco, CA',
            website: 'https://johnsmith.dev',
            profilePicture: 'https://storage.example.com/profiles/user-123.jpg',
            updatedAt: '2024-01-01T00:00:00.000Z',
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
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid profile data',
    schema: {
      example: {
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Invalid profile data',
        details: [
          {
            field: 'name',
            message: 'Name must be between 2 and 100 characters',
          },
          {
            field: 'website',
            message: 'Website must be a valid URL',
          },
        ],
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired token',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User not found',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
  })
  async updateProfile(
    @Body() request: UpdateProfileRequest,
    @Req() req: Request,
  ): Promise<UpdateProfileResponse> {
    try {
      const userId = this.extractUserIdFromRequest(req);
      
      this.logger.log(`Updating profile for user: ${userId}`);

      const updateRequest = {
        ...request,
        userId,
        clientInfo: {
          userAgent: req.headers['user-agent'] || 'unknown',
          ipAddress: this.extractClientIP(req),
          deviceId: req.headers['x-device-id'] as string || undefined,
        },
      };

      const result = await this.updateProfileUseCase.execute(updateRequest);

      this.logger.log(`Profile updated successfully for user: ${userId}`);
      return this.profilePresenter.presentUpdateProfileSuccess(result);

    } catch (error) {
      this.logger.error('Failed to update user profile:', error);

      if (error.message?.includes('validation') || error.message?.includes('invalid')) {
        throw new BadRequestException(
          this.profilePresenter.presentValidationError(error.message)
        );
      }

      if (error.message?.includes('not found')) {
        throw new NotFoundException(
          this.profilePresenter.presentUserNotFound()
        );
      }

      if (error.message?.includes('unauthorized')) {
        throw new UnauthorizedException(
          this.profilePresenter.presentUnauthorized()
        );
      }

      throw new InternalServerErrorException(
        this.profilePresenter.presentInternalError()
      );
    }
  }

  /**
   * Upload profile picture
   * POST /profile/picture
   */
  @Post('picture')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(FileInterceptor('file', {
    limits: {
      fileSize: 5 * 1024 * 1024, // 5MB
      files: 1,
    },
    fileFilter: (req, file, callback) => {
      // Allow only image files
      const allowedMimeTypes = [
        'image/jpeg',
        'image/jpg',
        'image/png',
        'image/gif',
        'image/webp',
      ];
      
      if (allowedMimeTypes.includes(file.mimetype)) {
        callback(null, true);
      } else {
        callback(new BadRequestException('Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.'), false);
      }
    },
  }))
  @ApiConsumes('multipart/form-data')
  @ApiOperation({
    summary: 'Upload profile picture',
    description: 'Upload and update the authenticated user\'s profile picture',
  })
  @ApiBody({
    type: UploadProfilePictureRequest,
    description: 'Profile picture file upload',
    schema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          format: 'binary',
          description: 'Image file (JPEG, PNG, GIF, WebP) - max 5MB',
        },
      },
      required: ['file'],
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Profile picture uploaded successfully',
    type: UploadProfilePictureResponse,
    schema: {
      example: {
        success: true,
        message: 'Profile picture uploaded successfully',
        data: {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
            profilePicture: 'https://storage.example.com/profiles/user-123.jpg',
            updatedAt: '2024-01-01T00:00:00.000Z',
          },
          upload: {
            originalName: 'profile.jpg',
            fileName: 'user-123-1640995200000.jpg',
            size: 245760,
            mimeType: 'image/jpeg',
            url: 'https://storage.example.com/profiles/user-123.jpg',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid file or file too large',
    schema: {
      example: {
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired token',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User not found',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
  })
  async uploadProfilePicture(
    @UploadedFile() file: Express.Multer.File,
    @Req() req: Request,
  ): Promise<UploadProfilePictureResponse> {
    try {
      if (!file) {
        throw new BadRequestException(
          this.profilePresenter.presentValidationError('Profile picture file is required')
        );
      }

      const userId = this.extractUserIdFromRequest(req);
      
      this.logger.log(`Uploading profile picture for user: ${userId}, file: ${file.originalname}`);

      const uploadRequest = {
        userId,
        file: {
          originalName: file.originalname,
          mimeType: file.mimetype,
          size: file.size,
          buffer: file.buffer,
        },
        clientInfo: {
          userAgent: req.headers['user-agent'] || 'unknown',
          ipAddress: this.extractClientIP(req),
          deviceId: req.headers['x-device-id'] as string || undefined,
        },
      };

      const result = await this.updateProfileUseCase.execute(uploadRequest);

      this.logger.log(`Profile picture uploaded successfully for user: ${userId}`);
      return this.profilePresenter.presentUploadProfilePictureSuccess(result);

    } catch (error) {
      this.logger.error('Failed to upload profile picture:', error);

      if (error instanceof BadRequestException) {
        throw error;
      }

      if (error.message?.includes('validation') || 
          error.message?.includes('invalid') ||
          error.message?.includes('file')) {
        throw new BadRequestException(
          this.profilePresenter.presentValidationError(error.message)
        );
      }

      if (error.message?.includes('not found')) {
        throw new NotFoundException(
          this.profilePresenter.presentUserNotFound()
        );
      }

      if (error.message?.includes('unauthorized')) {
        throw new UnauthorizedException(
          this.profilePresenter.presentUnauthorized()
        );
      }

      throw new InternalServerErrorException(
        this.profilePresenter.presentInternalError()
      );
    }
  }

  /**
   * Delete profile picture
   * DELETE /profile/picture
   */
  @Put('picture/delete')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Delete profile picture',
    description: 'Remove the authenticated user\'s profile picture',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Profile picture deleted successfully',
    schema: {
      example: {
        success: true,
        message: 'Profile picture deleted successfully',
        data: {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
            profilePicture: null,
            updatedAt: '2024-01-01T00:00:00.000Z',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired token',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User not found or no profile picture to delete',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
  })
  async deleteProfilePicture(@Req() req: Request): Promise<UpdateProfileResponse> {
    try {
      const userId = this.extractUserIdFromRequest(req);
      
      this.logger.log(`Deleting profile picture for user: ${userId}`);

      const deleteRequest = {
        userId,
        profilePicture: null, // Setting to null removes the picture
        clientInfo: {
          userAgent: req.headers['user-agent'] || 'unknown',
          ipAddress: this.extractClientIP(req),
          deviceId: req.headers['x-device-id'] as string || undefined,
        },
      };

      const result = await this.updateProfileUseCase.execute(deleteRequest);

      this.logger.log(`Profile picture deleted successfully for user: ${userId}`);
      return this.profilePresenter.presentDeleteProfilePictureSuccess(result);

    } catch (error) {
      this.logger.error('Failed to delete profile picture:', error);

      if (error.message?.includes('not found')) {
        throw new NotFoundException(
          this.profilePresenter.presentUserNotFound()
        );
      }

      if (error.message?.includes('unauthorized')) {
        throw new UnauthorizedException(
          this.profilePresenter.presentUnauthorized()
        );
      }

      throw new InternalServerErrorException(
        this.profilePresenter.presentInternalError()
      );
    }
  }

  // Private helper methods

  private extractUserIdFromRequest(req: Request): string {
    // The JWT guard should populate req.user with the decoded token payload
    const user = (req as any).user;
    
    if (!user || !user.sub) {
      throw new UnauthorizedException('Invalid token payload');
    }
    
    return user.sub;
  }

  private extractClientIP(req: Request): string {
    return (
      (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (req.headers['x-real-ip'] as string) ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      'unknown'
    );
  }
}