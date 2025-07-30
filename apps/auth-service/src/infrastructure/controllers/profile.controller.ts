import {
  Controller,
  Get,
  Put,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UsePipes,
  ValidationPipe,
  Req,
  UseGuards,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
  ApiConsumes,
} from '@nestjs/swagger';
import { Request } from 'express';
import { FileInterceptor } from '@nestjs/platform-express';
import { Throttle } from '@nestjs/throttler';

// Use Cases
import { UpdateProfileUseCase } from '../../domain/use-cases/update-profile.use-case';
import { GetUserProfileUseCase } from '../../domain/use-cases/get-user-profile.use-case';

// DTOs
import {
  UpdateProfileRequestDto,
  ProfileResponseDto,
  UpdateProfileResponseDto,
} from './dtos/profile.dto';
import { ErrorResponseDto } from './dtos/common.dto';

// Presenters
import { ProfilePresenter } from '../presenters/profile.presenter';

// Guards (will be implemented later)
// import { JwtAuthGuard } from '../guards/jwt-auth.guard';

@ApiTags('User Profile')
@Controller('profile')
@UsePipes(new ValidationPipe({ 
  whitelist: true, 
  forbidNonWhitelisted: true,
  transform: true,
}))
// @UseGuards(JwtAuthGuard) // Will be implemented in step 8
@ApiBearerAuth()
export class ProfileController {
  constructor(
    private readonly updateProfileUseCase: UpdateProfileUseCase,
    private readonly getUserProfileUseCase: GetUserProfileUseCase,
    private readonly profilePresenter: ProfilePresenter,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get user profile',
    description: 'Retrieves the authenticated user\'s profile information',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User profile retrieved successfully',
    type: ProfileResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or missing access token',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User profile not found',
    type: ErrorResponseDto,
  })
  async getProfile(@Req() request: Request): Promise<ProfileResponseDto> {
    // Extract user ID from JWT payload (will be available after JwtAuthGuard is implemented)
    const userId = (request as any).user?.userId || 'temp_user_id';
    
    const getUserProfileRequest = {
      userId,
    };

    const response = await this.getUserProfileUseCase.execute(getUserProfileRequest);
    return this.profilePresenter.presentProfile(response);
  }

  @Put()
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 updates per minute
  @ApiOperation({
    summary: 'Update user profile',
    description: 'Updates the authenticated user\'s profile information',
  })
  @ApiBody({ type: UpdateProfileRequestDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Profile updated successfully',
    type: UpdateProfileResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input data',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or missing access token',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User profile not found',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: 'Validation errors',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Too many update attempts',
    type: ErrorResponseDto,
  })
  async updateProfile(
    @Body() updateProfileDto: UpdateProfileRequestDto,
    @Req() request: Request,
  ): Promise<UpdateProfileResponseDto> {
    // Extract user ID from JWT payload (will be available after JwtAuthGuard is implemented)
    const userId = (request as any).user?.userId || 'temp_user_id';
    
    const updateProfileRequest = {
      userId,
      name: updateProfileDto.name,
      profilePicture: updateProfileDto.profilePicture,
    };

    const response = await this.updateProfileUseCase.execute(updateProfileRequest);
    return this.profilePresenter.presentUpdateProfile(response);
  }

  @Post('picture')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(FileInterceptor('file', {
    limits: {
      fileSize: 5 * 1024 * 1024, // 5MB limit
    },
    fileFilter: (req, file, callback) => {
      // Only allow image files
      if (!file.mimetype.match(/^image\/(jpeg|png|gif|webp)$/)) {
        return callback(new BadRequestException('Only image files (JPEG, PNG, GIF, WebP) are allowed'), false);
      }
      callback(null, true);
    },
  }))
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 uploads per minute
  @ApiOperation({
    summary: 'Upload profile picture',
    description: 'Uploads and sets a new profile picture for the authenticated user',
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
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
    schema: {
      type: 'object',
      properties: {
        profilePicture: {
          type: 'string',
          description: 'URL of the uploaded profile picture',
          example: 'https://cdn.example.com/profiles/user_123/avatar.jpg',
        },
        message: {
          type: 'string',
          example: 'Profile picture updated successfully',
        },
        timestamp: {
          type: 'string',
          example: '2023-12-31T23:59:59.000Z',
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid file type or size',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or missing access token',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.PAYLOAD_TOO_LARGE,
    description: 'File size exceeds 5MB limit',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Too many upload attempts',
    type: ErrorResponseDto,
  })
  async uploadProfilePicture(
    @UploadedFile() file: Express.Multer.File,
    @Req() request: Request,
  ) {
    if (!file) {
      throw new BadRequestException('No file uploaded');
    }

    // Extract user ID from JWT payload (will be available after JwtAuthGuard is implemented)
    const userId = (request as any).user?.userId || 'temp_user_id';

    // In a real implementation, you would:
    // 1. Upload the file to a cloud storage service (AWS S3, Google Cloud Storage, etc.)
    // 2. Generate optimized versions (thumbnails, different sizes)
    // 3. Update the user's profile with the new picture URL
    // 4. Delete the old profile picture if it exists

    // For now, we'll simulate the upload process
    const simulatedUploadUrl = `https://cdn.example.com/profiles/${userId}/avatar_${Date.now()}.jpg`;

    // Update the user's profile picture
    const updateProfileRequest = {
      userId,
      profilePicture: simulatedUploadUrl,
    };

    const response = await this.updateProfileUseCase.execute(updateProfileRequest);
    
    return {
      profilePicture: simulatedUploadUrl,
      message: 'Profile picture updated successfully',
      timestamp: new Date().toISOString(),
      fileInfo: {
        originalName: file.originalname,
        mimeType: file.mimetype,
        size: file.size,
      },
    };
  }

  @Get('settings')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get user account settings',
    description: 'Retrieves user account settings and preferences',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User settings retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        userId: { type: 'string', example: 'user_123456789' },
        emailNotifications: { type: 'boolean', example: true },
        pushNotifications: { type: 'boolean', example: false },
        twoFactorEnabled: { type: 'boolean', example: false },
        language: { type: 'string', example: 'en' },
        timezone: { type: 'string', example: 'UTC' },
        privacy: {
          type: 'object',
          properties: {
            profileVisibility: { type: 'string', example: 'public' },
            showEmail: { type: 'boolean', example: false },
          },
        },
        createdAt: { type: 'string', example: '2023-01-01T00:00:00.000Z' },
        updatedAt: { type: 'string', example: '2023-12-31T23:59:59.000Z' },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or missing access token',
    type: ErrorResponseDto,
  })
  async getUserSettings(@Req() request: Request) {
    // Extract user ID from JWT payload (will be available after JwtAuthGuard is implemented)
    const userId = (request as any).user?.userId || 'temp_user_id';

    // This would typically fetch from a UserSettings entity/repository
    // For now, return mock settings
    return {
      userId,
      emailNotifications: true,
      pushNotifications: false,
      twoFactorEnabled: false,
      language: 'en',
      timezone: 'UTC',
      privacy: {
        profileVisibility: 'public',
        showEmail: false,
      },
      createdAt: '2023-01-01T00:00:00.000Z',
      updatedAt: new Date().toISOString(),
    };
  }

  @Put('settings')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 updates per minute
  @ApiOperation({
    summary: 'Update user account settings',
    description: 'Updates user account settings and preferences',
  })
  @ApiBody({
    description: 'User settings update data',
    schema: {
      type: 'object',
      properties: {
        emailNotifications: { type: 'boolean', example: true },
        pushNotifications: { type: 'boolean', example: false },
        language: { type: 'string', example: 'en' },
        timezone: { type: 'string', example: 'UTC' },
        privacy: {
          type: 'object',
          properties: {
            profileVisibility: { type: 'string', example: 'public' },
            showEmail: { type: 'boolean', example: false },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Settings updated successfully',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string', example: 'Settings updated successfully' },
        timestamp: { type: 'string', example: '2023-12-31T23:59:59.000Z' },
        updatedSettings: { 
          type: 'object',
          description: 'Updated settings object',
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid settings data',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or missing access token',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Too many update attempts',
    type: ErrorResponseDto,
  })
  async updateUserSettings(
    @Body() settingsData: any,
    @Req() request: Request,
  ) {
    // Extract user ID from JWT payload (will be available after JwtAuthGuard is implemented)
    const userId = (request as any).user?.userId || 'temp_user_id';

    // This would typically update a UserSettings entity/repository
    // For now, return success response
    return {
      message: 'Settings updated successfully',
      timestamp: new Date().toISOString(),
      updatedSettings: {
        userId,
        ...settingsData,
        updatedAt: new Date().toISOString(),
      },
    };
  }

  @Get('sessions')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get active user sessions',
    description: 'Retrieves list of active authentication sessions for the user',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Active sessions retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        sessions: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              sessionId: { type: 'string', example: 'session_123456789' },
              deviceId: { type: 'string', example: 'device_987654321' },
              userAgent: { type: 'string', example: 'Mozilla/5.0...' },
              ipAddress: { type: 'string', example: '192.168.1.1' },
              location: { type: 'string', example: 'New York, US' },
              current: { type: 'boolean', example: true },
              createdAt: { type: 'string', example: '2023-12-31T20:00:00.000Z' },
              lastActivity: { type: 'string', example: '2023-12-31T23:59:59.000Z' },
              expiresAt: { type: 'string', example: '2024-01-07T23:59:59.000Z' },
            },
          },
        },
        totalCount: { type: 'number', example: 3 },
        timestamp: { type: 'string', example: '2023-12-31T23:59:59.000Z' },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or missing access token',
    type: ErrorResponseDto,
  })
  async getActiveSessions(@Req() request: Request) {
    // Extract user ID and session ID from JWT payload
    const userId = (request as any).user?.userId || 'temp_user_id';
    const currentSessionId = (request as any).user?.sessionId || 'temp_session_id';

    // This would typically fetch from AuthSessionRepository
    // For now, return mock sessions
    const mockSessions = [
      {
        sessionId: currentSessionId,
        deviceId: 'device_current',
        userAgent: request.headers['user-agent'] || 'Unknown',
        ipAddress: this.getClientIpAddress(request),
        location: 'Current Location',
        current: true,
        createdAt: '2023-12-31T20:00:00.000Z',
        lastActivity: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      },
      {
        sessionId: 'session_mobile_456',
        deviceId: 'device_mobile_456',
        userAgent: 'MyApp/1.0 (iPhone; iOS 16.0)',
        ipAddress: '10.0.0.1',
        location: 'Mobile Device',
        current: false,
        createdAt: '2023-12-30T10:00:00.000Z',
        lastActivity: '2023-12-31T18:30:00.000Z',
        expiresAt: new Date(Date.now() + 6 * 24 * 60 * 60 * 1000).toISOString(),
      },
    ];

    return {
      sessions: mockSessions,
      totalCount: mockSessions.length,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Extract client IP address considering proxies
   * @param request Express request object
   * @returns Client IP address
   */
  private getClientIpAddress(request: Request): string {
    const forwarded = request.headers['x-forwarded-for'] as string;
    const realIp = request.headers['x-real-ip'] as string;
    
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
    
    if (realIp) {
      return realIp;
    }
    
    return request.connection.remoteAddress || 
           request.socket.remoteAddress || 
           'Unknown';
  }
}