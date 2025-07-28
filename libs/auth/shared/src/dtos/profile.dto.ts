import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsUrl, IsEmail, Length, MaxLength } from 'class-validator';

// Request DTOs
export class GetUserProfileRequest {
  @ApiProperty({
    description: 'User ID to retrieve profile for',
    example: 'user-123',
  })
  @IsString()
  userId: string;
}

export class UpdateProfileRequest {
  @ApiPropertyOptional({
    description: 'User display name',
    example: 'John Smith',
    minLength: 2,
    maxLength: 100,
  })
  @IsOptional()
  @IsString()
  @Length(2, 100, { message: 'Name must be between 2 and 100 characters' })
  name?: string;

  @ApiPropertyOptional({
    description: 'User bio/description',
    example: 'Software developer with 5 years of experience',
    maxLength: 500,
  })
  @IsOptional()
  @IsString()
  @MaxLength(500, { message: 'Bio must not exceed 500 characters' })
  bio?: string;

  @ApiPropertyOptional({
    description: 'User location',
    example: 'San Francisco, CA',
    maxLength: 100,
  })
  @IsOptional()
  @IsString()
  @MaxLength(100, { message: 'Location must not exceed 100 characters' })
  location?: string;

  @ApiPropertyOptional({
    description: 'User website URL',
    example: 'https://johnsmith.dev',
  })
  @IsOptional()
  @IsUrl({}, { message: 'Website must be a valid URL' })
  website?: string;
}

export class UploadProfilePictureRequest {
  @ApiProperty({
    description: 'Profile picture file',
    type: 'string',
    format: 'binary',
  })
  file: Express.Multer.File;
}

// Internal request DTOs (for use cases)
export interface UpdateProfileUseCaseRequest extends UpdateProfileRequest {
  userId: string;
  profilePicture?: string | null;
  file?: {
    originalName: string;
    mimeType: string;
    size: number;
    buffer: Buffer;
  };
  clientInfo: {
    userAgent: string;
    ipAddress: string;
    deviceId?: string;
  };
}

// Response DTOs
export class UserProfileResponse {
  @ApiProperty({
    description: 'User unique identifier',
    example: 'user-123',
  })
  id: string;

  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  email: string;

  @ApiProperty({
    description: 'User display name',
    example: 'John Doe',
  })
  name: string;

  @ApiPropertyOptional({
    description: 'User profile picture URL',
    example: 'https://storage.example.com/profiles/user-123.jpg',
  })
  profilePicture?: string;

  @ApiPropertyOptional({
    description: 'User bio/description',
    example: 'Software developer with 5 years of experience',
  })
  bio?: string;

  @ApiPropertyOptional({
    description: 'User location',
    example: 'San Francisco, CA',
  })
  location?: string;

  @ApiPropertyOptional({
    description: 'User website URL',
    example: 'https://johnsmith.dev',
  })
  website?: string;

  @ApiProperty({
    description: 'Authentication provider',
    example: 'local',
    enum: ['local', 'google', 'apple'],
  })
  provider: string;

  @ApiProperty({
    description: 'Email verification status',
    example: true,
  })
  emailVerified: boolean;

  @ApiProperty({
    description: 'User account status',
    example: 'active',
    enum: ['active', 'inactive', 'suspended'],
  })
  status: string;

  @ApiProperty({
    description: 'Account creation timestamp',
    example: '2024-01-01T00:00:00.000Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: 'Last profile update timestamp',
    example: '2024-01-01T00:00:00.000Z',
  })
  updatedAt: Date;

  @ApiProperty({
    description: 'Last login timestamp',
    example: '2024-01-01T00:00:00.000Z',
  })
  lastLoginAt: Date;
}

export class SessionInfo {
  @ApiProperty({
    description: 'Session unique identifier',
    example: 'session-123',
  })
  id: string;

  @ApiProperty({
    description: 'Device and browser information',
    example: 'Chrome on Windows',
  })
  deviceInfo: string;

  @ApiProperty({
    description: 'IP address of the session',
    example: '192.168.1.1',
  })
  ipAddress: string;

  @ApiProperty({
    description: 'Last activity timestamp',
    example: '2024-01-01T00:00:00.000Z',
  })
  lastActivity: Date;

  @ApiProperty({
    description: 'Session creation timestamp',
    example: '2024-01-01T00:00:00.000Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: 'Whether this is the current session',
    example: true,
  })
  isCurrentSession: boolean;
}

export class AccountSummary {
  @ApiProperty({
    description: 'Total number of sessions created',
    example: 5,
  })
  totalSessions: number;

  @ApiProperty({
    description: 'Number of currently active sessions',
    example: 2,
  })
  activeSessions: number;

  @ApiProperty({
    description: 'Last password change timestamp',
    example: '2024-01-01T00:00:00.000Z',
  })
  lastPasswordChange: Date;

  @ApiProperty({
    description: 'Human-readable account age',
    example: '90 days',
  })
  accountAge: string;
}

export class ProfileChangeInfo {
  @ApiProperty({
    description: 'Field that was changed',
    example: 'name',
  })
  field: string;

  @ApiProperty({
    description: 'Previous value',
    example: 'John Doe',
  })
  oldValue: any;

  @ApiProperty({
    description: 'New value',
    example: 'John Smith',
  })
  newValue: any;
}

export class UploadInfo {
  @ApiProperty({
    description: 'Original file name',
    example: 'profile.jpg',
  })
  originalName: string;

  @ApiProperty({
    description: 'Stored file name',
    example: 'user-123-1640995200000.jpg',
  })
  fileName: string;

  @ApiProperty({
    description: 'File size in bytes',
    example: 245760,
  })
  size: number;

  @ApiProperty({
    description: 'File MIME type',
    example: 'image/jpeg',
  })
  mimeType: string;

  @ApiProperty({
    description: 'File access URL',
    example: 'https://storage.example.com/profiles/user-123.jpg',
  })
  url: string;
}

// Composite response types
export interface UserProfileWithSessions {
  user: UserProfileResponse;
  sessions: SessionInfo[];
  accountSummary: AccountSummary;
}

export interface UpdateProfileResult {
  user: UserProfileResponse;
  changes: ProfileChangeInfo[];
}

export interface UploadProfilePictureResult {
  user: UserProfileResponse;
  upload: UploadInfo;
}

// Use case result types
export type GetUserProfileResult = UserProfileWithSessions;

// API Response DTOs
export class GetProfileResponse {
  @ApiProperty({
    description: 'Operation success status',
    example: true,
  })
  success: boolean;

  @ApiProperty({
    description: 'Response message',
    example: 'Profile retrieved successfully',
  })
  message: string;

  @ApiProperty({
    description: 'Profile data with sessions and account summary',
    type: () => ({
      user: UserProfileResponse,
      sessions: [SessionInfo],
      accountSummary: AccountSummary,
    }),
  })
  data: UserProfileWithSessions;
}

export class UpdateProfileResponse {
  @ApiProperty({
    description: 'Operation success status',
    example: true,
  })
  success: boolean;

  @ApiProperty({
    description: 'Response message',
    example: 'Profile updated successfully',
  })
  message: string;

  @ApiProperty({
    description: 'Updated profile data with change information',
    type: () => ({
      user: UserProfileResponse,
      changes: [ProfileChangeInfo],
    }),
  })
  data: UpdateProfileResult;
}

export class UploadProfilePictureResponse {
  @ApiProperty({
    description: 'Operation success status',
    example: true,
  })
  success: boolean;

  @ApiProperty({
    description: 'Response message',
    example: 'Profile picture uploaded successfully',
  })
  message: string;

  @ApiProperty({
    description: 'Upload result with user data and file information',
    type: () => ({
      user: UserProfileResponse,
      upload: UploadInfo,
    }),
  })
  data: UploadProfilePictureResult;
}