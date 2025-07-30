import { IsString, MinLength, MaxLength, IsOptional, IsUrl } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateProfileRequestDto {
  @ApiPropertyOptional({
    description: 'User display name',
    example: 'John Doe',
    minLength: 1,
    maxLength: 100,
  })
  @IsOptional()
  @IsString({ message: 'Name must be a string' })
  @MinLength(1, { message: 'Name cannot be empty' })
  @MaxLength(100, { message: 'Name must not exceed 100 characters' })
  name?: string;

  @ApiPropertyOptional({
    description: 'User profile picture URL (must be HTTPS)',
    example: 'https://example.com/avatar.jpg',
    format: 'uri',
  })
  @IsOptional()
  @IsString({ message: 'Profile picture must be a string' })
  @IsUrl({ protocols: ['https'], require_protocol: true }, { 
    message: 'Profile picture must be a valid HTTPS URL' 
  })
  @MaxLength(500, { message: 'Profile picture URL must not exceed 500 characters' })
  profilePicture?: string;
}

export class ProfileResponseDto {
  @ApiProperty({
    description: 'User ID',
    example: 'user_123456789',
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
    example: 'https://example.com/avatar.jpg',
  })
  profilePicture?: string;

  @ApiProperty({
    description: 'Authentication provider',
    example: 'LOCAL',
    enum: ['LOCAL', 'GOOGLE', 'APPLE'],
  })
  provider: string;

  @ApiProperty({
    description: 'Account status',
    example: 'ACTIVE',
    enum: ['ACTIVE', 'INACTIVE'],
  })
  status: string;

  @ApiProperty({
    description: 'Account creation timestamp in ISO format',
    example: '2023-01-01T00:00:00.000Z',
  })
  createdAt: string;

  @ApiProperty({
    description: 'Last profile update timestamp in ISO format',
    example: '2023-12-31T23:59:59.000Z',
  })
  updatedAt: string;
}

export class UpdateProfileResponseDto {
  @ApiProperty({
    description: 'Updated user profile',
    type: ProfileResponseDto,
  })
  profile: ProfileResponseDto;

  @ApiProperty({
    description: 'Success message',
    example: 'Profile updated successfully',
  })
  message: string;

  @ApiProperty({
    description: 'Update timestamp in ISO format',
    example: '2023-12-31T23:59:59.000Z',
  })
  timestamp: string;
}