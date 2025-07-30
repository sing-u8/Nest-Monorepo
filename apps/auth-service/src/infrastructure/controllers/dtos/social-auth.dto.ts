import { IsString, IsEnum, IsOptional, MinLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum OAuthProvider {
  GOOGLE = 'GOOGLE',
  APPLE = 'APPLE',
}

export class SocialLoginRequestDto {
  @ApiProperty({
    description: 'OAuth provider',
    example: 'GOOGLE',
    enum: OAuthProvider,
  })
  @IsEnum(OAuthProvider, { message: 'Provider must be either GOOGLE or APPLE' })
  provider: OAuthProvider;

  @ApiProperty({
    description: 'Authorization code from OAuth provider',
    example: '4/0AdQt8qh7rME5s1234...',
  })
  @IsString({ message: 'Authorization code must be a string' })
  @MinLength(1, { message: 'Authorization code is required' })
  code: string;

  @ApiPropertyOptional({
    description: 'State parameter for CSRF protection',
    example: 'random_state_value_123',
  })
  @IsOptional()
  @IsString({ message: 'State must be a string' })
  state?: string;

  @ApiPropertyOptional({
    description: 'ID token for Apple Sign In',
    example: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsOptional()
  @IsString({ message: 'ID token must be a string' })
  idToken?: string;

  @ApiPropertyOptional({
    description: 'User data from Apple Sign In form (first time only)',
    example: '{"name":{"firstName":"John","lastName":"Doe"}}',
  })
  @IsOptional()
  user?: any;
}

export class OAuthAuthorizationUrlResponseDto {
  @ApiProperty({
    description: 'OAuth authorization URL',
    example: 'https://accounts.google.com/o/oauth2/v2/auth?client_id=...',
  })
  authorizationUrl: string;

  @ApiProperty({
    description: 'OAuth provider',
    example: 'GOOGLE',
    enum: OAuthProvider,
  })
  provider: string;

  @ApiProperty({
    description: 'State parameter for CSRF protection',
    example: 'random_state_value_123',
  })
  state: string;

  @ApiPropertyOptional({
    description: 'Nonce parameter for Apple Sign In',
    example: 'random_nonce_value_456',
  })
  nonce?: string;
}

export class SocialLoginResponseDto {
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
    example: 'GOOGLE',
    enum: OAuthProvider,
  })
  provider: string;

  @ApiProperty({
    description: 'Provider user ID',
    example: 'google_123456789',
  })
  providerId: string;

  @ApiProperty({
    description: 'Access token for API authentication',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken: string;

  @ApiProperty({
    description: 'Refresh token for obtaining new access tokens',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  refreshToken: string;

  @ApiProperty({
    description: 'Access token expiration time in ISO format',
    example: '2023-12-31T23:59:59.000Z',
  })
  expiresAt: string;

  @ApiProperty({
    description: 'Authentication session ID',
    example: 'session_987654321',
  })
  sessionId: string;

  @ApiProperty({
    description: 'Whether this is a new user account',
    example: false,
  })
  isNewUser: boolean;
}