import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ErrorResponseDto {
  @ApiProperty({
    description: 'HTTP status code',
    example: 400,
  })
  statusCode: number;

  @ApiProperty({
    description: 'Error message',
    example: 'Invalid email address',
  })
  message: string;

  @ApiProperty({
    description: 'Error code for client handling',
    example: 'INVALID_EMAIL',
  })
  error: string;

  @ApiProperty({
    description: 'Request timestamp in ISO format',
    example: '2023-12-31T23:59:59.000Z',
  })
  timestamp: string;

  @ApiProperty({
    description: 'Request path',
    example: '/auth/register',
  })
  path: string;

  @ApiPropertyOptional({
    description: 'Validation errors (for 422 responses)',
    example: [
      {
        field: 'email',
        message: 'Please provide a valid email address',
      },
      {
        field: 'password',
        message: 'Password must be at least 8 characters long',
      },
    ],
  })
  validationErrors?: Array<{
    field: string;
    message: string;
  }>;

  @ApiPropertyOptional({
    description: 'Additional error details for debugging',
    example: { correlationId: 'req_123456789' },
  })
  details?: Record<string, any>;
}

export class SuccessResponseDto {
  @ApiProperty({
    description: 'Success message',
    example: 'Operation completed successfully',
  })
  message: string;

  @ApiProperty({
    description: 'Response timestamp in ISO format',
    example: '2023-12-31T23:59:59.000Z',
  })
  timestamp: string;

  @ApiPropertyOptional({
    description: 'Additional response data',
  })
  data?: any;
}

export class ValidationErrorDto {
  @ApiProperty({
    description: 'Field name that failed validation',
    example: 'email',
  })
  field: string;

  @ApiProperty({
    description: 'Validation error message',
    example: 'Please provide a valid email address',
  })
  message: string;

  @ApiPropertyOptional({
    description: 'Validation constraint that was violated',
    example: 'isEmail',
  })
  constraint?: string;

  @ApiPropertyOptional({
    description: 'Invalid value that was provided',
    example: 'invalid-email',
  })
  value?: any;
}