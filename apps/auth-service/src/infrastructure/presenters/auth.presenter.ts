import { Injectable } from '@nestjs/common';

// Use Case Response Models
import { RegisterUserResponse } from '../../domain/models/register-user.model';
import { LoginUserResponse } from '../../domain/models/login-user.model';
import { RefreshTokenResponse } from '../../domain/models/refresh-token.model';
import { SocialLoginResponse } from '../../domain/models/social-login.model';
import { LogoutUserResponse } from '../../domain/models/logout-user.model';

// DTOs
import {
  AuthResponseDto,
  RefreshTokenResponseDto,
  LogoutResponseDto,
} from '../controllers/dtos/auth.dto';
import { SocialLoginResponseDto } from '../controllers/dtos/social-auth.dto';

@Injectable()
export class AuthPresenter {
  /**
   * Present registration response
   */
  presentAuthResponse(response: RegisterUserResponse | LoginUserResponse): AuthResponseDto {
    return {
      id: response.user.getId(),
      email: response.user.getEmail(),
      name: response.user.getName(),
      profilePicture: response.user.getProfilePicture(),
      provider: response.user.getProvider().toString(),
      accessToken: response.accessToken.getValue(),
      refreshToken: response.refreshToken.getValue(),
      expiresAt: response.accessToken.getExpiresAt().toISOString(),
      sessionId: response.sessionId,
    };
  }

  /**
   * Present refresh token response
   */
  presentRefreshTokenResponse(response: RefreshTokenResponse): RefreshTokenResponseDto {
    return {
      accessToken: response.accessToken.getValue(),
      refreshToken: response.refreshToken.getValue(),
      expiresAt: response.accessToken.getExpiresAt().toISOString(),
      sessionId: response.sessionId,
    };
  }

  /**
   * Present social login response
   */
  presentSocialLoginResponse(response: SocialLoginResponse): SocialLoginResponseDto {
    return {
      id: response.user.getId(),
      email: response.user.getEmail(),
      name: response.user.getName(),
      profilePicture: response.user.getProfilePicture(),
      provider: response.user.getProvider().toString(),
      providerId: response.user.getProviderId() || '',
      accessToken: response.accessToken.getValue(),
      refreshToken: response.refreshToken.getValue(),
      expiresAt: response.accessToken.getExpiresAt().toISOString(),
      sessionId: response.sessionId,
      isNewUser: response.isNewUser,
    };
  }

  /**
   * Present logout response
   */
  presentLogoutResponse(response: LogoutUserResponse): LogoutResponseDto {
    return {
      message: response.message,
      timestamp: response.timestamp.toISOString(),
    };
  }

  /**
   * Present error response with consistent format
   */
  presentErrorResponse(
    error: Error,
    statusCode: number,
    path: string,
    timestamp: Date = new Date(),
  ) {
    // Map domain errors to appropriate error codes
    const errorCode = this.mapErrorToCode(error);
    
    return {
      statusCode,
      message: error.message,
      error: errorCode,
      timestamp: timestamp.toISOString(),
      path,
    };
  }

  /**
   * Present validation error response
   */
  presentValidationErrorResponse(
    validationErrors: Array<{ field: string; message: string; constraint?: string; value?: any }>,
    path: string,
    timestamp: Date = new Date(),
  ) {
    return {
      statusCode: 422,
      message: 'Validation failed',
      error: 'VALIDATION_ERROR',
      timestamp: timestamp.toISOString(),
      path,
      validationErrors: validationErrors.map(error => ({
        field: error.field,
        message: error.message,
        constraint: error.constraint,
        value: error.value,
      })),
    };
  }

  /**
   * Map domain errors to API error codes
   */
  private mapErrorToCode(error: Error): string {
    const errorName = error.constructor.name;
    
    // Map specific domain errors
    const errorCodeMap: Record<string, string> = {
      // User Registration Errors
      'UserAlreadyExistsError': 'USER_ALREADY_EXISTS',
      'InvalidEmailError': 'INVALID_EMAIL',
      'InvalidPasswordError': 'INVALID_PASSWORD',
      'InvalidNameError': 'INVALID_NAME',
      
      // Authentication Errors
      'InvalidCredentialsError': 'INVALID_CREDENTIALS',
      'UserNotFoundError': 'USER_NOT_FOUND',
      'UserNotActiveError': 'USER_NOT_ACTIVE',
      
      // Token Errors
      'InvalidRefreshTokenError': 'INVALID_REFRESH_TOKEN',
      'TokenExpiredError': 'TOKEN_EXPIRED',
      'InvalidTokenError': 'INVALID_TOKEN',
      
      // Social Login Errors
      'UnsupportedProviderError': 'UNSUPPORTED_PROVIDER',
      'OAuthAuthorizationError': 'OAUTH_AUTHORIZATION_ERROR',
      'OAuthUserInfoError': 'OAUTH_USER_INFO_ERROR',
      'GoogleOAuthError': 'GOOGLE_OAUTH_ERROR',
      'GoogleTokenExchangeError': 'GOOGLE_TOKEN_EXCHANGE_ERROR',
      'GoogleUserInfoError': 'GOOGLE_USER_INFO_ERROR',
      'AppleOAuthError': 'APPLE_OAUTH_ERROR',
      'AppleTokenVerificationError': 'APPLE_TOKEN_VERIFICATION_ERROR',
      'AppleUserInfoExtractionError': 'APPLE_USER_INFO_EXTRACTION_ERROR',
      
      // Profile Errors
      'NoChangesError': 'NO_CHANGES_DETECTED',
      'InvalidProfilePictureUrlError': 'INVALID_PROFILE_PICTURE_URL',
      
      // Session Errors
      'InvalidSessionError': 'INVALID_SESSION',
      'SessionExpiredError': 'SESSION_EXPIRED',
      
      // Generic Errors
      'ValidationError': 'VALIDATION_ERROR',
      'NotFoundError': 'NOT_FOUND',
      'UnauthorizedError': 'UNAUTHORIZED',
      'ForbiddenError': 'FORBIDDEN',
    };

    return errorCodeMap[errorName] || 'INTERNAL_SERVER_ERROR';
  }

  /**
   * Present success response with consistent format
   */
  presentSuccessResponse(message: string, data?: any, timestamp: Date = new Date()) {
    return {
      message,
      timestamp: timestamp.toISOString(),
      ...(data && { data }),
    };
  }

  /**
   * Present paginated response
   */
  presentPaginatedResponse<T>(
    items: T[],
    totalCount: number,
    page: number,
    limit: number,
    timestamp: Date = new Date(),
  ) {
    const totalPages = Math.ceil(totalCount / limit);
    const hasNextPage = page < totalPages;
    const hasPreviousPage = page > 1;

    return {
      items,
      pagination: {
        currentPage: page,
        totalPages,
        totalCount,
        limit,
        hasNextPage,
        hasPreviousPage,
      },
      timestamp: timestamp.toISOString(),
    };
  }

  /**
   * Present health check response
   */
  presentHealthCheckResponse(status: 'healthy' | 'unhealthy', checks: Record<string, any>) {
    return {
      status,
      timestamp: new Date().toISOString(),
      checks,
    };
  }

  /**
   * Present rate limit response
   */
  presentRateLimitResponse(
    limit: number,
    remaining: number,
    resetTime: Date,
    retryAfter?: number,
  ) {
    return {
      statusCode: 429,
      message: 'Too many requests',
      error: 'TOO_MANY_REQUESTS',
      timestamp: new Date().toISOString(),
      rateLimit: {
        limit,
        remaining,
        resetTime: resetTime.toISOString(),
        ...(retryAfter && { retryAfter }),
      },
    };
  }
}