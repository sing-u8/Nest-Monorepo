import { Injectable } from '@nestjs/common';
import { AuthPresenter as AuthPresenterPort } from '@auth/domain';
import {
  RegisterUserResponse,
  LoginUserResponse,
  SocialLoginResponse,
  RefreshTokenResponse,
  LogoutResponse,
  ValidateTokenResponse,
  ApiResponse,
  ErrorResponse,
} from '@auth/shared';

/**
 * Authentication Presenter Implementation
 * 
 * Implements the AuthPresenter port interface to format authentication
 * responses consistently across the application. This presenter follows
 * the Clean Architecture pattern by implementing the port defined in
 * the domain layer.
 * 
 * All responses follow a consistent format:
 * - success: boolean
 * - message: string
 * - data?: any (for successful operations)
 * - error?: string (for failed operations)
 * - details?: any (for additional error information)
 */
@Injectable()
export class AuthPresenter implements AuthPresenterPort {

  // Success Response Presenters

  presentRegistrationSuccess(response: any): RegisterUserResponse {
    return {
      success: true,
      message: 'User registered successfully',
      data: {
        user: {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
          profilePicture: response.user.profilePicture,
          provider: response.user.provider,
          emailVerified: response.user.emailVerified,
          createdAt: response.user.createdAt,
        },
        tokens: {
          accessToken: response.tokens.accessToken,
          refreshToken: response.tokens.refreshToken,
          expiresIn: response.tokens.expiresIn,
          tokenType: response.tokens.tokenType || 'Bearer',
        },
        session: {
          id: response.session.id,
          expiresAt: response.session.expiresAt,
        },
      },
    };
  }

  presentLoginSuccess(response: any): LoginUserResponse {
    return {
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
          profilePicture: response.user.profilePicture,
          provider: response.user.provider,
          lastLoginAt: response.user.lastLoginAt,
        },
        tokens: {
          accessToken: response.tokens.accessToken,
          refreshToken: response.tokens.refreshToken,
          expiresIn: response.tokens.expiresIn,
          tokenType: response.tokens.tokenType || 'Bearer',
        },
        session: {
          id: response.session.id,
          expiresAt: response.session.expiresAt,
          rememberMe: response.session.rememberMe || false,
        },
      },
    };
  }

  presentSocialLoginSuccess(response: any): SocialLoginResponse {
    return {
      success: true,
      message: `${response.provider} authentication successful`,
      data: {
        user: {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
          profilePicture: response.user.profilePicture,
          provider: response.user.provider,
          isNewUser: response.user.isNewUser || false,
        },
        tokens: {
          accessToken: response.tokens.accessToken,
          refreshToken: response.tokens.refreshToken,
          expiresIn: response.tokens.expiresIn,
          tokenType: response.tokens.tokenType || 'Bearer',
        },
        session: {
          id: response.session.id,
          expiresAt: response.session.expiresAt,
        },
      },
    };
  }

  presentTokenRefreshSuccess(response: any): RefreshTokenResponse {
    return {
      success: true,
      message: 'Tokens refreshed successfully',
      data: {
        tokens: {
          accessToken: response.tokens.accessToken,
          refreshToken: response.tokens.refreshToken,
          expiresIn: response.tokens.expiresIn,
          tokenType: response.tokens.tokenType || 'Bearer',
        },
        session: {
          id: response.session.id,
          expiresAt: response.session.expiresAt,
        },
      },
    };
  }

  presentLogoutSuccess(response: any): LogoutResponse {
    return {
      success: true,
      message: response.allSessions 
        ? 'Logged out from all devices successfully'
        : 'Logged out successfully',
      data: {
        tokensRevoked: response.tokensRevoked || 1,
        sessionsTerminated: response.sessionsTerminated || 1,
        allSessions: response.allSessions || false,
      },
    };
  }

  presentTokenValidation(response: any): ValidateTokenResponse {
    return {
      success: true,
      message: 'Token is valid',
      data: {
        valid: response.valid,
        user: response.user ? {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
        } : undefined,
        expiresAt: response.expiresAt,
        remainingTime: response.remainingTime,
      },
    };
  }

  // Error Response Presenters

  presentDuplicateEmail(email: string): ErrorResponse {
    return {
      success: false,
      error: 'DUPLICATE_EMAIL',
      message: 'An account with this email address already exists',
      details: {
        field: 'email',
        value: email,
        suggestion: 'Please use a different email address or try logging in',
      },
    };
  }

  presentRegistrationValidationError(errors: Record<string, string[]>): ErrorResponse {
    const formattedErrors = Object.entries(errors).map(([field, messages]) => ({
      field,
      messages,
    }));

    return {
      success: false,
      error: 'VALIDATION_ERROR',
      message: 'Registration data validation failed',
      details: {
        errors: formattedErrors,
        totalErrors: formattedErrors.length,
      },
    };
  }

  presentInvalidCredentials(): ErrorResponse {
    return {
      success: false,
      error: 'INVALID_CREDENTIALS',
      message: 'Invalid email or password',
      details: {
        suggestion: 'Please check your email and password and try again',
      },
    };
  }

  presentAccountLocked(reason: string): ErrorResponse {
    const reasonMessages = {
      'suspended': 'Your account has been suspended',
      'inactive': 'Your account is inactive',
      'deleted': 'Your account has been deleted',
      'locked': 'Your account has been temporarily locked',
    };

    return {
      success: false,
      error: 'ACCOUNT_LOCKED',
      message: reasonMessages[reason] || 'Your account is not accessible',
      details: {
        reason,
        suggestion: reason === 'locked' 
          ? 'Please contact support to unlock your account'
          : 'Please contact support for assistance',
      },
    };
  }

  presentSocialLoginFailure(provider: string, error: string): ErrorResponse {
    return {
      success: false,
      error: 'SOCIAL_LOGIN_ERROR',
      message: `${provider} authentication failed`,
      details: {
        provider,
        error,
        suggestion: `Please try again or use a different ${provider} account`,
      },
    };
  }

  presentTokenRefreshFailure(error: string): ErrorResponse {
    return {
      success: false,
      error: 'TOKEN_REFRESH_ERROR',
      message: 'Failed to refresh authentication tokens',
      details: {
        error,
        suggestion: 'Please log in again to continue',
      },
    };
  }

  presentLogoutFailure(error: string): ErrorResponse {
    return {
      success: false,
      error: 'LOGOUT_ERROR',
      message: 'Failed to log out completely',
      details: {
        error,
        suggestion: 'Some sessions may still be active. Please clear your browser cache.',
      },
    };
  }

  presentRateLimitExceeded(retryAfter: number): ErrorResponse {
    return {
      success: false,
      error: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests. Please try again later.',
      details: {
        retryAfter,
        retryAfterFormatted: this.formatRetryAfter(retryAfter),
        suggestion: 'Please wait before making another request',
      },
    };
  }

  presentAuthenticationError(error: string, code?: string): ErrorResponse {
    return {
      success: false,
      error: code || 'AUTHENTICATION_ERROR',
      message: 'Authentication failed',
      details: {
        error,
        suggestion: 'Please check your credentials and try again',
      },
    };
  }

  presentServerError(error: string): ErrorResponse {
    return {
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected error occurred',
      details: {
        suggestion: 'Please try again later. If the problem persists, contact support.',
      },
    };
  }

  // OAuth-specific presenters

  presentOAuthError(message: string): ErrorResponse {
    return {
      success: false,
      error: 'OAUTH_ERROR',
      message,
      details: {
        suggestion: 'Please try the authentication process again',
      },
    };
  }

  presentValidationError(message: string): ErrorResponse {
    return {
      success: false,
      error: 'VALIDATION_ERROR',
      message,
      details: {
        suggestion: 'Please check your input and try again',
      },
    };
  }

  presentUnauthorized(): ErrorResponse {
    return {
      success: false,
      error: 'UNAUTHORIZED',
      message: 'Invalid or expired authentication token',
      details: {
        suggestion: 'Please log in again to continue',
      },
    };
  }

  presentInternalError(): ErrorResponse {
    return {
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred',
      details: {
        suggestion: 'Please try again later',
      },
    };
  }

  // Helper Methods

  private formatRetryAfter(seconds: number): string {
    if (seconds < 60) {
      return `${seconds} seconds`;
    } else if (seconds < 3600) {
      const minutes = Math.ceil(seconds / 60);
      return `${minutes} minute${minutes > 1 ? 's' : ''}`;
    } else {
      const hours = Math.ceil(seconds / 3600);
      return `${hours} hour${hours > 1 ? 's' : ''}`;
    }
  }
}