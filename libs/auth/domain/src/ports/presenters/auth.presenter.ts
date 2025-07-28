import {
  RegisterUserResponse,
  LoginUserResponse,
  SocialLoginResponse,
  RefreshTokenResponse,
  LogoutResponse,
  ValidateTokenResponse,
} from '@auth/shared';

/**
 * Authentication Presenter Port Interface
 * 
 * This interface defines how authentication results should be presented.
 * Infrastructure layer must implement this interface for different output formats.
 */
export interface AuthPresenter {
  /**
   * Present successful user registration
   * @param response - Registration response data
   */
  presentRegistrationSuccess(response: RegisterUserResponse): void;

  /**
   * Present registration failure due to duplicate email
   * @param email - Email that already exists
   */
  presentDuplicateEmail(email: string): void;

  /**
   * Present registration failure due to invalid input
   * @param errors - Validation errors
   */
  presentRegistrationValidationError(errors: Record<string, string[]>): void;

  /**
   * Present successful user login
   * @param response - Login response data
   */
  presentLoginSuccess(response: LoginUserResponse): void;

  /**
   * Present login failure due to invalid credentials
   */
  presentInvalidCredentials(): void;

  /**
   * Present login failure due to account being locked/disabled
   * @param reason - Reason for account being inaccessible
   */
  presentAccountLocked(reason: string): void;

  /**
   * Present successful social login
   * @param response - Social login response data
   */
  presentSocialLoginSuccess(response: SocialLoginResponse): void;

  /**
   * Present social login failure
   * @param provider - OAuth provider that failed
   * @param error - Error message
   */
  presentSocialLoginFailure(provider: string, error: string): void;

  /**
   * Present successful token refresh
   * @param response - Token refresh response data
   */
  presentTokenRefreshSuccess(response: RefreshTokenResponse): void;

  /**
   * Present token refresh failure
   * @param error - Error message
   */
  presentTokenRefreshFailure(error: string): void;

  /**
   * Present successful logout
   * @param response - Logout response data
   */
  presentLogoutSuccess(response: LogoutResponse): void;

  /**
   * Present logout failure
   * @param error - Error message
   */
  presentLogoutFailure(error: string): void;

  /**
   * Present token validation result
   * @param response - Token validation response data
   */
  presentTokenValidation(response: ValidateTokenResponse): void;

  /**
   * Present rate limiting error
   * @param retryAfter - Seconds until next attempt allowed
   */
  presentRateLimitExceeded(retryAfter: number): void;

  /**
   * Present general authentication error
   * @param error - Error message
   * @param code - Error code
   */
  presentAuthenticationError(error: string, code?: string): void;

  /**
   * Present server error
   * @param error - Error message
   */
  presentServerError(error: string): void;
}