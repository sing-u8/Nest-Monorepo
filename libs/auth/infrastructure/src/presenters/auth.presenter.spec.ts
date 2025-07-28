import { Test, TestingModule } from '@nestjs/testing';
import { AuthPresenter } from './auth.presenter';
import {
  RegisterUserResponse,
  LoginUserResponse,
  SocialLoginResponse,
  RefreshTokenResponse,
  LogoutResponse,
  ValidateTokenResponse,
  ErrorResponse,
} from '@auth/shared';

describe('AuthPresenter', () => {
  let presenter: AuthPresenter;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AuthPresenter],
    }).compile();

    presenter = module.get<AuthPresenter>(AuthPresenter);
  });

  describe('Success Response Presenters', () => {
    describe('presentRegistrationSuccess', () => {
      it('should present registration success response', () => {
        const mockResponse = {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
            profilePicture: null,
            provider: 'local',
            emailVerified: false,
            createdAt: new Date('2024-01-01'),
          },
          tokens: {
            accessToken: 'access-token-123',
            refreshToken: 'refresh-token-123',
            expiresIn: 900,
            tokenType: 'Bearer',
          },
          session: {
            id: 'session-123',
            expiresAt: new Date('2024-01-02'),
          },
        };

        const result = presenter.presentRegistrationSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'User registered successfully',
          data: {
            user: {
              id: 'user-123',
              email: 'user@example.com',
              name: 'John Doe',
              profilePicture: null,
              provider: 'local',
              emailVerified: false,
              createdAt: new Date('2024-01-01'),
            },
            tokens: {
              accessToken: 'access-token-123',
              refreshToken: 'refresh-token-123',
              expiresIn: 900,
              tokenType: 'Bearer',
            },
            session: {
              id: 'session-123',
              expiresAt: new Date('2024-01-02'),
            },
          },
        });
      });

      it('should default tokenType to Bearer if not provided', () => {
        const mockResponse = {
          user: { id: 'user-123', email: 'user@example.com', name: 'John Doe', provider: 'local', emailVerified: false, createdAt: new Date() },
          tokens: { accessToken: 'token', refreshToken: 'refresh', expiresIn: 900 },
          session: { id: 'session-123', expiresAt: new Date() },
        };

        const result = presenter.presentRegistrationSuccess(mockResponse);

        expect(result.data.tokens.tokenType).toBe('Bearer');
      });
    });

    describe('presentLoginSuccess', () => {
      it('should present login success response', () => {
        const mockResponse = {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
            profilePicture: 'https://example.com/avatar.jpg',
            provider: 'local',
            lastLoginAt: new Date('2024-01-01'),
          },
          tokens: {
            accessToken: 'access-token-123',
            refreshToken: 'refresh-token-123',
            expiresIn: 900,
            tokenType: 'Bearer',
          },
          session: {
            id: 'session-123',
            expiresAt: new Date('2024-01-02'),
            rememberMe: true,
          },
        };

        const result = presenter.presentLoginSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'Login successful',
          data: {
            user: {
              id: 'user-123',
              email: 'user@example.com',
              name: 'John Doe',
              profilePicture: 'https://example.com/avatar.jpg',
              provider: 'local',
              lastLoginAt: new Date('2024-01-01'),
            },
            tokens: {
              accessToken: 'access-token-123',
              refreshToken: 'refresh-token-123',
              expiresIn: 900,
              tokenType: 'Bearer',
            },
            session: {
              id: 'session-123',
              expiresAt: new Date('2024-01-02'),
              rememberMe: true,
            },
          },
        });
      });

      it('should default rememberMe to false if not provided', () => {
        const mockResponse = {
          user: { id: 'user-123', email: 'user@example.com', name: 'John Doe', provider: 'local', lastLoginAt: new Date() },
          tokens: { accessToken: 'token', refreshToken: 'refresh', expiresIn: 900 },
          session: { id: 'session-123', expiresAt: new Date() },
        };

        const result = presenter.presentLoginSuccess(mockResponse);

        expect(result.data.session.rememberMe).toBe(false);
      });
    });

    describe('presentSocialLoginSuccess', () => {
      it('should present social login success response', () => {
        const mockResponse = {
          user: {
            id: 'user-123',
            email: 'user@gmail.com',
            name: 'John Doe',
            profilePicture: 'https://example.com/avatar.jpg',
            provider: 'google',
            isNewUser: true,
          },
          tokens: {
            accessToken: 'access-token-123',
            refreshToken: 'refresh-token-123',
            expiresIn: 900,
          },
          session: {
            id: 'session-123',
            expiresAt: new Date('2024-01-02'),
          },
          provider: 'google',
        };

        const result = presenter.presentSocialLoginSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'google authentication successful',
          data: {
            user: {
              id: 'user-123',
              email: 'user@gmail.com',
              name: 'John Doe',
              profilePicture: 'https://example.com/avatar.jpg',
              provider: 'google',
              isNewUser: true,
            },
            tokens: {
              accessToken: 'access-token-123',
              refreshToken: 'refresh-token-123',
              expiresIn: 900,
              tokenType: 'Bearer',
            },
            session: {
              id: 'session-123',
              expiresAt: new Date('2024-01-02'),
            },
          },
        });
      });

      it('should default isNewUser to false if not provided', () => {
        const mockResponse = {
          user: { id: 'user-123', email: 'user@gmail.com', name: 'John Doe', provider: 'google' },
          tokens: { accessToken: 'token', refreshToken: 'refresh', expiresIn: 900 },
          session: { id: 'session-123', expiresAt: new Date() },
          provider: 'google',
        };

        const result = presenter.presentSocialLoginSuccess(mockResponse);

        expect(result.data.user.isNewUser).toBe(false);
      });
    });

    describe('presentTokenRefreshSuccess', () => {
      it('should present token refresh success response', () => {
        const mockResponse = {
          tokens: {
            accessToken: 'new-access-token',
            refreshToken: 'new-refresh-token',
            expiresIn: 900,
          },
          session: {
            id: 'session-123',
            expiresAt: new Date('2024-01-02'),
          },
        };

        const result = presenter.presentTokenRefreshSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'Tokens refreshed successfully',
          data: {
            tokens: {
              accessToken: 'new-access-token',
              refreshToken: 'new-refresh-token',
              expiresIn: 900,
              tokenType: 'Bearer',
            },
            session: {
              id: 'session-123',
              expiresAt: new Date('2024-01-02'),
            },
          },
        });
      });
    });

    describe('presentLogoutSuccess', () => {
      it('should present single session logout success', () => {
        const mockResponse = {
          tokensRevoked: 2,
          sessionsTerminated: 1,
          allSessions: false,
        };

        const result = presenter.presentLogoutSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'Logged out successfully',
          data: {
            tokensRevoked: 2,
            sessionsTerminated: 1,
            allSessions: false,
          },
        });
      });

      it('should present all sessions logout success', () => {
        const mockResponse = {
          tokensRevoked: 5,
          sessionsTerminated: 3,
          allSessions: true,
        };

        const result = presenter.presentLogoutSuccess(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'Logged out from all devices successfully',
          data: {
            tokensRevoked: 5,
            sessionsTerminated: 3,
            allSessions: true,
          },
        });
      });

      it('should use default values if not provided', () => {
        const mockResponse = {};

        const result = presenter.presentLogoutSuccess(mockResponse);

        expect(result.data.tokensRevoked).toBe(1);
        expect(result.data.sessionsTerminated).toBe(1);
        expect(result.data.allSessions).toBe(false);
      });
    });

    describe('presentTokenValidation', () => {
      it('should present token validation response with user data', () => {
        const mockResponse = {
          valid: true,
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
          },
          expiresAt: new Date('2024-01-02'),
          remainingTime: 3600,
        };

        const result = presenter.presentTokenValidation(mockResponse);

        expect(result).toEqual({
          success: true,
          message: 'Token is valid',
          data: {
            valid: true,
            user: {
              id: 'user-123',
              email: 'user@example.com',
              name: 'John Doe',
            },
            expiresAt: new Date('2024-01-02'),
            remainingTime: 3600,
          },
        });
      });

      it('should handle token validation without user data', () => {
        const mockResponse = {
          valid: false,
          expiresAt: new Date('2024-01-01'),
          remainingTime: 0,
        };

        const result = presenter.presentTokenValidation(mockResponse);

        expect(result.data.user).toBeUndefined();
        expect(result.data.valid).toBe(false);
      });
    });
  });

  describe('Error Response Presenters', () => {
    describe('presentDuplicateEmail', () => {
      it('should present duplicate email error', () => {
        const result = presenter.presentDuplicateEmail('user@example.com');

        expect(result).toEqual({
          success: false,
          error: 'DUPLICATE_EMAIL',
          message: 'An account with this email address already exists',
          details: {
            field: 'email',
            value: 'user@example.com',
            suggestion: 'Please use a different email address or try logging in',
          },
        });
      });
    });

    describe('presentRegistrationValidationError', () => {
      it('should present registration validation errors', () => {
        const errors = {
          email: ['Invalid email format'],
          password: ['Password too weak', 'Password must contain uppercase letters'],
          name: ['Name is required'],
        };

        const result = presenter.presentRegistrationValidationError(errors);

        expect(result).toEqual({
          success: false,
          error: 'VALIDATION_ERROR',
          message: 'Registration data validation failed',
          details: {
            errors: [
              { field: 'email', messages: ['Invalid email format'] },
              { field: 'password', messages: ['Password too weak', 'Password must contain uppercase letters'] },
              { field: 'name', messages: ['Name is required'] },
            ],
            totalErrors: 3,
          },
        });
      });
    });

    describe('presentInvalidCredentials', () => {
      it('should present invalid credentials error', () => {
        const result = presenter.presentInvalidCredentials();

        expect(result).toEqual({
          success: false,
          error: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password',
          details: {
            suggestion: 'Please check your email and password and try again',
          },
        });
      });
    });

    describe('presentAccountLocked', () => {
      it('should present account suspended error', () => {
        const result = presenter.presentAccountLocked('suspended');

        expect(result).toEqual({
          success: false,
          error: 'ACCOUNT_LOCKED',
          message: 'Your account has been suspended',
          details: {
            reason: 'suspended',
            suggestion: 'Please contact support for assistance',
          },
        });
      });

      it('should present account locked error', () => {
        const result = presenter.presentAccountLocked('locked');

        expect(result).toEqual({
          success: false,
          error: 'ACCOUNT_LOCKED',
          message: 'Your account has been temporarily locked',
          details: {
            reason: 'locked',
            suggestion: 'Please contact support to unlock your account',
          },
        });
      });

      it('should handle unknown reason', () => {
        const result = presenter.presentAccountLocked('unknown');

        expect(result).toEqual({
          success: false,
          error: 'ACCOUNT_LOCKED',
          message: 'Your account is not accessible',
          details: {
            reason: 'unknown',
            suggestion: 'Please contact support for assistance',
          },
        });
      });
    });

    describe('presentSocialLoginFailure', () => {
      it('should present social login failure', () => {
        const result = presenter.presentSocialLoginFailure('google', 'Token validation failed');

        expect(result).toEqual({
          success: false,
          error: 'SOCIAL_LOGIN_ERROR',
          message: 'google authentication failed',
          details: {
            provider: 'google',
            error: 'Token validation failed',
            suggestion: 'Please try again or use a different google account',
          },
        });
      });
    });

    describe('presentRateLimitExceeded', () => {
      it('should present rate limit error with seconds', () => {
        const result = presenter.presentRateLimitExceeded(30);

        expect(result).toEqual({
          success: false,
          error: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          details: {
            retryAfter: 30,
            retryAfterFormatted: '30 seconds',
            suggestion: 'Please wait before making another request',
          },
        });
      });

      it('should present rate limit error with minutes', () => {
        const result = presenter.presentRateLimitExceeded(120);

        expect(result).toEqual({
          success: false,
          error: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          details: {
            retryAfter: 120,
            retryAfterFormatted: '2 minutes',
            suggestion: 'Please wait before making another request',
          },
        });
      });

      it('should present rate limit error with hours', () => {
        const result = presenter.presentRateLimitExceeded(7200);

        expect(result).toEqual({
          success: false,
          error: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          details: {
            retryAfter: 7200,
            retryAfterFormatted: '2 hours',
            suggestion: 'Please wait before making another request',
          },
        });
      });
    });

    describe('OAuth-specific presenters', () => {
      it('should present OAuth error', () => {
        const result = presenter.presentOAuthError('Invalid authorization code');

        expect(result).toEqual({
          success: false,
          error: 'OAUTH_ERROR',
          message: 'Invalid authorization code',
          details: {
            suggestion: 'Please try the authentication process again',
          },
        });
      });

      it('should present validation error', () => {
        const result = presenter.presentValidationError('Invalid request format');

        expect(result).toEqual({
          success: false,
          error: 'VALIDATION_ERROR',
          message: 'Invalid request format',
          details: {
            suggestion: 'Please check your input and try again',
          },
        });
      });

      it('should present unauthorized error', () => {
        const result = presenter.presentUnauthorized();

        expect(result).toEqual({
          success: false,
          error: 'UNAUTHORIZED',
          message: 'Invalid or expired authentication token',
          details: {
            suggestion: 'Please log in again to continue',
          },
        });
      });

      it('should present internal error', () => {
        const result = presenter.presentInternalError();

        expect(result).toEqual({
          success: false,
          error: 'INTERNAL_ERROR',
          message: 'An unexpected error occurred',
          details: {
            suggestion: 'Please try again later',
          },
        });
      });
    });
  });

  describe('Helper Methods', () => {
    describe('formatRetryAfter', () => {
      it('should format seconds correctly', () => {
        // Using private method through reflection for testing
        const formatRetryAfter = (presenter as any).formatRetryAfter.bind(presenter);
        
        expect(formatRetryAfter(1)).toBe('1 seconds');
        expect(formatRetryAfter(30)).toBe('30 seconds');
        expect(formatRetryAfter(59)).toBe('59 seconds');
      });

      it('should format minutes correctly', () => {
        const formatRetryAfter = (presenter as any).formatRetryAfter.bind(presenter);
        
        expect(formatRetryAfter(60)).toBe('1 minute');
        expect(formatRetryAfter(120)).toBe('2 minutes');
        expect(formatRetryAfter(3540)).toBe('59 minutes');
      });

      it('should format hours correctly', () => {
        const formatRetryAfter = (presenter as any).formatRetryAfter.bind(presenter);
        
        expect(formatRetryAfter(3600)).toBe('1 hour');
        expect(formatRetryAfter(7200)).toBe('2 hours');
        expect(formatRetryAfter(36000)).toBe('10 hours');
      });
    });
  });
});