import { AuthPresenter } from '../auth.presenter';

// Entities
import { User, UserStatus, AuthProvider } from '../../../domain/entities/user.entity';
import { Token, TokenType } from '../../../domain/entities/token.entity';

// Response Models
import { RegisterUserResponse } from '../../../domain/models/register-user.model';
import { LoginUserResponse } from '../../../domain/models/login-user.model';
import { RefreshTokenResponse } from '../../../domain/models/refresh-token.model';
import { SocialLoginResponse } from '../../../domain/models/social-login.model';
import { LogoutUserResponse } from '../../../domain/models/logout-user.model';

describe('AuthPresenter', () => {
  let presenter: AuthPresenter;

  const mockUser = User.create(
    'user_123',
    'test@example.com',
    'Test User',
    'hashedPassword',
    AuthProvider.LOCAL,
    UserStatus.ACTIVE,
  );

  const mockAccessToken = Token.create(
    'token_123',
    TokenType.ACCESS,
    'access_token_value',
    new Date('2023-12-31T23:59:59.000Z'),
    'user_123',
  );

  const mockRefreshToken = Token.create(
    'refresh_token_123',
    TokenType.REFRESH,
    'refresh_token_value',
    new Date('2024-01-07T23:59:59.000Z'),
    'user_123',
  );

  beforeEach(() => {
    presenter = new AuthPresenter();
  });

  describe('presentAuthResponse', () => {
    it('should present registration response correctly', () => {
      // Arrange
      const registerResponse: RegisterUserResponse = {
        user: mockUser,
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
        sessionId: 'session_123',
      };

      // Act
      const result = presenter.presentAuthResponse(registerResponse);

      // Assert
      expect(result).toEqual({
        id: 'user_123',
        email: 'test@example.com',
        name: 'Test User',
        profilePicture: undefined,
        provider: 'LOCAL',
        accessToken: 'access_token_value',
        refreshToken: 'refresh_token_value',
        expiresAt: '2023-12-31T23:59:59.000Z',
        sessionId: 'session_123',
      });
    });

    it('should present login response correctly', () => {
      // Arrange
      const userWithProfilePicture = User.create(
        'user_456',
        'user@example.com',
        'Another User',
        'hashedPassword',
        AuthProvider.GOOGLE,
        UserStatus.ACTIVE,
        'google_123',
        'https://example.com/avatar.jpg',
      );

      const loginResponse: LoginUserResponse = {
        user: userWithProfilePicture,
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
        sessionId: 'session_456',
      };

      // Act
      const result = presenter.presentAuthResponse(loginResponse);

      // Assert
      expect(result).toEqual({
        id: 'user_456',
        email: 'user@example.com',
        name: 'Another User',
        profilePicture: 'https://example.com/avatar.jpg',
        provider: 'GOOGLE',
        accessToken: 'access_token_value',
        refreshToken: 'refresh_token_value',
        expiresAt: '2023-12-31T23:59:59.000Z',
        sessionId: 'session_456',
      });
    });
  });

  describe('presentRefreshTokenResponse', () => {
    it('should present refresh token response correctly', () => {
      // Arrange
      const refreshResponse: RefreshTokenResponse = {
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
        sessionId: 'session_123',
      };

      // Act
      const result = presenter.presentRefreshTokenResponse(refreshResponse);

      // Assert
      expect(result).toEqual({
        accessToken: 'access_token_value',
        refreshToken: 'refresh_token_value',
        expiresAt: '2023-12-31T23:59:59.000Z',
        sessionId: 'session_123',
      });
    });
  });

  describe('presentSocialLoginResponse', () => {
    it('should present social login response for new user', () => {
      // Arrange
      const socialUser = User.create(
        'user_789',
        'social@example.com',
        'Social User',
        '',
        AuthProvider.GOOGLE,
        UserStatus.ACTIVE,
        'google_789',
        'https://example.com/social-avatar.jpg',
      );

      const socialLoginResponse: SocialLoginResponse = {
        user: socialUser,
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
        sessionId: 'session_789',
        isNewUser: true,
      };

      // Act
      const result = presenter.presentSocialLoginResponse(socialLoginResponse);

      // Assert
      expect(result).toEqual({
        id: 'user_789',
        email: 'social@example.com',
        name: 'Social User',
        profilePicture: 'https://example.com/social-avatar.jpg',
        provider: 'GOOGLE',
        providerId: 'google_789',
        accessToken: 'access_token_value',
        refreshToken: 'refresh_token_value',
        expiresAt: '2023-12-31T23:59:59.000Z',
        sessionId: 'session_789',
        isNewUser: true,
      });
    });

    it('should present social login response for existing user', () => {
      // Arrange
      const existingUser = User.create(
        'user_existing',
        'existing@example.com',
        'Existing User',
        'hashedPassword',
        AuthProvider.APPLE,
        UserStatus.ACTIVE,
        'apple_existing',
      );

      const socialLoginResponse: SocialLoginResponse = {
        user: existingUser,
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
        sessionId: 'session_existing',
        isNewUser: false,
      };

      // Act
      const result = presenter.presentSocialLoginResponse(socialLoginResponse);

      // Assert
      expect(result).toEqual({
        id: 'user_existing',
        email: 'existing@example.com',
        name: 'Existing User',
        profilePicture: undefined,
        provider: 'APPLE',
        providerId: 'apple_existing',
        accessToken: 'access_token_value',
        refreshToken: 'refresh_token_value',
        expiresAt: '2023-12-31T23:59:59.000Z',
        sessionId: 'session_existing',
        isNewUser: false,
      });
    });

    it('should handle user without provider ID', () => {
      // Arrange
      const userWithoutProviderId = User.create(
        'user_no_provider',
        'noprovider@example.com',
        'No Provider User',
        'hashedPassword',
        AuthProvider.LOCAL,
        UserStatus.ACTIVE,
      );

      const socialLoginResponse: SocialLoginResponse = {
        user: userWithoutProviderId,
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
        sessionId: 'session_no_provider',
        isNewUser: false,
      };

      // Act
      const result = presenter.presentSocialLoginResponse(socialLoginResponse);

      // Assert
      expect(result.providerId).toBe('');
    });
  });

  describe('presentLogoutResponse', () => {
    it('should present logout response correctly', () => {
      // Arrange
      const logoutResponse: LogoutUserResponse = {
        message: 'Successfully logged out',
        timestamp: new Date('2023-12-31T23:59:59.000Z'),
      };

      // Act
      const result = presenter.presentLogoutResponse(logoutResponse);

      // Assert
      expect(result).toEqual({
        message: 'Successfully logged out',
        timestamp: '2023-12-31T23:59:59.000Z',
      });
    });
  });

  describe('presentErrorResponse', () => {
    it('should present error response with mapped error code', () => {
      // Arrange
      const error = new Error('User already exists');
      error.name = 'UserAlreadyExistsError';
      Object.setPrototypeOf(error, Error.prototype);
      error.constructor = { name: 'UserAlreadyExistsError' } as any;

      const statusCode = 409;
      const path = '/auth/register';
      const timestamp = new Date('2023-12-31T23:59:59.000Z');

      // Act
      const result = presenter.presentErrorResponse(error, statusCode, path, timestamp);

      // Assert
      expect(result).toEqual({
        statusCode: 409,
        message: 'User already exists',
        error: 'USER_ALREADY_EXISTS',
        timestamp: '2023-12-31T23:59:59.000Z',
        path: '/auth/register',
      });
    });

    it('should use default error code for unknown errors', () => {
      // Arrange
      const error = new Error('Unknown error');
      const statusCode = 500;
      const path = '/auth/login';

      // Act
      const result = presenter.presentErrorResponse(error, statusCode, path);

      // Assert
      expect(result.error).toBe('INTERNAL_SERVER_ERROR');
    });

    it('should map various domain errors correctly', () => {
      // Test cases for different error types
      const testCases = [
        { errorName: 'InvalidCredentialsError', expectedCode: 'INVALID_CREDENTIALS' },
        { errorName: 'TokenExpiredError', expectedCode: 'TOKEN_EXPIRED' },
        { errorName: 'GoogleOAuthError', expectedCode: 'GOOGLE_OAUTH_ERROR' },
        { errorName: 'AppleTokenVerificationError', expectedCode: 'APPLE_TOKEN_VERIFICATION_ERROR' },
        { errorName: 'NoChangesError', expectedCode: 'NO_CHANGES_DETECTED' },
        { errorName: 'ValidationError', expectedCode: 'VALIDATION_ERROR' },
      ];

      testCases.forEach(({ errorName, expectedCode }) => {
        // Arrange
        const error = new Error('Test error');
        error.constructor = { name: errorName } as any;

        // Act
        const result = presenter.presentErrorResponse(error, 400, '/test');

        // Assert
        expect(result.error).toBe(expectedCode);
      });
    });
  });

  describe('presentValidationErrorResponse', () => {
    it('should present validation error response correctly', () => {
      // Arrange
      const validationErrors = [
        {
          field: 'email',
          message: 'Please provide a valid email address',
          constraint: 'isEmail',
          value: 'invalid-email',
        },
        {
          field: 'password',
          message: 'Password must be at least 8 characters long',
          constraint: 'minLength',
          value: 'short',
        },
      ];
      const path = '/auth/register';
      const timestamp = new Date('2023-12-31T23:59:59.000Z');

      // Act
      const result = presenter.presentValidationErrorResponse(validationErrors, path, timestamp);

      // Assert
      expect(result).toEqual({
        statusCode: 422,
        message: 'Validation failed',
        error: 'VALIDATION_ERROR',
        timestamp: '2023-12-31T23:59:59.000Z',
        path: '/auth/register',
        validationErrors: [
          {
            field: 'email',
            message: 'Please provide a valid email address',
            constraint: 'isEmail',
            value: 'invalid-email',
          },
          {
            field: 'password',
            message: 'Password must be at least 8 characters long',
            constraint: 'minLength',
            value: 'short',
          },
        ],
      });
    });

    it('should handle validation errors without constraint or value', () => {
      // Arrange
      const validationErrors = [
        {
          field: 'name',
          message: 'Name is required',
        },
      ];
      const path = '/auth/register';

      // Act
      const result = presenter.presentValidationErrorResponse(validationErrors, path);

      // Assert
      expect(result.validationErrors[0]).toEqual({
        field: 'name',
        message: 'Name is required',
        constraint: undefined,
        value: undefined,
      });
    });
  });

  describe('presentSuccessResponse', () => {
    it('should present success response without data', () => {
      // Arrange
      const message = 'Operation completed successfully';
      const timestamp = new Date('2023-12-31T23:59:59.000Z');

      // Act
      const result = presenter.presentSuccessResponse(message, undefined, timestamp);

      // Assert
      expect(result).toEqual({
        message: 'Operation completed successfully',
        timestamp: '2023-12-31T23:59:59.000Z',
      });
    });

    it('should present success response with data', () => {
      // Arrange
      const message = 'Data retrieved successfully';
      const data = { userId: 'user_123', count: 5 };
      const timestamp = new Date('2023-12-31T23:59:59.000Z');

      // Act
      const result = presenter.presentSuccessResponse(message, data, timestamp);

      // Assert
      expect(result).toEqual({
        message: 'Data retrieved successfully',
        timestamp: '2023-12-31T23:59:59.000Z',
        data: { userId: 'user_123', count: 5 },
      });
    });
  });

  describe('presentPaginatedResponse', () => {
    it('should present paginated response correctly', () => {
      // Arrange
      const items = ['item1', 'item2', 'item3'];
      const totalCount = 10;
      const page = 2;
      const limit = 3;
      const timestamp = new Date('2023-12-31T23:59:59.000Z');

      // Act
      const result = presenter.presentPaginatedResponse(items, totalCount, page, limit, timestamp);

      // Assert
      expect(result).toEqual({
        items: ['item1', 'item2', 'item3'],
        pagination: {
          currentPage: 2,
          totalPages: 4,
          totalCount: 10,
          limit: 3,
          hasNextPage: true,
          hasPreviousPage: true,
        },
        timestamp: '2023-12-31T23:59:59.000Z',
      });
    });

    it('should handle first page correctly', () => {
      // Arrange
      const items = ['item1', 'item2'];
      const totalCount = 5;
      const page = 1;
      const limit = 2;

      // Act
      const result = presenter.presentPaginatedResponse(items, totalCount, page, limit);

      // Assert
      expect(result.pagination).toEqual({
        currentPage: 1,
        totalPages: 3,
        totalCount: 5,
        limit: 2,
        hasNextPage: true,
        hasPreviousPage: false,
      });
    });

    it('should handle last page correctly', () => {
      // Arrange
      const items = ['item1'];
      const totalCount = 5;
      const page = 3;
      const limit = 2;

      // Act
      const result = presenter.presentPaginatedResponse(items, totalCount, page, limit);

      // Assert
      expect(result.pagination).toEqual({
        currentPage: 3,
        totalPages: 3,
        totalCount: 5,
        limit: 2,
        hasNextPage: false,
        hasPreviousPage: true,
      });
    });
  });

  describe('presentHealthCheckResponse', () => {
    it('should present healthy status correctly', () => {
      // Arrange
      const status = 'healthy' as const;
      const checks = {
        database: { status: 'up', responseTime: 50 },
        redis: { status: 'up', responseTime: 10 },
      };

      // Act
      const result = presenter.presentHealthCheckResponse(status, checks);

      // Assert
      expect(result).toEqual({
        status: 'healthy',
        timestamp: expect.any(String),
        checks: {
          database: { status: 'up', responseTime: 50 },
          redis: { status: 'up', responseTime: 10 },
        },
      });
    });

    it('should present unhealthy status correctly', () => {
      // Arrange
      const status = 'unhealthy' as const;
      const checks = {
        database: { status: 'down', error: 'Connection timeout' },
      };

      // Act
      const result = presenter.presentHealthCheckResponse(status, checks);

      // Assert
      expect(result.status).toBe('unhealthy');
      expect(result.checks).toEqual(checks);
    });
  });

  describe('presentRateLimitResponse', () => {
    it('should present rate limit response without retry after', () => {
      // Arrange
      const limit = 100;
      const remaining = 0;
      const resetTime = new Date('2023-12-31T23:59:59.000Z');

      // Act
      const result = presenter.presentRateLimitResponse(limit, remaining, resetTime);

      // Assert
      expect(result).toEqual({
        statusCode: 429,
        message: 'Too many requests',
        error: 'TOO_MANY_REQUESTS',
        timestamp: expect.any(String),
        rateLimit: {
          limit: 100,
          remaining: 0,
          resetTime: '2023-12-31T23:59:59.000Z',
        },
      });
    });

    it('should present rate limit response with retry after', () => {
      // Arrange
      const limit = 100;
      const remaining = 0;
      const resetTime = new Date('2023-12-31T23:59:59.000Z');
      const retryAfter = 3600;

      // Act
      const result = presenter.presentRateLimitResponse(limit, remaining, resetTime, retryAfter);

      // Assert
      expect(result.rateLimit).toEqual({
        limit: 100,
        remaining: 0,
        resetTime: '2023-12-31T23:59:59.000Z',
        retryAfter: 3600,
      });
    });
  });
});