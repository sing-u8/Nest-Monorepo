import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, ConflictException, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { AuthController } from './auth.controller';
import {
  RegisterUserUseCase,
  LoginUserUseCase,
  RefreshTokenUseCase,
  LogoutUserUseCase,
  AuthPresenter,
} from '@auth/domain';
import { 
  RegisterUserRequest,
  LoginUserRequest,
  RefreshTokenRequest,
  LogoutUserRequest,
} from '@auth/shared';

describe('AuthController', () => {
  let controller: AuthController;
  let registerUserUseCase: jest.Mocked<RegisterUserUseCase>;
  let loginUserUseCase: jest.Mocked<LoginUserUseCase>;
  let refreshTokenUseCase: jest.Mocked<RefreshTokenUseCase>;
  let logoutUserUseCase: jest.Mocked<LogoutUserUseCase>;
  let authPresenter: jest.Mocked<AuthPresenter>;

  beforeEach(async () => {
    // Create mocked use cases
    registerUserUseCase = {
      execute: jest.fn(),
    } as any;

    loginUserUseCase = {
      execute: jest.fn(),
    } as any;

    refreshTokenUseCase = {
      execute: jest.fn(),
    } as any;

    logoutUserUseCase = {
      execute: jest.fn(),
    } as any;

    // Create mocked presenter
    authPresenter = {
      presentRegistrationSuccess: jest.fn(),
      presentLoginSuccess: jest.fn(),
      presentTokenRefreshSuccess: jest.fn(),
      presentLogoutSuccess: jest.fn(),
      presentUserAlreadyExists: jest.fn(),
      presentInvalidCredentials: jest.fn(),
      presentInvalidRefreshToken: jest.fn(),
      presentValidationError: jest.fn(),
      presentInternalError: jest.fn(),
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: 'RegisterUserUseCase',
          useValue: registerUserUseCase,
        },
        {
          provide: 'LoginUserUseCase',
          useValue: loginUserUseCase,
        },
        {
          provide: 'RefreshTokenUseCase',
          useValue: refreshTokenUseCase,
        },
        {
          provide: 'LogoutUserUseCase',
          useValue: logoutUserUseCase,
        },
        {
          provide: 'AuthPresenter',
          useValue: authPresenter,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);

    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('register', () => {
    const mockRegisterRequest: RegisterUserRequest = {
      email: 'test@example.com',
      password: 'SecurePassword123!',
      name: 'John Doe',
      clientInfo: {
        userAgent: 'Mozilla/5.0...',
        ipAddress: '192.168.1.1',
        deviceId: 'device-123',
      },
    };

    it('should register user successfully', async () => {
      const mockResponse = {
        success: true,
        message: 'User registered successfully',
        data: {
          user: {
            id: 'user-123',
            email: 'test@example.com',
            name: 'John Doe',
            status: 'active',
            createdAt: new Date(),
          },
          tokens: {
            accessToken: 'access-token',
            refreshToken: 'refresh-token',
            expiresIn: 900,
            tokenType: 'Bearer',
          },
          session: {
            id: 'session-123',
            expiresAt: new Date(),
          },
        },
      };

      registerUserUseCase.execute.mockResolvedValue(undefined);
      authPresenter.presentRegistrationSuccess.mockReturnValue(mockResponse);

      const result = await controller.register(mockRegisterRequest);

      expect(registerUserUseCase.execute).toHaveBeenCalledWith(mockRegisterRequest);
      expect(authPresenter.presentRegistrationSuccess).toHaveBeenCalled();
      expect(result).toEqual(mockResponse);
    });

    it('should throw ConflictException when user already exists', async () => {
      const error = new Error('User already exists');
      registerUserUseCase.execute.mockRejectedValue(error);
      authPresenter.presentUserAlreadyExists.mockReturnValue({
        success: false,
        error: 'USER_ALREADY_EXISTS',
        message: 'A user with this email already exists',
      });

      await expect(controller.register(mockRegisterRequest)).rejects.toThrow(ConflictException);
      expect(authPresenter.presentUserAlreadyExists).toHaveBeenCalled();
    });

    it('should throw BadRequestException for validation errors', async () => {
      const error = new Error('Validation failed: invalid email');
      registerUserUseCase.execute.mockRejectedValue(error);
      authPresenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Validation failed: invalid email',
      });

      await expect(controller.register(mockRegisterRequest)).rejects.toThrow(BadRequestException);
      expect(authPresenter.presentValidationError).toHaveBeenCalledWith('Validation failed: invalid email');
    });

    it('should throw InternalServerErrorException for unexpected errors', async () => {
      const error = new Error('Database connection failed');
      registerUserUseCase.execute.mockRejectedValue(error);
      authPresenter.presentInternalError.mockReturnValue({
        success: false,
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      });

      await expect(controller.register(mockRegisterRequest)).rejects.toThrow(InternalServerErrorException);
      expect(authPresenter.presentInternalError).toHaveBeenCalled();
    });
  });

  describe('login', () => {
    const mockLoginRequest: LoginUserRequest = {
      email: 'test@example.com',
      password: 'SecurePassword123!',
      rememberMe: true,
      clientInfo: {
        userAgent: 'Mozilla/5.0...',
        ipAddress: '192.168.1.1',
        deviceId: 'device-123',
      },
    };

    it('should login user successfully', async () => {
      const mockLoginResult = {
        user: {
          id: 'user-123',
          email: 'test@example.com',
          name: 'John Doe',
          status: 'active',
          lastLoginAt: new Date(),
        },
        tokens: {
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
          expiresIn: 900,
          tokenType: 'Bearer',
        },
        session: {
          id: 'session-123',
          expiresAt: new Date(),
          rememberMe: true,
        },
      };

      const mockResponse = {
        success: true,
        message: 'Login successful',
        data: mockLoginResult,
      };

      loginUserUseCase.execute.mockResolvedValue(mockLoginResult);
      authPresenter.presentLoginSuccess.mockReturnValue(mockResponse);

      const result = await controller.login(mockLoginRequest);

      expect(loginUserUseCase.execute).toHaveBeenCalledWith(mockLoginRequest);
      expect(authPresenter.presentLoginSuccess).toHaveBeenCalledWith(mockLoginResult);
      expect(result).toEqual(mockResponse);
    });

    it('should throw UnauthorizedException for invalid credentials', async () => {
      const error = new Error('Invalid credentials');
      loginUserUseCase.execute.mockRejectedValue(error);
      authPresenter.presentInvalidCredentials.mockReturnValue({
        success: false,
        error: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password',
      });

      await expect(controller.login(mockLoginRequest)).rejects.toThrow(UnauthorizedException);
      expect(authPresenter.presentInvalidCredentials).toHaveBeenCalled();
    });

    it('should throw UnauthorizedException for suspended account', async () => {
      const error = new Error('Account is suspended');
      loginUserUseCase.execute.mockRejectedValue(error);
      authPresenter.presentInvalidCredentials.mockReturnValue({
        success: false,
        error: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password',
      });

      await expect(controller.login(mockLoginRequest)).rejects.toThrow(UnauthorizedException);
      expect(authPresenter.presentInvalidCredentials).toHaveBeenCalled();
    });

    it('should throw BadRequestException for validation errors', async () => {
      const error = new Error('Validation failed: invalid email format');
      loginUserUseCase.execute.mockRejectedValue(error);
      authPresenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Validation failed: invalid email format',
      });

      await expect(controller.login(mockLoginRequest)).rejects.toThrow(BadRequestException);
      expect(authPresenter.presentValidationError).toHaveBeenCalledWith('Validation failed: invalid email format');
    });
  });

  describe('refreshToken', () => {
    const mockRefreshRequest: RefreshTokenRequest = {
      refreshToken: 'valid-refresh-token',
      clientInfo: {
        userAgent: 'Mozilla/5.0...',
        ipAddress: '192.168.1.1',
        deviceId: 'device-123',
      },
    };

    it('should refresh token successfully', async () => {
      const mockRefreshResult = {
        tokens: {
          accessToken: 'new-access-token',
          refreshToken: 'new-refresh-token',
          expiresIn: 900,
          tokenType: 'Bearer',
        },
        user: {
          id: 'user-123',
          email: 'test@example.com',
          name: 'John Doe',
        },
      };

      const mockResponse = {
        success: true,
        message: 'Token refreshed successfully',
        data: mockRefreshResult,
      };

      refreshTokenUseCase.execute.mockResolvedValue(mockRefreshResult);
      authPresenter.presentTokenRefreshSuccess.mockReturnValue(mockResponse);

      const result = await controller.refreshToken(mockRefreshRequest);

      expect(refreshTokenUseCase.execute).toHaveBeenCalledWith(mockRefreshRequest);
      expect(authPresenter.presentTokenRefreshSuccess).toHaveBeenCalledWith(mockRefreshResult);
      expect(result).toEqual(mockResponse);
    });

    it('should throw UnauthorizedException for invalid refresh token', async () => {
      const error = new Error('Invalid refresh token');
      refreshTokenUseCase.execute.mockRejectedValue(error);
      authPresenter.presentInvalidRefreshToken.mockReturnValue({
        success: false,
        error: 'INVALID_REFRESH_TOKEN',
        message: 'Refresh token is invalid or expired',
      });

      await expect(controller.refreshToken(mockRefreshRequest)).rejects.toThrow(UnauthorizedException);
      expect(authPresenter.presentInvalidRefreshToken).toHaveBeenCalled();
    });

    it('should throw UnauthorizedException for expired refresh token', async () => {
      const error = new Error('Refresh token has expired');
      refreshTokenUseCase.execute.mockRejectedValue(error);
      authPresenter.presentInvalidRefreshToken.mockReturnValue({
        success: false,
        error: 'INVALID_REFRESH_TOKEN',
        message: 'Refresh token is invalid or expired',
      });

      await expect(controller.refreshToken(mockRefreshRequest)).rejects.toThrow(UnauthorizedException);
      expect(authPresenter.presentInvalidRefreshToken).toHaveBeenCalled();
    });

    it('should throw BadRequestException for validation errors', async () => {
      const error = new Error('Validation failed: refresh token is required');
      refreshTokenUseCase.execute.mockRejectedValue(error);
      authPresenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Validation failed: refresh token is required',
      });

      await expect(controller.refreshToken(mockRefreshRequest)).rejects.toThrow(BadRequestException);
      expect(authPresenter.presentValidationError).toHaveBeenCalledWith('Validation failed: refresh token is required');
    });
  });

  describe('logout', () => {
    const mockLogoutRequest: LogoutUserRequest = {
      refreshToken: 'valid-refresh-token',
      logoutFromAllDevices: false,
      clientInfo: {
        userAgent: 'Mozilla/5.0...',
        ipAddress: '192.168.1.1',
        deviceId: 'device-123',
      },
    };

    it('should logout user successfully', async () => {
      const mockLogoutResult = {
        loggedOutAt: new Date(),
        sessionsClosed: 1,
        tokensRevoked: 2,
      };

      const mockResponse = {
        success: true,
        message: 'Logout successful',
        data: mockLogoutResult,
      };

      logoutUserUseCase.execute.mockResolvedValue(mockLogoutResult);
      authPresenter.presentLogoutSuccess.mockReturnValue(mockResponse);

      const result = await controller.logout(mockLogoutRequest);

      expect(logoutUserUseCase.execute).toHaveBeenCalledWith(mockLogoutRequest);
      expect(authPresenter.presentLogoutSuccess).toHaveBeenCalledWith(mockLogoutResult);
      expect(result).toEqual(mockResponse);
    });

    it('should logout from all devices successfully', async () => {
      const mockLogoutAllRequest = {
        ...mockLogoutRequest,
        logoutFromAllDevices: true,
      };

      const mockLogoutResult = {
        loggedOutAt: new Date(),
        sessionsClosed: 3,
        tokensRevoked: 6,
      };

      const mockResponse = {
        success: true,
        message: 'Logout successful',
        data: mockLogoutResult,
      };

      logoutUserUseCase.execute.mockResolvedValue(mockLogoutResult);
      authPresenter.presentLogoutSuccess.mockReturnValue(mockResponse);

      const result = await controller.logout(mockLogoutAllRequest);

      expect(logoutUserUseCase.execute).toHaveBeenCalledWith(mockLogoutAllRequest);
      expect(result).toEqual(mockResponse);
    });

    it('should throw UnauthorizedException for invalid refresh token', async () => {
      const error = new Error('Invalid refresh token');
      logoutUserUseCase.execute.mockRejectedValue(error);
      authPresenter.presentInvalidRefreshToken.mockReturnValue({
        success: false,
        error: 'INVALID_REFRESH_TOKEN',
        message: 'Refresh token is invalid or expired',
      });

      await expect(controller.logout(mockLogoutRequest)).rejects.toThrow(UnauthorizedException);
      expect(authPresenter.presentInvalidRefreshToken).toHaveBeenCalled();
    });

    it('should throw BadRequestException for validation errors', async () => {
      const error = new Error('Validation failed: refresh token is required');
      logoutUserUseCase.execute.mockRejectedValue(error);
      authPresenter.presentValidationError.mockReturnValue({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Validation failed: refresh token is required',
      });

      await expect(controller.logout(mockLogoutRequest)).rejects.toThrow(BadRequestException);
      expect(authPresenter.presentValidationError).toHaveBeenCalledWith('Validation failed: refresh token is required');
    });

    it('should handle logout gracefully on internal errors', async () => {
      const error = new Error('Database connection failed');
      logoutUserUseCase.execute.mockRejectedValue(error);
      
      const gracefulResponse = {
        success: true,
        message: 'Logout successful',
        data: {
          loggedOutAt: expect.any(Date),
          sessionsClosed: 0,
          tokensRevoked: 0,
        },
      };

      authPresenter.presentLogoutSuccess.mockReturnValue(gracefulResponse);

      const result = await controller.logout(mockLogoutRequest);

      expect(result).toEqual(gracefulResponse);
      expect(authPresenter.presentLogoutSuccess).toHaveBeenCalledWith({
        loggedOutAt: expect.any(Date),
        sessionsClosed: 0,
        tokensRevoked: 0,
      });
    });
  });

  describe('error handling', () => {
    it('should handle undefined error messages gracefully', async () => {
      const mockRequest: RegisterUserRequest = {
        email: 'test@example.com',
        password: 'password',
        name: 'Test User',
        clientInfo: {},
      };

      const error = new Error();
      error.message = undefined as any;
      
      registerUserUseCase.execute.mockRejectedValue(error);
      authPresenter.presentInternalError.mockReturnValue({
        success: false,
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      });

      await expect(controller.register(mockRequest)).rejects.toThrow(InternalServerErrorException);
      expect(authPresenter.presentInternalError).toHaveBeenCalled();
    });

    it('should handle null errors gracefully', async () => {
      const mockRequest: LoginUserRequest = {
        email: 'test@example.com',
        password: 'password',
        clientInfo: {},
      };

      loginUserUseCase.execute.mockRejectedValue(null);
      authPresenter.presentInternalError.mockReturnValue({
        success: false,
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      });

      await expect(controller.login(mockRequest)).rejects.toThrow(InternalServerErrorException);
      expect(authPresenter.presentInternalError).toHaveBeenCalled();
    });
  });
});