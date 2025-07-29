import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  UsePipes,
  Inject,
  Logger,
  BadRequestException,
  UnauthorizedException,
  ConflictException,
  InternalServerErrorException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import {
  AuthRateLimit,
  RegisterRateLimit,
  RefreshRateLimit,
} from '../decorators/rate-limit.decorator';
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
  RegisterUserResponse,
  LoginUserResponse,
  RefreshTokenResponse,
  LogoutUserResponse,
} from '@auth/shared';

/**
 * Authentication Controller
 * 
 * Handles core authentication operations including user registration,
 * login, token refresh, and logout functionality.
 * 
 * All endpoints implement proper validation, error handling, and
 * consistent response formatting through presenters.
 */
@ApiTags('Authentication')
@Controller('auth')
@UsePipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
  validateCustomDecorators: true,
}))
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    @Inject('RegisterUserUseCase')
    private readonly registerUserUseCase: RegisterUserUseCase,
    
    @Inject('LoginUserUseCase')
    private readonly loginUserUseCase: LoginUserUseCase,
    
    @Inject('RefreshTokenUseCase')
    private readonly refreshTokenUseCase: RefreshTokenUseCase,
    
    @Inject('LogoutUserUseCase')
    private readonly logoutUserUseCase: LogoutUserUseCase,
    
    @Inject('AuthPresenter')
    private readonly authPresenter: AuthPresenter,
  ) {}

  /**
   * Register new user
   * POST /auth/register
   */
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @RegisterRateLimit()
  @ApiOperation({
    summary: 'Register new user',
    description: 'Creates a new user account with email and password authentication',
  })
  @ApiBody({
    type: RegisterUserRequest,
    description: 'User registration data',
    examples: {
      'registration-example': {
        summary: 'Standard registration',
        description: 'Example of user registration with required fields',
        value: {
          email: 'user@example.com',
          password: 'SecurePassword123!',
          name: 'John Doe',
          clientInfo: {
            userAgent: 'Mozilla/5.0...',
            ipAddress: '192.168.1.1',
            deviceId: 'device-123',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'User registered successfully',
    type: RegisterUserResponse,
    schema: {
      example: {
        success: true,
        message: 'User registered successfully',
        data: {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
            status: 'active',
            createdAt: '2024-01-01T00:00:00.000Z',
          },
          tokens: {
            accessToken: 'eyJhbGciOiJSUzI1NiIs...',
            refreshToken: 'eyJhbGciOiJSUzI1NiIs...',
            expiresIn: 900,
            tokenType: 'Bearer',
          },
          session: {
            id: 'session-123',
            expiresAt: '2024-01-08T00:00:00.000Z',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid request data',
    schema: {
      example: {
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Invalid input data',
        details: [
          {
            field: 'email',
            message: 'Invalid email format',
          },
          {
            field: 'password',
            message: 'Password must be at least 8 characters long',
          },
        ],
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'User already exists',
    schema: {
      example: {
        success: false,
        error: 'USER_ALREADY_EXISTS',
        message: 'A user with this email already exists',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
    schema: {
      example: {
        success: false,
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      },
    },
  })
  async register(@Body() request: RegisterUserRequest): Promise<RegisterUserResponse> {
    try {
      this.logger.log(`Registration attempt for email: ${request.email}`);

      await this.registerUserUseCase.execute(request);

      this.logger.log(`User registered successfully: ${request.email}`);
      return this.authPresenter.presentRegistrationSuccess();

    } catch (error) {
      this.logger.error(`Registration failed for ${request.email}:`, error);

      if (error.message?.includes('already exists')) {
        throw new ConflictException(
          this.authPresenter.presentUserAlreadyExists()
        );
      }

      if (error.message?.includes('validation') || error.message?.includes('invalid')) {
        throw new BadRequestException(
          this.authPresenter.presentValidationError(error.message)
        );
      }

      throw new InternalServerErrorException(
        this.authPresenter.presentInternalError()
      );
    }
  }

  /**
   * User login
   * POST /auth/login
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @AuthRateLimit()
  @ApiOperation({
    summary: 'User login',
    description: 'Authenticates user with email and password, returns access and refresh tokens',
  })
  @ApiBody({
    type: LoginUserRequest,
    description: 'User login credentials',
    examples: {
      'login-example': {
        summary: 'Standard login',
        description: 'Example of user login with email and password',
        value: {
          email: 'user@example.com',
          password: 'SecurePassword123!',
          rememberMe: true,
          clientInfo: {
            userAgent: 'Mozilla/5.0...',
            ipAddress: '192.168.1.1',
            deviceId: 'device-123',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Login successful',
    type: LoginUserResponse,
    schema: {
      example: {
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
            status: 'active',
            lastLoginAt: '2024-01-01T00:00:00.000Z',
          },
          tokens: {
            accessToken: 'eyJhbGciOiJSUzI1NiIs...',
            refreshToken: 'eyJhbGciOiJSUzI1NiIs...',
            expiresIn: 900,
            tokenType: 'Bearer',
          },
          session: {
            id: 'session-123',
            expiresAt: '2024-01-08T00:00:00.000Z',
            rememberMe: true,
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid request data',
    schema: {
      example: {
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Invalid input data',
        details: [
          {
            field: 'email',
            message: 'Email is required',
          },
          {
            field: 'password',
            message: 'Password is required',
          },
        ],
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid credentials or account issues',
    schema: {
      example: {
        success: false,
        error: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
  })
  async login(@Body() request: LoginUserRequest): Promise<LoginUserResponse> {
    try {
      this.logger.log(`Login attempt for email: ${request.email}`);

      const result = await this.loginUserUseCase.execute(request);

      this.logger.log(`User logged in successfully: ${request.email}`);
      return this.authPresenter.presentLoginSuccess(result);

    } catch (error) {
      this.logger.error(`Login failed for ${request.email}:`, error);

      if (error.message?.includes('invalid credentials') || 
          error.message?.includes('password') ||
          error.message?.includes('not found') ||
          error.message?.includes('suspended') ||
          error.message?.includes('inactive')) {
        throw new UnauthorizedException(
          this.authPresenter.presentInvalidCredentials()
        );
      }

      if (error.message?.includes('validation') || error.message?.includes('invalid')) {
        throw new BadRequestException(
          this.authPresenter.presentValidationError(error.message)
        );
      }

      throw new InternalServerErrorException(
        this.authPresenter.presentInternalError()
      );
    }
  }

  /**
   * Refresh access token
   * POST /auth/refresh
   */
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @RefreshRateLimit()
  @ApiOperation({
    summary: 'Refresh access token',
    description: 'Exchanges a valid refresh token for a new access token',
  })
  @ApiBody({
    type: RefreshTokenRequest,
    description: 'Refresh token data',
    examples: {
      'refresh-example': {
        summary: 'Token refresh',
        description: 'Example of refreshing access token using refresh token',
        value: {
          refreshToken: 'eyJhbGciOiJSUzI1NiIs...',
          clientInfo: {
            userAgent: 'Mozilla/5.0...',
            ipAddress: '192.168.1.1',
            deviceId: 'device-123',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Token refreshed successfully',
    type: RefreshTokenResponse,
    schema: {
      example: {
        success: true,
        message: 'Token refreshed successfully',
        data: {
          tokens: {
            accessToken: 'eyJhbGciOiJSUzI1NiIs...',
            refreshToken: 'eyJhbGciOiJSUzI1NiIs...',
            expiresIn: 900,
            tokenType: 'Bearer',
          },
          user: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'John Doe',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid request data',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired refresh token',
    schema: {
      example: {
        success: false,
        error: 'INVALID_REFRESH_TOKEN',
        message: 'Refresh token is invalid or expired',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
  })
  async refreshToken(@Body() request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    try {
      this.logger.log('Token refresh attempt');

      const result = await this.refreshTokenUseCase.execute(request);

      this.logger.log('Token refreshed successfully');
      return this.authPresenter.presentTokenRefreshSuccess(result);

    } catch (error) {
      this.logger.error('Token refresh failed:', error);

      if (error.message?.includes('invalid') || 
          error.message?.includes('expired') ||
          error.message?.includes('revoked') ||
          error.message?.includes('not found')) {
        throw new UnauthorizedException(
          this.authPresenter.presentInvalidRefreshToken()
        );
      }

      if (error.message?.includes('validation')) {
        throw new BadRequestException(
          this.authPresenter.presentValidationError(error.message)
        );
      }

      throw new InternalServerErrorException(
        this.authPresenter.presentInternalError()
      );
    }
  }

  /**
   * User logout
   * POST /auth/logout
   */
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @AuthRateLimit()
  @ApiOperation({
    summary: 'User logout',
    description: 'Invalidates user session and revokes tokens',
  })
  @ApiBody({
    type: LogoutUserRequest,
    description: 'Logout request data',
    examples: {
      'logout-example': {
        summary: 'Standard logout',
        description: 'Example of user logout with token revocation',
        value: {
          refreshToken: 'eyJhbGciOiJSUzI1NiIs...',
          logoutFromAllDevices: false,
          clientInfo: {
            userAgent: 'Mozilla/5.0...',
            ipAddress: '192.168.1.1',
            deviceId: 'device-123',
          },
        },
      },
      'logout-all-devices': {
        summary: 'Logout from all devices',
        description: 'Example of logging out from all devices',
        value: {
          refreshToken: 'eyJhbGciOiJSUzI1NiIs...',
          logoutFromAllDevices: true,
          clientInfo: {
            userAgent: 'Mozilla/5.0...',
            ipAddress: '192.168.1.1',
            deviceId: 'device-123',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Logout successful',
    type: LogoutUserResponse,
    schema: {
      example: {
        success: true,
        message: 'Logout successful',
        data: {
          loggedOutAt: '2024-01-01T00:00:00.000Z',
          sessionsClosed: 1,
          tokensRevoked: 2,
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid request data',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid refresh token',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
  })
  async logout(@Body() request: LogoutUserRequest): Promise<LogoutUserResponse> {
    try {
      this.logger.log('Logout attempt');

      const result = await this.logoutUserUseCase.execute(request);

      this.logger.log('User logged out successfully');
      return this.authPresenter.presentLogoutSuccess(result);

    } catch (error) {
      this.logger.error('Logout failed:', error);

      if (error.message?.includes('invalid') || 
          error.message?.includes('expired') ||
          error.message?.includes('not found')) {
        throw new UnauthorizedException(
          this.authPresenter.presentInvalidRefreshToken()
        );
      }

      if (error.message?.includes('validation')) {
        throw new BadRequestException(
          this.authPresenter.presentValidationError(error.message)
        );
      }

      // For logout, we might want to succeed even if there are some errors
      // to ensure the client clears its tokens
      this.logger.warn('Logout completed with warnings:', error);
      return this.authPresenter.presentLogoutSuccess({
        loggedOutAt: new Date(),
        sessionsClosed: 0,
        tokensRevoked: 0,
      });
    }
  }
}