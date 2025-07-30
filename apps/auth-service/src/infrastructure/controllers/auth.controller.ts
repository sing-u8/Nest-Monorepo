import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UsePipes,
  ValidationPipe,
  Req,
  UseGuards,
  Get,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { Request } from 'express';
import { Throttle } from '@nestjs/throttler';

// Use Cases
import { RegisterUserUseCase } from '../../domain/use-cases/register-user.use-case';
import { LoginUserUseCase } from '../../domain/use-cases/login-user.use-case';
import { RefreshTokenUseCase } from '../../domain/use-cases/refresh-token.use-case';
import { LogoutUserUseCase } from '../../domain/use-cases/logout-user.use-case';

// DTOs
import {
  RegisterRequestDto,
  LoginRequestDto,
  RefreshTokenRequestDto,
  AuthResponseDto,
  RefreshTokenResponseDto,
  LogoutResponseDto,
} from './dtos/auth.dto';
import { ErrorResponseDto } from './dtos/common.dto';

// Presenters
import { AuthPresenter } from '../presenters/auth.presenter';

// Guards (will be implemented later)
// import { JwtAuthGuard } from '../guards/jwt-auth.guard';

@ApiTags('Authentication')
@Controller('auth')
@UsePipes(new ValidationPipe({ 
  whitelist: true, 
  forbidNonWhitelisted: true,
  transform: true,
}))
export class AuthController {
  constructor(
    private readonly registerUserUseCase: RegisterUserUseCase,
    private readonly loginUserUseCase: LoginUserUseCase,
    private readonly refreshTokenUseCase: RefreshTokenUseCase,
    private readonly logoutUserUseCase: LogoutUserUseCase,
    private readonly authPresenter: AuthPresenter,
  ) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @ApiOperation({
    summary: 'Register a new user account',
    description: 'Creates a new user account with email and password authentication',
  })
  @ApiBody({ type: RegisterRequestDto })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'User registered successfully',
    type: AuthResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input data',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'User already exists',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: 'Validation errors',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Too many registration attempts',
    type: ErrorResponseDto,
  })
  async register(
    @Body() registerDto: RegisterRequestDto,
    @Req() request: Request,
  ): Promise<AuthResponseDto> {
    const clientInfo = this.extractClientInfo(request);
    
    const registerRequest = {
      email: registerDto.email,
      password: registerDto.password,
      name: registerDto.name,
      profilePicture: registerDto.profilePicture,
      clientInfo,
    };

    const response = await this.registerUserUseCase.execute(registerRequest);
    return this.authPresenter.presentAuthResponse(response);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 requests per minute
  @ApiOperation({
    summary: 'Authenticate user with email and password',
    description: 'Authenticates user credentials and returns access/refresh tokens',
  })
  @ApiBody({ type: LoginRequestDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User authenticated successfully',
    type: AuthResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input data',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid credentials',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Account is inactive',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: 'Validation errors',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Too many login attempts',
    type: ErrorResponseDto,
  })
  async login(
    @Body() loginDto: LoginRequestDto,
    @Req() request: Request,
  ): Promise<AuthResponseDto> {
    const clientInfo = this.extractClientInfo(request);
    
    const loginRequest = {
      email: loginDto.email,
      password: loginDto.password,
      clientInfo,
    };

    const response = await this.loginUserUseCase.execute(loginRequest);
    return this.authPresenter.presentAuthResponse(response);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 20, ttl: 60000 } }) // 20 requests per minute
  @ApiOperation({
    summary: 'Refresh access token',
    description: 'Exchanges refresh token for new access/refresh token pair',
  })
  @ApiBody({ type: RefreshTokenRequestDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Tokens refreshed successfully',
    type: RefreshTokenResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input data',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired refresh token',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'User account is inactive',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: 'Validation errors',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Too many refresh attempts',
    type: ErrorResponseDto,
  })
  async refreshToken(
    @Body() refreshDto: RefreshTokenRequestDto,
    @Req() request: Request,
  ): Promise<RefreshTokenResponseDto> {
    const clientInfo = this.extractClientInfo(request);
    
    const refreshRequest = {
      refreshToken: refreshDto.refreshToken,
      clientInfo,
    };

    const response = await this.refreshTokenUseCase.execute(refreshRequest);
    return this.authPresenter.presentRefreshTokenResponse(response);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  // @UseGuards(JwtAuthGuard) // Will be implemented in step 8
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Logout user and revoke session',
    description: 'Invalidates the current session and revokes all tokens',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User logged out successfully',
    type: LogoutResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or missing access token',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Logout failed',
    type: ErrorResponseDto,
  })
  async logout(@Req() request: Request): Promise<LogoutResponseDto> {
    // Extract user from JWT payload (will be available after JwtAuthGuard is implemented)
    const userId = (request as any).user?.userId || 'temp_user_id';
    const sessionId = (request as any).user?.sessionId || 'temp_session_id';
    
    const logoutRequest = {
      userId,
      sessionId,
    };

    const response = await this.logoutUserUseCase.execute(logoutRequest);
    return this.authPresenter.presentLogoutResponse(response);
  }

  @Get('me')
  @HttpCode(HttpStatus.OK)
  // @UseGuards(JwtAuthGuard) // Will be implemented in step 8
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get current user information',
    description: 'Returns the authenticated user\'s profile information',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User information retrieved successfully',
    // type: ProfileResponseDto, // Will be defined in ProfileController
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or missing access token',
    type: ErrorResponseDto,
  })
  async getCurrentUser(@Req() request: Request) {
    // This endpoint will be implemented after guards are ready
    // For now, return a placeholder response
    const userId = (request as any).user?.userId || 'temp_user_id';
    
    return {
      message: 'Get current user endpoint - to be implemented with JWT guard',
      userId,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Extract client information from HTTP request
   * @param request Express request object
   * @returns Client information object
   */
  private extractClientInfo(request: Request) {
    const userAgent = request.headers['user-agent'] || 'Unknown';
    const ipAddress = this.getClientIpAddress(request);
    const deviceId = request.headers['x-device-id'] as string || null;

    return {
      userAgent,
      ipAddress,
      deviceId,
    };
  }

  /**
   * Extract client IP address considering proxies
   * @param request Express request object
   * @returns Client IP address
   */
  private getClientIpAddress(request: Request): string {
    const forwarded = request.headers['x-forwarded-for'] as string;
    const realIp = request.headers['x-real-ip'] as string;
    
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
    
    if (realIp) {
      return realIp;
    }
    
    return request.connection.remoteAddress || 
           request.socket.remoteAddress || 
           'Unknown';
  }
}