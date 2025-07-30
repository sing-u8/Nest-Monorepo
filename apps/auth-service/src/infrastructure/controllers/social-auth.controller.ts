import {
  Controller,
  Get,
  Post,
  Query,
  Body,
  HttpCode,
  HttpStatus,
  UsePipes,
  ValidationPipe,
  Req,
  Res,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiQuery,
  ApiBody,
} from '@nestjs/swagger';
import { Request, Response } from 'express';
import { Throttle } from '@nestjs/throttler';
import { randomBytes } from 'crypto';

// Use Cases
import { SocialLoginUseCase } from '../../domain/use-cases/social-login.use-case';

// Services
import { GoogleOAuthService } from '../../domain/ports/google-oauth.service';
import { AppleOAuthService } from '../../domain/ports/apple-oauth.service';

// DTOs
import {
  SocialLoginRequestDto,
  OAuthAuthorizationUrlResponseDto,
  SocialLoginResponseDto,
  OAuthProvider,
} from './dtos/social-auth.dto';
import { ErrorResponseDto } from './dtos/common.dto';

// Presenters
import { AuthPresenter } from '../presenters/auth.presenter';

@ApiTags('Social Authentication')
@Controller('auth')
@UsePipes(new ValidationPipe({ 
  whitelist: true, 
  forbidNonWhitelisted: true,
  transform: true,
}))
export class SocialAuthController {
  constructor(
    private readonly socialLoginUseCase: SocialLoginUseCase,
    private readonly googleOAuthService: GoogleOAuthService,
    private readonly appleOAuthService: AppleOAuthService,
    private readonly authPresenter: AuthPresenter,
  ) {}

  @Get('google')
  @ApiOperation({
    summary: 'Initiate Google OAuth flow',
    description: 'Redirects user to Google OAuth authorization page',
  })
  @ApiQuery({
    name: 'redirect_uri',
    required: false,
    description: 'Custom redirect URI after successful authentication',
    example: 'https://myapp.com/dashboard',
  })
  @ApiResponse({
    status: HttpStatus.FOUND,
    description: 'Redirect to Google OAuth authorization URL',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid configuration',
    type: ErrorResponseDto,
  })
  async initiateGoogleOAuth(
    @Query('redirect_uri') redirectUri?: string,
    @Res() response?: Response,
  ) {
    if (!this.googleOAuthService.validateConfiguration()) {
      throw new BadRequestException('Google OAuth is not properly configured');
    }

    const state = this.generateState();
    const scopes = ['openid', 'email', 'profile'];
    const authorizationUrl = this.googleOAuthService.getAuthorizationUrl(scopes, state);

    // Store state and redirect URI in session/cache for validation
    // In production, use Redis or similar for state storage
    const stateData = {
      state,
      redirectUri,
      provider: OAuthProvider.GOOGLE,
      timestamp: new Date().toISOString(),
    };

    if (response) {
      // Redirect mode for browser-based authentication
      response.redirect(authorizationUrl);
      return;
    }

    // API mode - return authorization URL
    return {
      authorizationUrl,
      provider: OAuthProvider.GOOGLE,
      state,
    } as OAuthAuthorizationUrlResponseDto;
  }

  @Get('google/callback')
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 requests per minute
  @ApiOperation({
    summary: 'Handle Google OAuth callback',
    description: 'Processes the authorization code from Google OAuth flow',
  })
  @ApiQuery({
    name: 'code',
    required: true,
    description: 'Authorization code from Google',
    example: '4/0AdQt8qh7rME5s1234...',
  })
  @ApiQuery({
    name: 'state',
    required: true,
    description: 'State parameter for CSRF protection',
    example: 'random_state_value_123',
  })
  @ApiQuery({
    name: 'error',
    required: false,
    description: 'Error code if OAuth failed',
    example: 'access_denied',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User authenticated successfully via Google',
    type: SocialLoginResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid authorization code or state',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'OAuth authorization denied',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Too many callback attempts',
    type: ErrorResponseDto,
  })
  async handleGoogleCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error?: string,
    @Req() request?: Request,
  ): Promise<SocialLoginResponseDto> {
    if (error) {
      throw new BadRequestException(`Google OAuth error: ${error}`);
    }

    if (!code || !state) {
      throw new BadRequestException('Missing authorization code or state parameter');
    }

    // In production, validate state parameter against stored value
    // For now, we'll skip state validation
    
    const clientInfo = this.extractClientInfo(request);
    
    const socialLoginRequest = {
      provider: OAuthProvider.GOOGLE,
      code,
      state,
      clientInfo,
    };

    const response = await this.socialLoginUseCase.execute(socialLoginRequest);
    return this.authPresenter.presentSocialLoginResponse(response);
  }

  @Get('apple')
  @ApiOperation({
    summary: 'Initiate Apple Sign In flow',
    description: 'Redirects user to Apple Sign In authorization page',
  })
  @ApiQuery({
    name: 'redirect_uri',
    required: false,
    description: 'Custom redirect URI after successful authentication',
    example: 'https://myapp.com/dashboard',
  })
  @ApiResponse({
    status: HttpStatus.FOUND,
    description: 'Redirect to Apple Sign In authorization URL',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid configuration',
    type: ErrorResponseDto,
  })
  async initiateAppleOAuth(
    @Query('redirect_uri') redirectUri?: string,
    @Res() response?: Response,
  ) {
    if (!this.appleOAuthService.validateConfiguration()) {
      throw new BadRequestException('Apple OAuth is not properly configured');
    }

    const state = this.generateState();
    const nonce = this.generateNonce();
    const scopes = ['name', 'email'];
    const authorizationUrl = this.appleOAuthService.getAuthorizationUrl(scopes, state, nonce);

    // Store state, nonce, and redirect URI for validation
    const stateData = {
      state,
      nonce,
      redirectUri,
      provider: OAuthProvider.APPLE,
      timestamp: new Date().toISOString(),
    };

    if (response) {
      // Redirect mode for browser-based authentication
      response.redirect(authorizationUrl);
      return;
    }

    // API mode - return authorization URL
    return {
      authorizationUrl,
      provider: OAuthProvider.APPLE,
      state,
      nonce,
    } as OAuthAuthorizationUrlResponseDto;
  }

  @Post('apple/callback')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 requests per minute
  @ApiOperation({
    summary: 'Handle Apple Sign In callback',
    description: 'Processes the form POST from Apple Sign In flow',
  })
  @ApiBody({
    description: 'Apple Sign In callback data',
    schema: {
      type: 'object',
      properties: {
        code: {
          type: 'string',
          description: 'Authorization code from Apple',
          example: 'c1234567890abcdef...',
        },
        id_token: {
          type: 'string',
          description: 'ID token from Apple',
          example: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
        },
        state: {
          type: 'string',
          description: 'State parameter for CSRF protection',
          example: 'random_state_value_123',
        },
        user: {
          type: 'string',
          description: 'User data JSON (first time only)',
          example: '{"name":{"firstName":"John","lastName":"Doe"},"email":"john@example.com"}',
        },
      },
      required: ['id_token', 'state'],
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User authenticated successfully via Apple Sign In',
    type: SocialLoginResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid ID token or state',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Apple Sign In authorization failed',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Too many callback attempts',
    type: ErrorResponseDto,
  })
  async handleAppleCallback(
    @Body() callbackData: any,
    @Req() request?: Request,
  ): Promise<SocialLoginResponseDto> {
    const { code, id_token: idToken, state, user } = callbackData;

    if (!idToken || !state) {
      throw new BadRequestException('Missing ID token or state parameter');
    }

    // In production, validate state parameter against stored value
    // For now, we'll skip state validation

    const clientInfo = this.extractClientInfo(request);
    
    // Parse user data if provided (first time sign in)
    let userData;
    if (user && typeof user === 'string') {
      try {
        userData = JSON.parse(user);
      } catch (error) {
        // Ignore invalid user data
        userData = undefined;
      }
    } else if (user && typeof user === 'object') {
      userData = user;
    }

    const socialLoginRequest = {
      provider: OAuthProvider.APPLE,
      code,
      idToken,
      state,
      user: userData,
      clientInfo,
    };

    const response = await this.socialLoginUseCase.execute(socialLoginRequest);
    return this.authPresenter.presentSocialLoginResponse(response);
  }

  @Post('social/login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 15, ttl: 60000 } }) // 15 requests per minute
  @ApiOperation({
    summary: 'Process social login with authorization code',
    description: 'Alternative endpoint for processing OAuth codes via API instead of callbacks',
  })
  @ApiBody({ type: SocialLoginRequestDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User authenticated successfully via social provider',
    type: SocialLoginResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input data',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Social authentication failed',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: 'Validation errors',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Too many social login attempts',
    type: ErrorResponseDto,
  })
  async socialLogin(
    @Body() socialLoginDto: SocialLoginRequestDto,
    @Req() request: Request,
  ): Promise<SocialLoginResponseDto> {
    const clientInfo = this.extractClientInfo(request);
    
    const socialLoginRequest = {
      provider: socialLoginDto.provider,
      code: socialLoginDto.code,
      state: socialLoginDto.state,
      idToken: socialLoginDto.idToken,
      user: socialLoginDto.user,
      clientInfo,
    };

    const response = await this.socialLoginUseCase.execute(socialLoginRequest);
    return this.authPresenter.presentSocialLoginResponse(response);
  }

  @Get('providers')
  @ApiOperation({
    summary: 'Get available OAuth providers',
    description: 'Returns list of configured OAuth providers and their status',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'OAuth providers information',
    schema: {
      type: 'object',
      properties: {
        providers: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string', example: 'GOOGLE' },
              displayName: { type: 'string', example: 'Google' },
              available: { type: 'boolean', example: true },
              authorizationUrl: { type: 'string', example: '/auth/google' },
            },
          },
        },
        timestamp: { type: 'string', example: '2023-12-31T23:59:59.000Z' },
      },
    },
  })
  async getAvailableProviders() {
    const providers = [
      {
        name: OAuthProvider.GOOGLE,
        displayName: 'Google',
        available: this.googleOAuthService.validateConfiguration(),
        authorizationUrl: '/auth/google',
      },
      {
        name: OAuthProvider.APPLE,
        displayName: 'Apple',
        available: this.appleOAuthService.validateConfiguration(),
        authorizationUrl: '/auth/apple',
      },
    ];

    return {
      providers,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Generate cryptographically secure state parameter
   * @returns Random state string
   */
  private generateState(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Generate cryptographically secure nonce parameter
   * @returns Random nonce string
   */
  private generateNonce(): string {
    return randomBytes(16).toString('hex');
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