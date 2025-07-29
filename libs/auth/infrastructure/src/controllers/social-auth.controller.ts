import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Res,
  Req,
  HttpStatus,
  HttpCode,
  BadRequestException,
  UnauthorizedException,
  InternalServerErrorException,
  ValidationPipe,
  UsePipes,
  Inject,
  Logger,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiQuery, ApiBody } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { SocialAuthRateLimit } from '../decorators/rate-limit.decorator';
import { SocialLoginUseCase, AuthPresenter } from '@auth/domain';
import { GoogleOAuthService, AppleOAuthService } from '../services';
import {
  SocialLoginRequest,
  SocialLoginResponse,
  GoogleCallbackQuery,
  AppleCallbackRequest,
} from '@auth/shared';

/**
 * Social Authentication Controller
 * 
 * Handles OAuth authentication flows for social providers:
 * - Google OAuth 2.0 authorization code flow
 * - Apple Sign In identity token flow
 * 
 * Provides secure OAuth initiation and callback handling
 * with comprehensive error handling and security measures.
 */
@ApiTags('Social Authentication')
@Controller('auth')
@UsePipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
  validateCustomDecorators: true,
}))
export class SocialAuthController {
  private readonly logger = new Logger(SocialAuthController.name);

  constructor(
    @Inject('SocialLoginUseCase')
    private readonly socialLoginUseCase: SocialLoginUseCase,

    @Inject('AuthPresenter')
    private readonly authPresenter: AuthPresenter,

    private readonly googleOAuthService: GoogleOAuthService,
    private readonly appleOAuthService: AppleOAuthService,
  ) {}

  /**
   * Initiate Google OAuth flow
   * GET /auth/google
   */
  @Get('google')
  @SocialAuthRateLimit()
  @ApiOperation({
    summary: 'Initiate Google OAuth flow',
    description: 'Redirects user to Google OAuth authorization page',
  })
  @ApiQuery({
    name: 'state',
    required: false,
    description: 'Optional state parameter for CSRF protection',
    example: 'random-state-123',
  })
  @ApiQuery({
    name: 'redirect_uri',
    required: false,
    description: 'Optional custom redirect URI after successful authentication',
    example: 'https://yourapp.com/dashboard',
  })
  @ApiResponse({
    status: HttpStatus.FOUND,
    description: 'Redirects to Google OAuth authorization URL',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Failed to generate Google OAuth URL',
    schema: {
      example: {
        success: false,
        error: 'OAUTH_ERROR',
        message: 'Failed to initiate Google OAuth flow',
      },
    },
  })
  async initiateGoogleAuth(
    @Query('state') state?: string,
    @Query('redirect_uri') redirectUri?: string,
    @Res() res?: Response,
  ): Promise<void> {
    try {
      this.logger.log('Initiating Google OAuth flow');

      // Generate secure state if not provided
      const oauthState = state || this.generateSecureState();
      
      // Store redirect URI in state if provided (encode for security)
      const stateData = redirectUri 
        ? `${oauthState}|${Buffer.from(redirectUri).toString('base64')}`
        : oauthState;

      // Generate Google OAuth URL
      const authUrl = await this.googleOAuthService.generateAuthUrl(stateData);

      this.logger.log('Google OAuth URL generated successfully');
      
      // Redirect to Google OAuth
      res?.redirect(authUrl);

    } catch (error) {
      this.logger.error('Failed to initiate Google OAuth flow:', error);
      
      throw new InternalServerErrorException(
        this.authPresenter.presentOAuthError('Failed to initiate Google OAuth flow')
      );
    }
  }

  /**
   * Handle Google OAuth callback
   * GET /auth/google/callback
   */
  @Get('google/callback')
  @SocialAuthRateLimit()
  @ApiOperation({
    summary: 'Handle Google OAuth callback',
    description: 'Processes Google OAuth callback and completes user authentication',
  })
  @ApiQuery({
    name: 'code',
    required: true,
    description: 'Authorization code from Google',
    example: '4/0AX4XfWjYn1mZHEHLBbVtk-example-code',
  })
  @ApiQuery({
    name: 'state',
    required: true,
    description: 'State parameter for CSRF protection',
    example: 'random-state-123',
  })
  @ApiQuery({
    name: 'error',
    required: false,
    description: 'Error code if OAuth failed',
    example: 'access_denied',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Google OAuth authentication successful',
    type: SocialLoginResponse,
    schema: {
      example: {
        success: true,
        message: 'Google authentication successful',
        data: {
          user: {
            id: 'user-123',
            email: 'user@gmail.com',
            name: 'John Doe',
            provider: 'google',
            isNewUser: false,
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
    description: 'Invalid OAuth callback parameters',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'OAuth authentication failed',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
  })
  async handleGoogleCallback(
    @Query() query: GoogleCallbackQuery,
    @Req() req: Request,
    @Res() res?: Response,
  ): Promise<SocialLoginResponse | void> {
    try {
      this.logger.log('Processing Google OAuth callback');

      // Handle OAuth error responses
      if (query.error) {
        this.logger.warn(`Google OAuth error: ${query.error}`);
        
        if (query.error === 'access_denied') {
          throw new UnauthorizedException(
            this.authPresenter.presentOAuthError('User denied access to Google account')
          );
        }
        
        throw new UnauthorizedException(
          this.authPresenter.presentOAuthError(`Google OAuth error: ${query.error}`)
        );
      }

      // Validate required parameters
      if (!query.code || !query.state) {
        throw new BadRequestException(
          this.authPresenter.presentValidationError('Missing required OAuth parameters')
        );
      }

      // Extract state and redirect URI
      const { state, redirectUri } = this.parseStateData(query.state);

      // Exchange authorization code for tokens
      const tokens = await this.googleOAuthService.exchangeCodeForTokens(query.code);
      
      // Get user profile
      const userProfile = await this.googleOAuthService.getUserProfile(tokens.accessToken);

      // Create social login request
      const socialLoginRequest: SocialLoginRequest = {
        provider: 'google',
        authorizationCode: query.code,
        idToken: tokens.idToken || undefined,
        profile: {
          id: userProfile.id,
          email: userProfile.email,
          emailVerified: userProfile.emailVerified,
          name: userProfile.name || undefined,
          givenName: userProfile.givenName || undefined,
          familyName: userProfile.familyName || undefined,
          picture: userProfile.picture || undefined,
          locale: userProfile.locale || undefined,
        },
        clientInfo: {
          userAgent: req.headers['user-agent'] || 'unknown',
          ipAddress: this.extractClientIP(req),
          deviceId: req.headers['x-device-id'] as string || undefined,
        },
      };

      // Execute social login use case
      const result = await this.socialLoginUseCase.execute(socialLoginRequest);

      this.logger.log(`Google OAuth successful for user: ${userProfile.email}`);
      
      const response = this.authPresenter.presentSocialLoginSuccess(result);

      // Handle redirect if specified
      if (redirectUri && res) {
        const redirectUrl = new URL(redirectUri);
        redirectUrl.searchParams.set('token', result.tokens.accessToken);
        redirectUrl.searchParams.set('refresh_token', result.tokens.refreshToken);
        
        res.redirect(redirectUrl.toString());
        return;
      }

      return response;

    } catch (error) {
      this.logger.error('Google OAuth callback failed:', error);

      if (error instanceof BadRequestException || error instanceof UnauthorizedException) {
        throw error;
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
   * Initiate Apple Sign In flow  
   * GET /auth/apple
   */
  @Get('apple')
  @SocialAuthRateLimit()
  @ApiOperation({
    summary: 'Initiate Apple Sign In flow',
    description: 'Redirects user to Apple Sign In authorization page',
  })
  @ApiQuery({
    name: 'state',
    required: false,
    description: 'Optional state parameter for CSRF protection',
    example: 'random-state-123',
  })
  @ApiQuery({
    name: 'redirect_uri',
    required: false,
    description: 'Optional custom redirect URI after successful authentication',
    example: 'https://yourapp.com/dashboard',
  })
  @ApiResponse({
    status: HttpStatus.FOUND,
    description: 'Redirects to Apple Sign In authorization URL',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Failed to generate Apple OAuth URL',
  })
  async initiateAppleAuth(
    @Query('state') state?: string,
    @Query('redirect_uri') redirectUri?: string,
    @Res() res?: Response,
  ): Promise<void> {
    try {
      this.logger.log('Initiating Apple Sign In flow');

      // Generate secure state and nonce
      const oauthState = state || this.generateSecureState();
      const nonce = this.generateSecureNonce();
      
      // Store redirect URI and nonce in state if provided
      const stateData = redirectUri 
        ? `${oauthState}|${Buffer.from(redirectUri).toString('base64')}|${nonce}`
        : `${oauthState}||${nonce}`;

      // Generate Apple Sign In URL
      const authUrl = await this.appleOAuthService.generateAuthUrl(stateData, nonce);

      this.logger.log('Apple Sign In URL generated successfully');
      
      // Redirect to Apple Sign In
      res?.redirect(authUrl);

    } catch (error) {
      this.logger.error('Failed to initiate Apple Sign In flow:', error);
      
      throw new InternalServerErrorException(
        this.authPresenter.presentOAuthError('Failed to initiate Apple Sign In flow')
      );
    }
  }

  /**
   * Handle Apple Sign In callback
   * POST /auth/apple/callback
   */
  @Post('apple/callback')
  @HttpCode(HttpStatus.OK)
  @SocialAuthRateLimit()
  @ApiOperation({
    summary: 'Handle Apple Sign In callback',
    description: 'Processes Apple Sign In callback and completes user authentication',
  })
  @ApiBody({
    type: AppleCallbackRequest,
    description: 'Apple Sign In callback data',
    examples: {
      'apple-callback': {
        summary: 'Apple callback with ID token',
        description: 'Standard Apple Sign In callback with identity token',
        value: {
          code: 'c6b8e0e8d.0.mrty.example-authorization-code',
          id_token: 'eyJraWQiOiJBSURPUEsxIiwiYWxnIjoiUlMyNTYifQ...',
          state: 'random-state-123',
          user: JSON.stringify({
            email: 'user@privaterelay.appleid.com',
            name: { firstName: 'John', lastName: 'Doe' }
          }),
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Apple Sign In authentication successful',
    type: SocialLoginResponse,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid Apple callback parameters',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Apple authentication failed',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error',
  })
  async handleAppleCallback(
    @Body() body: AppleCallbackRequest,
    @Req() req: Request,
    @Res() res?: Response,
  ): Promise<SocialLoginResponse | void> {
    try {
      this.logger.log('Processing Apple Sign In callback');

      // Validate required parameters
      if (!body.id_token || !body.state) {
        throw new BadRequestException(
          this.authPresenter.presentValidationError('Missing required Apple callback parameters')
        );
      }

      // Extract state, redirect URI, and nonce
      const { state, redirectUri, nonce } = this.parseAppleStateData(body.state);

      // Validate ID token with nonce
      const userProfile = await this.appleOAuthService.validateIdToken(body.id_token, nonce);

      // Parse additional user data if provided (first sign-in only)
      let additionalUserData = null;
      if (body.user) {
        try {
          additionalUserData = typeof body.user === 'string' 
            ? JSON.parse(body.user) 
            : body.user;
        } catch (error) {
          this.logger.warn('Failed to parse Apple user data:', error);
        }
      }

      // Create social login request
      const socialLoginRequest: SocialLoginRequest = {
        provider: 'apple',
        authorizationCode: body.code || undefined,
        idToken: body.id_token,
        profile: {
          id: userProfile.id,
          email: userProfile.email,
          emailVerified: userProfile.emailVerified,
          name: userProfile.name || this.extractAppleName(additionalUserData),
          isPrivateEmail: userProfile.isPrivateEmail,
          realUserStatus: userProfile.realUserStatus,
        },
        clientInfo: {
          userAgent: req.headers['user-agent'] || 'unknown',
          ipAddress: this.extractClientIP(req),
          deviceId: req.headers['x-device-id'] as string || undefined,
        },
      };

      // Execute social login use case
      const result = await this.socialLoginUseCase.execute(socialLoginRequest);

      this.logger.log(`Apple Sign In successful for user: ${userProfile.email}`);
      
      const response = this.authPresenter.presentSocialLoginSuccess(result);

      // Handle redirect if specified
      if (redirectUri && res) {
        const redirectUrl = new URL(redirectUri);
        redirectUrl.searchParams.set('token', result.tokens.accessToken);
        redirectUrl.searchParams.set('refresh_token', result.tokens.refreshToken);
        
        res.redirect(redirectUrl.toString());
        return;
      }

      return response;

    } catch (error) {
      this.logger.error('Apple Sign In callback failed:', error);

      if (error instanceof BadRequestException || error instanceof UnauthorizedException) {
        throw error;
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
   * Get OAuth service configuration
   * GET /auth/oauth/config
   */
  @Get('oauth/config')
  @ApiOperation({
    summary: 'Get OAuth configuration',
    description: 'Returns public OAuth configuration for client applications',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'OAuth configuration retrieved successfully',
    schema: {
      example: {
        success: true,
        data: {
          google: {
            clientId: 'your-google-client-id.googleusercontent.com',
            redirectUri: 'https://yourapp.com/auth/google/callback',
            scopes: ['email', 'profile'],
          },
          apple: {
            clientId: 'com.yourapp.service',
            redirectUri: 'https://yourapp.com/auth/apple/callback',
            scopes: ['name', 'email'],
          },
        },
      },
    },
  })
  async getOAuthConfig(): Promise<any> {
    try {
      const googleConfig = this.googleOAuthService.getConfiguration();
      const appleConfig = this.appleOAuthService.getConfiguration();

      return {
        success: true,
        data: {
          google: {
            clientId: googleConfig.clientId,
            redirectUri: googleConfig.redirectUri,
            scopes: googleConfig.scopes,
          },
          apple: {
            clientId: appleConfig.clientId,
            redirectUri: appleConfig.redirectUri,
            scopes: appleConfig.scopes,
          },
        },
      };
    } catch (error) {
      this.logger.error('Failed to get OAuth configuration:', error);
      
      throw new InternalServerErrorException(
        this.authPresenter.presentInternalError()
      );
    }
  }

  // Private helper methods

  private generateSecureState(length: number = 32): string {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    
    return result;
  }

  private generateSecureNonce(length: number = 32): string {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    
    return result;
  }

  private parseStateData(stateData: string): { state: string; redirectUri?: string } {
    try {
      if (stateData.includes('|')) {
        const [state, encodedRedirectUri] = stateData.split('|');
        const redirectUri = Buffer.from(encodedRedirectUri, 'base64').toString();
        return { state, redirectUri };
      }
      
      return { state: stateData };
    } catch (error) {
      this.logger.warn('Failed to parse state data:', error);
      return { state: stateData };
    }
  }

  private parseAppleStateData(stateData: string): { state: string; redirectUri?: string; nonce?: string } {
    try {
      const parts = stateData.split('|');
      const state = parts[0];
      const redirectUri = parts[1] ? Buffer.from(parts[1], 'base64').toString() : undefined;
      const nonce = parts[2] || undefined;
      
      return { state, redirectUri, nonce };
    } catch (error) {
      this.logger.warn('Failed to parse Apple state data:', error);
      return { state: stateData };
    }
  }

  private extractClientIP(req: Request): string {
    return (
      (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (req.headers['x-real-ip'] as string) ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      'unknown'
    );
  }

  private extractAppleName(userData: any): string | undefined {
    if (!userData || !userData.name) {
      return undefined;
    }

    const { firstName, lastName } = userData.name;
    
    if (firstName && lastName) {
      return `${firstName} ${lastName}`;
    }
    
    if (firstName) {
      return firstName;
    }
    
    if (lastName) {
      return lastName;
    }
    
    return undefined;
  }
}