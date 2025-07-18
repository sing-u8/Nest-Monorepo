import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Ip,
  Post,
  UseGuards,
} from '@nestjs/common';

// Application Services
import { AuthApplicationService } from '@/auth/application/service';
// Guards & Decorators
import { JwtAuthGuard } from '@/auth/infrastructure/guard';
import { RefreshTokenGuard } from '@/auth/infrastructure/guard';
import { CurrentUser, CurrentUserInfo } from '../decorator/current-user.decorator';
import { Public } from '../decorator/public.decorator';
// Presentation DTOs
import {
  LoginRequestDto,
  LogoutRequestDto,
  RefreshTokenRequestDto,
  SignUpRequestDto,
} from '../dto/requests';
import {
  AuthResponseDto,
  BaseResponseDto,
  LogoutResponseDto,
  RefreshTokenResponseDto,
  TokenInfoDto,
  UserInfoDto,
} from '../dto/responses';

/**
 * Auth Controller
 *
 * 인증 관련 API 엔드포인트를 처리합니다.
 */
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthApplicationService,
  ) {}

  @Post('signup')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  async signUp(
    @Body() signUpDto: SignUpRequestDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent?: string,
  ): Promise<BaseResponseDto<AuthResponseDto>> {
    const deviceInfo = userAgent || 'Unknown Device';
    const ipAddress = ip || 'Unknown IP';

    const result = await this.authService.signUp(signUpDto);

    return new BaseResponseDto({
      success: true,
      message: '회원가입이 완료되었습니다.',
      data: new AuthResponseDto({
        user: result.user,
        tokens: new TokenInfoDto({
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
          expiresIn: result.expiresIn,
          refreshExpiresIn: 7 * 24 * 60 * 60, // 7일 (초)
        }),
        isNewUser: result.isNewUser,
      }),
    });
  }

  @Post('login')
  @Public()
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginRequestDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent?: string,
  ): Promise<BaseResponseDto<AuthResponseDto>> {
    const deviceInfo = loginDto.deviceInfo || userAgent || 'Unknown Device';
    const ipAddress = loginDto.ipAddress || ip || 'Unknown IP';

    const result = await this.authService.login(loginDto);

    return new BaseResponseDto({
      success: true,
      message: '로그인이 완료되었습니다.',
      data: new AuthResponseDto({
        user: result.user,
        tokens: new TokenInfoDto({
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
          expiresIn: result.expiresIn,
          refreshExpiresIn: 7 * 24 * 60 * 60, // 7일 (초)
        }),
        isNewUser: result.isNewUser,
      }),
    });
  }

  @Post('refresh')
  @Public()
  @UseGuards(RefreshTokenGuard)
  @HttpCode(HttpStatus.OK)
  async refreshToken(
    @Body() refreshDto: RefreshTokenRequestDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent?: string,
  ): Promise<BaseResponseDto<RefreshTokenResponseDto>> {
    const deviceInfo = refreshDto.deviceInfo || userAgent || 'Unknown Device';
    const ipAddress = refreshDto.ipAddress || ip || 'Unknown IP';

    const result = await this.authService.refreshToken(refreshDto);

    return new BaseResponseDto({
      success: true,
      message: '토큰이 갱신되었습니다.',
      data: new RefreshTokenResponseDto({
        tokens: new TokenInfoDto({
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
          expiresIn: result.expiresIn,
          refreshExpiresIn: 7 * 24 * 60 * 60, // 7일 (초)
        }),
        user: null, // refreshToken 응답에서는 사용자 정보 제외
      }),
    });
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(
    @Body() logoutDto: LogoutRequestDto,
    @CurrentUser() currentUser: CurrentUserInfo,
  ): Promise<BaseResponseDto<LogoutResponseDto>> {
    await this.authService.logout(logoutDto);

    return new BaseResponseDto({
      success: true,
      message: '로그아웃이 완료되었습니다.',
      data: new LogoutResponseDto(),
    });
  }

  @Post('logout-all')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logoutAll(
    @CurrentUser() currentUser: CurrentUserInfo,
  ): Promise<BaseResponseDto<LogoutResponseDto>> {
    await this.authService.logoutAll(currentUser.userId);

    return new BaseResponseDto({
      success: true,
      message: '모든 디바이스에서 로그아웃되었습니다.',
      data: new LogoutResponseDto(),
    });
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getCurrentUser(
    @CurrentUser() currentUser: CurrentUserInfo,
  ): Promise<BaseResponseDto<UserInfoDto>> {
    const user = await this.authService.getCurrentUser(currentUser.userId);

    return new BaseResponseDto({
      success: true,
      message: '사용자 정보를 조회했습니다.',
      data: new UserInfoDto(user),
    });
  }
}
