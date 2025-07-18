import { Body, Controller, Delete, Get, Param, Patch, Query, UseGuards } from '@nestjs/common';
import { UserApplicationService } from '@/auth/application/service';
import { JwtAuthGuard } from '@/auth/infrastructure/guard';
import { CurrentUser, CurrentUserInfo } from '../decorator/current-user.decorator';
import { ChangePasswordRequestDto } from '../dto/requests';
import { BaseResponseDto, UserDetailDto, UserListResponseDto } from '../dto/responses';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserApplicationService) {}

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  async getProfile(@CurrentUser() currentUser: CurrentUserInfo): Promise<BaseResponseDto<UserDetailDto>> {
    const user = await this.userService.getUserById(currentUser.userId);

    return new BaseResponseDto({
      success: true,
      message: '사용자 프로필을 조회했습니다.',
      data: new UserDetailDto(user),
    });
  }

  @Patch('password')
  @UseGuards(JwtAuthGuard)
  async changePassword(
    @Body() changePasswordDto: ChangePasswordRequestDto,
    @CurrentUser() currentUser: CurrentUserInfo,
  ): Promise<BaseResponseDto<{ message: string }>> {
    await this.userService.changePassword(
      currentUser.userId,
      changePasswordDto,
    );

    return new BaseResponseDto({
      success: true,
      message: '비밀번호가 성공적으로 변경되었습니다.',
      data: { message: '비밀번호 변경 완료' },
    });
  }

  @Delete('account')
  @UseGuards(JwtAuthGuard)
  async deleteAccount(@CurrentUser() currentUser: CurrentUserInfo): Promise<BaseResponseDto<{ message: string }>> {
    await this.userService.deleteUser(
      currentUser.userId,
      'User requested account deletion',
    );

    return new BaseResponseDto({
      success: true,
      message: '계정이 성공적으로 삭제되었습니다.',
      data: { message: '계정 삭제 완료' },
    });
  }
}
