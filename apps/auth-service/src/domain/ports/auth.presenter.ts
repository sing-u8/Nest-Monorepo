import {
  RegisterUserResponse,
  LoginUserResponse,
  SocialLoginResponse,
  RefreshTokenResponse,
  UpdateProfileResponse,
  LogoutResponse,
  ErrorResponse
} from '../models/auth.models';

export interface AuthPresenter {
  presentRegisterSuccess(response: RegisterUserResponse): any;
  presentLoginSuccess(response: LoginUserResponse): any;
  presentSocialLoginSuccess(response: SocialLoginResponse): any;
  presentRefreshTokenSuccess(response: RefreshTokenResponse): any;
  presentUpdateProfileSuccess(response: UpdateProfileResponse): any;
  presentLogoutSuccess(response: LogoutResponse): any;
  presentError(error: ErrorResponse): any;
  presentValidationError(errors: string[]): any;
}