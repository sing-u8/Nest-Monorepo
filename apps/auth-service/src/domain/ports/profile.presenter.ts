import { UpdateProfileResponse, ErrorResponse } from '../models/auth.models';

export interface ProfileInfo {
  id: string;
  email: string;
  name: string;
  profilePicture?: string;
  provider: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ProfilePresenter {
  presentProfile(profile: ProfileInfo): any;
  presentUpdateSuccess(response: UpdateProfileResponse): any;
  presentError(error: ErrorResponse): any;
  presentValidationError(errors: string[]): any;
}