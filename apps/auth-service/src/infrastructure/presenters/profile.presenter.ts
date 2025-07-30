import { Injectable } from '@nestjs/common';

// Use Case Response Models
import { UpdateProfileResponse } from '../../domain/models/update-profile.model';
import { GetUserProfileResponse } from '../../domain/models/get-user-profile.model';

// DTOs
import {
  ProfileResponseDto,
  UpdateProfileResponseDto,
} from '../controllers/dtos/profile.dto';

@Injectable()
export class ProfilePresenter {
  /**
   * Present user profile
   */
  presentProfile(response: GetUserProfileResponse): ProfileResponseDto {
    return {
      id: response.user.getId(),
      email: response.user.getEmail(),
      name: response.user.getName(),
      profilePicture: response.user.getProfilePicture(),
      provider: response.user.getProvider().toString(),
      status: response.user.getStatus().toString(),
      createdAt: response.user.getCreatedAt().toISOString(),
      updatedAt: response.user.getUpdatedAt().toISOString(),
    };
  }

  /**
   * Present update profile response
   */
  presentUpdateProfile(response: UpdateProfileResponse): UpdateProfileResponseDto {
    return {
      profile: {
        id: response.user.getId(),
        email: response.user.getEmail(),
        name: response.user.getName(),
        profilePicture: response.user.getProfilePicture(),
        provider: response.user.getProvider().toString(),
        status: response.user.getStatus().toString(),
        createdAt: response.user.getCreatedAt().toISOString(),
        updatedAt: response.user.getUpdatedAt().toISOString(),
      },
      message: response.message,
      timestamp: response.timestamp.toISOString(),
    };
  }

  /**
   * Present profile summary for listings
   */
  presentProfileSummary(user: any) {
    return {
      id: user.getId(),
      name: user.getName(),
      profilePicture: user.getProfilePicture(),
      provider: user.getProvider().toString(),
      status: user.getStatus().toString(),
    };
  }

  /**
   * Present user session information
   */
  presentUserSession(session: any) {
    return {
      sessionId: session.getSessionToken(),
      deviceId: session.getClientInfo()?.deviceId || null,
      userAgent: session.getClientInfo()?.userAgent || 'Unknown',
      ipAddress: session.getClientInfo()?.ipAddress || 'Unknown',
      location: this.getLocationFromIp(session.getClientInfo()?.ipAddress),
      createdAt: session.getCreatedAt().toISOString(),
      lastActivity: session.getUpdatedAt().toISOString(),
      expiresAt: session.getExpiresAt().toISOString(),
      isActive: !session.isExpired(),
    };
  }

  /**
   * Present multiple user sessions
   */
  presentUserSessions(sessions: any[], currentSessionId?: string) {
    return {
      sessions: sessions.map(session => ({
        ...this.presentUserSession(session),
        current: session.getSessionToken() === currentSessionId,
      })),
      totalCount: sessions.length,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Present user settings
   */
  presentUserSettings(settings: any) {
    return {
      userId: settings.userId,
      emailNotifications: settings.emailNotifications ?? true,
      pushNotifications: settings.pushNotifications ?? false,
      twoFactorEnabled: settings.twoFactorEnabled ?? false,
      language: settings.language ?? 'en',
      timezone: settings.timezone ?? 'UTC',
      privacy: {
        profileVisibility: settings.privacy?.profileVisibility ?? 'public',
        showEmail: settings.privacy?.showEmail ?? false,
      },
      createdAt: settings.createdAt?.toISOString() || new Date().toISOString(),
      updatedAt: settings.updatedAt?.toISOString() || new Date().toISOString(),
    };
  }

  /**
   * Present profile picture upload response
   */
  presentProfilePictureUpload(
    profilePictureUrl: string,
    fileInfo?: {
      originalName: string;
      mimeType: string;
      size: number;
    },
  ) {
    return {
      profilePicture: profilePictureUrl,
      message: 'Profile picture updated successfully',
      timestamp: new Date().toISOString(),
      ...(fileInfo && { fileInfo }),
    };
  }

  /**
   * Present account activity summary
   */
  presentAccountActivity(activity: {
    lastLogin?: Date;
    loginCount?: number;
    activeSessions?: number;
    recentActivity?: Array<{
      action: string;
      timestamp: Date;
      ipAddress?: string;
      userAgent?: string;
    }>;
  }) {
    return {
      lastLogin: activity.lastLogin?.toISOString() || null,
      loginCount: activity.loginCount || 0,
      activeSessions: activity.activeSessions || 0,
      recentActivity: activity.recentActivity?.map(item => ({
        action: item.action,
        timestamp: item.timestamp.toISOString(),
        ipAddress: item.ipAddress || 'Unknown',
        userAgent: item.userAgent || 'Unknown',
        location: this.getLocationFromIp(item.ipAddress),
      })) || [],
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Present profile validation errors
   */
  presentProfileValidationErrors(errors: Array<{
    field: string;
    message: string;
    constraint?: string;
    value?: any;
  }>) {
    return {
      statusCode: 422,
      message: 'Profile validation failed',
      error: 'PROFILE_VALIDATION_ERROR',
      timestamp: new Date().toISOString(),
      validationErrors: errors.map(error => ({
        field: error.field,
        message: error.message,
        constraint: error.constraint,
        value: error.value,
      })),
    };
  }

  /**
   * Present profile update success with change summary
   */
  presentProfileUpdateSuccess(
    updatedUser: any,
    changes: Record<string, { from: any; to: any }>,
  ) {
    return {
      profile: this.presentProfile({ user: updatedUser }),
      message: 'Profile updated successfully',
      changes: Object.entries(changes).map(([field, change]) => ({
        field,
        from: change.from,
        to: change.to,
      })),
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Present account deletion confirmation
   */
  presentAccountDeletionConfirmation() {
    return {
      message: 'Account deletion confirmation sent',
      instructions: 'Please check your email for account deletion instructions',
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Present privacy settings
   */
  presentPrivacySettings(settings: {
    profileVisibility: 'public' | 'private';
    showEmail: boolean;
    showPhone: boolean;
    showLocation: boolean;
    allowSearchEngineIndexing: boolean;
    dataProcessingConsent: boolean;
  }) {
    return {
      privacy: settings,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Extract location information from IP address
   * In production, this would use a geolocation service
   */
  private getLocationFromIp(ipAddress?: string): string {
    if (!ipAddress || ipAddress === 'Unknown') {
      return 'Unknown Location';
    }

    // Mock location data - in production, use a service like MaxMind GeoIP
    const mockLocations: Record<string, string> = {
      '127.0.0.1': 'Localhost',
      '192.168.1.1': 'Local Network',
      '10.0.0.1': 'Private Network',
    };

    return mockLocations[ipAddress] || 'Unknown Location';
  }

  /**
   * Format file size in human-readable format
   */
  private formatFileSize(bytes: number): string {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  }

  /**
   * Validate profile picture URL format
   */
  private isValidProfilePictureUrl(url: string): boolean {
    try {
      const parsedUrl = new URL(url);
      return parsedUrl.protocol === 'https:' && 
             /\.(jpg|jpeg|png|gif|webp)$/i.test(parsedUrl.pathname);
    } catch {
      return false;
    }
  }
}