import { Injectable } from '@nestjs/common';
import { User } from '../entities/user.entity';
import { Session } from '../entities/session.entity';
import { UserRepository, SessionRepository } from '../ports/repositories';
import { 
  GetUserProfileRequest, 
  GetUserProfileResult,
  UserProfileWithSessions,
  SessionInfo,
  AccountSummary
} from '@auth/shared';

/**
 * Get User Profile Use Case
 * 
 * Retrieves comprehensive user profile information including:
 * - User basic information and settings
 * - Active sessions with device information
 * - Account summary and statistics
 * 
 * This use case aggregates data from multiple repositories to provide
 * a complete profile view for authenticated users.
 */
@Injectable()
export class GetUserProfileUseCase {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly sessionRepository: SessionRepository,
  ) {}

  async execute(request: GetUserProfileRequest): Promise<GetUserProfileResult> {
    const { userId } = request;

    // Validate input
    if (!userId?.trim()) {
      throw new Error('User ID is required');
    }

    try {
      // Fetch user information
      const user = await this.userRepository.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Fetch user's active sessions
      const sessions = await this.sessionRepository.findByUserId(userId);
      
      // Transform sessions to include device info and current session detection
      const sessionInfos: SessionInfo[] = sessions.map(session => ({
        id: session.id,
        deviceInfo: this.formatDeviceInfo(session.userAgent),
        ipAddress: session.ipAddress,
        lastActivity: session.lastActivity,
        createdAt: session.createdAt,
        isCurrentSession: session.isCurrent || false,
      }));

      // Calculate account summary statistics
      const accountSummary = await this.calculateAccountSummary(user, sessions);

      // Build comprehensive profile result
      const result: GetUserProfileResult = {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          profilePicture: user.profilePicture,
          bio: user.bio,
          location: user.location,
          website: user.website,
          provider: user.provider,
          emailVerified: user.emailVerified,
          status: user.status,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
          lastLoginAt: user.lastLoginAt,
        },
        sessions: sessionInfos,
        accountSummary,
      };

      return result;

    } catch (error) {
      // Re-throw with context for proper error handling in controller
      if (error.message === 'User not found') {
        throw error;
      }
      
      throw new Error(`Failed to retrieve user profile: ${error.message}`);
    }
  }

  /**
   * Format user agent string into human-readable device information
   */
  private formatDeviceInfo(userAgent: string): string {
    if (!userAgent || userAgent === 'unknown') {
      return 'Unknown device';
    }

    try {
      // Basic user agent parsing - in production, consider using a proper UA parser
      const ua = userAgent.toLowerCase();
      
      let browser = 'Unknown browser';
      let os = 'Unknown OS';

      // Detect browser
      if (ua.includes('chrome')) browser = 'Chrome';
      else if (ua.includes('firefox')) browser = 'Firefox';
      else if (ua.includes('safari') && !ua.includes('chrome')) browser = 'Safari';
      else if (ua.includes('edge')) browser = 'Edge';
      else if (ua.includes('opera')) browser = 'Opera';

      // Detect OS
      if (ua.includes('windows')) os = 'Windows';
      else if (ua.includes('macintosh') || ua.includes('mac os')) os = 'macOS';
      else if (ua.includes('linux')) os = 'Linux';
      else if (ua.includes('android')) os = 'Android';
      else if (ua.includes('iphone') || ua.includes('ipad')) os = 'iOS';

      return `${browser} on ${os}`;

    } catch (error) {
      return 'Unknown device';
    }
  }

  /**
   * Calculate account summary statistics
   */
  private async calculateAccountSummary(user: User, sessions: Session[]): Promise<AccountSummary> {
    try {
      // Count sessions
      const totalSessions = sessions.length;
      const activeSessions = sessions.filter(session => 
        session.expiresAt && session.expiresAt > new Date()
      ).length;

      // Calculate account age
      const accountAge = this.calculateAccountAge(user.createdAt);

      // Get last password change date
      // For now, use user creation date - in real implementation, 
      // this would come from a password history table
      const lastPasswordChange = user.createdAt;

      return {
        totalSessions,
        activeSessions,
        lastPasswordChange,
        accountAge,
      };

    } catch (error) {
      // Return default values if calculation fails
      return {
        totalSessions: 0,
        activeSessions: 0,
        lastPasswordChange: user.createdAt,
        accountAge: 'Unknown',
      };
    }
  }

  /**
   * Calculate human-readable account age
   */
  private calculateAccountAge(createdAt: Date): string {
    try {
      const now = new Date();
      const diffInMs = now.getTime() - createdAt.getTime();
      const diffInDays = Math.floor(diffInMs / (1000 * 60 * 60 * 24));

      if (diffInDays < 1) {
        return 'Today';
      } else if (diffInDays === 1) {
        return '1 day';
      } else if (diffInDays < 30) {
        return `${diffInDays} days`;
      } else if (diffInDays < 365) {
        const months = Math.floor(diffInDays / 30);
        return months === 1 ? '1 month' : `${months} months`;
      } else {
        const years = Math.floor(diffInDays / 365);
        const remainingMonths = Math.floor((diffInDays % 365) / 30);
        
        if (years === 1) {
          return remainingMonths > 0 ? `1 year, ${remainingMonths} months` : '1 year';
        } else {
          return remainingMonths > 0 ? `${years} years, ${remainingMonths} months` : `${years} years`;
        }
      }

    } catch (error) {
      return 'Unknown';
    }
  }
}