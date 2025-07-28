import { DataSource } from 'typeorm';
import { UserEntity } from '../entities/user.entity';
import { TokenEntity } from '../entities/token.entity';
import { AuthSessionEntity } from '../entities/auth-session.entity';

/**
 * Database Seed Data
 * 
 * Provides sample data for development and testing environments.
 * Should not be run in production environments.
 */
export class DatabaseSeeder {
  constructor(private readonly dataSource: DataSource) {}

  async run(): Promise<void> {
    const nodeEnv = process.env['NODE_ENV'] || 'development';
    
    if (nodeEnv === 'production') {
      throw new Error('Seeding is not allowed in production environment');
    }

    console.log('🌱 Starting database seeding...');

    await this.seedUsers();
    await this.seedTokens();
    await this.seedSessions();

    console.log('✅ Database seeding completed successfully');
  }

  private async seedUsers(): Promise<void> {
    const userRepository = this.dataSource.getRepository(UserEntity);

    // Check if users already exist
    const existingUsersCount = await userRepository.count();
    if (existingUsersCount > 0) {
      console.log('👥 Users already exist, skipping user seeding');
      return;
    }

    const users = [
      // Local user accounts
      {
        id: 'user-local-1',
        email: 'admin@example.com',
        password: '$2b$10$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', // 'admin123'
        name: 'Admin User',
        provider: 'local',
        email_verified: true,
        status: 'active',
        last_login_at: new Date('2024-01-15T10:30:00Z'),
      },
      {
        id: 'user-local-2',
        email: 'john.doe@example.com',
        password: '$2b$10$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', // 'password123'
        name: 'John Doe',
        provider: 'local',
        email_verified: true,
        status: 'active',
        last_login_at: new Date('2024-01-14T15:45:00Z'),
      },
      {
        id: 'user-local-3',
        email: 'jane.smith@example.com',
        password: '$2b$10$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', // 'password123'
        name: 'Jane Smith',
        provider: 'local',
        email_verified: false,
        status: 'active',
        last_login_at: new Date('2024-01-13T09:20:00Z'),
      },
      {
        id: 'user-local-4',
        email: 'inactive@example.com',
        password: '$2b$10$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', // 'password123'
        name: 'Inactive User',
        provider: 'local',
        email_verified: true,
        status: 'inactive',
        last_login_at: new Date('2024-01-01T12:00:00Z'),
      },
      
      // Social login accounts
      {
        id: 'user-google-1',
        email: 'googleuser@gmail.com',
        name: 'Google User',
        profile_picture: 'https://lh3.googleusercontent.com/a/photo.jpg',
        provider: 'google',
        provider_id: 'google-123456789',
        email_verified: true,
        status: 'active',
        last_login_at: new Date('2024-01-16T08:15:00Z'),
      },
      {
        id: 'user-apple-1',
        email: 'appleuser@privaterelay.appleid.com',
        name: 'Apple User',
        provider: 'apple',
        provider_id: 'apple-987654321',
        email_verified: true,
        status: 'active',
        last_login_at: new Date('2024-01-15T14:30:00Z'),
      },
      {
        id: 'user-google-2',
        email: 'anothergoogle@gmail.com',
        name: 'Another Google User',
        provider: 'google',
        provider_id: 'google-111222333',
        email_verified: true,
        status: 'suspended',
        last_login_at: new Date('2024-01-10T16:45:00Z'),
      },
    ];

    await userRepository.save(users);
    console.log(`👥 Created ${users.length} users`);
  }

  private async seedTokens(): Promise<void> {
    const tokenRepository = this.dataSource.getRepository(TokenEntity);

    // Check if tokens already exist
    const existingTokensCount = await tokenRepository.count();
    if (existingTokensCount > 0) {
      console.log('🎫 Tokens already exist, skipping token seeding');
      return;
    }

    const now = new Date();
    const oneHour = 60 * 60 * 1000;
    const oneDay = 24 * oneHour;
    const oneWeek = 7 * oneDay;

    const tokens = [
      // Active refresh tokens
      {
        id: 'token-refresh-1',
        user_id: 'user-local-1',
        type: 'refresh_token',
        value: 'hashed-refresh-token-1',
        expires_at: new Date(now.getTime() + oneWeek),
      },
      {
        id: 'token-refresh-2',
        user_id: 'user-local-2',
        type: 'refresh_token',
        value: 'hashed-refresh-token-2',
        expires_at: new Date(now.getTime() + oneWeek),
      },
      {
        id: 'token-refresh-3',
        user_id: 'user-google-1',
        type: 'refresh_token',
        value: 'hashed-refresh-token-3',
        expires_at: new Date(now.getTime() + oneWeek),
      },

      // Revoked tokens
      {
        id: 'token-refresh-4',
        user_id: 'user-local-2',
        type: 'refresh_token',
        value: 'hashed-refresh-token-4-revoked',
        expires_at: new Date(now.getTime() + oneWeek),
        revoked_at: new Date(now.getTime() - oneDay),
      },

      // Email verification tokens
      {
        id: 'token-email-1',
        user_id: 'user-local-3',
        type: 'email_verification',
        value: 'hashed-email-verification-token-1',
        expires_at: new Date(now.getTime() + oneDay),
      },

      // Expired tokens
      {
        id: 'token-expired-1',
        user_id: 'user-local-4',
        type: 'refresh_token',
        value: 'hashed-expired-token-1',
        expires_at: new Date(now.getTime() - oneDay),
      },

      // Password reset tokens
      {
        id: 'token-reset-1',
        user_id: 'user-local-1',
        type: 'password_reset',
        value: 'hashed-password-reset-token-1',
        expires_at: new Date(now.getTime() + oneHour),
      },
    ];

    await tokenRepository.save(tokens);
    console.log(`🎫 Created ${tokens.length} tokens`);
  }

  private async seedSessions(): Promise<void> {
    const sessionRepository = this.dataSource.getRepository(AuthSessionEntity);

    // Check if sessions already exist
    const existingSessionsCount = await sessionRepository.count();
    if (existingSessionsCount > 0) {
      console.log('💻 Sessions already exist, skipping session seeding');
      return;
    }

    const now = new Date();
    const oneDay = 24 * 60 * 60 * 1000;
    const oneWeek = 7 * oneDay;

    const sessions = [
      // Active sessions
      {
        id: 'session-web-1',
        user_id: 'user-local-1',
        session_token: 'hashed-session-token-web-1',
        status: 'active',
        device_id: 'web-device-1',
        platform: 'web',
        ip_address: '192.168.1.100',
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        expires_at: new Date(now.getTime() + oneWeek),
        last_activity_at: new Date(now.getTime() - 60 * 1000), // 1 minute ago
      },
      {
        id: 'session-mobile-1',
        user_id: 'user-local-1',
        session_token: 'hashed-session-token-mobile-1',
        status: 'active',
        device_id: 'mobile-device-1',
        platform: 'iOS',
        ip_address: '10.0.0.50',
        user_agent: 'MyApp/1.0.0 (iPhone; iOS 17.0)',
        expires_at: new Date(now.getTime() + oneWeek),
        last_activity_at: new Date(now.getTime() - 5 * 60 * 1000), // 5 minutes ago
      },
      {
        id: 'session-web-2',
        user_id: 'user-local-2',
        session_token: 'hashed-session-token-web-2',
        status: 'active',
        device_id: 'web-device-2',
        platform: 'web',
        ip_address: '203.0.113.45',
        user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        expires_at: new Date(now.getTime() + oneWeek),
        last_activity_at: new Date(now.getTime() - 30 * 60 * 1000), // 30 minutes ago
      },
      {
        id: 'session-google-1',
        user_id: 'user-google-1',
        session_token: 'hashed-session-token-google-1',
        status: 'active',
        device_id: 'android-device-1',
        platform: 'Android',
        ip_address: '198.51.100.78',
        user_agent: 'MyApp/1.0.0 (Android 14; SM-G998B)',
        expires_at: new Date(now.getTime() + oneWeek),
        last_activity_at: new Date(now.getTime() - 15 * 60 * 1000), // 15 minutes ago
      },

      // Expired sessions
      {
        id: 'session-expired-1',
        user_id: 'user-local-3',
        session_token: 'hashed-session-token-expired-1',
        status: 'expired',
        device_id: 'web-device-3',
        platform: 'web',
        ip_address: '172.16.0.25',
        user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        expires_at: new Date(now.getTime() - oneDay),
        last_activity_at: new Date(now.getTime() - oneDay - 60 * 1000),
      },

      // Revoked sessions
      {
        id: 'session-revoked-1',
        user_id: 'user-local-4',
        session_token: 'hashed-session-token-revoked-1',
        status: 'revoked',
        device_id: 'web-device-4',
        platform: 'web',
        ip_address: '10.1.1.100',
        user_agent: 'Mozilla/5.0 (compatible; Safari/537.36)',
        expires_at: new Date(now.getTime() + oneWeek),
        last_activity_at: new Date(now.getTime() - 2 * oneDay),
      },
    ];

    await sessionRepository.save(sessions);
    console.log(`💻 Created ${sessions.length} sessions`);
  }

  async clear(): Promise<void> {
    console.log('🧹 Clearing database...');

    const sessionRepository = this.dataSource.getRepository(AuthSessionEntity);
    const tokenRepository = this.dataSource.getRepository(TokenEntity);
    const userRepository = this.dataSource.getRepository(UserEntity);

    await sessionRepository.delete({});
    await tokenRepository.delete({});
    await userRepository.delete({});

    console.log('✅ Database cleared successfully');
  }
}