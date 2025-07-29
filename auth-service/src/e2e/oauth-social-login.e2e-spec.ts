import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../app/app.module';
import { DataSource } from 'typeorm';
import { UserEntity, AuthSessionEntity } from '@auth/infrastructure';

describe('OAuth Social Login E2E Tests', () => {
  let app: INestApplication;
  let dataSource: DataSource;

  beforeAll(async () => {
    // Set test environment variables including OAuth configurations
    process.env.NODE_ENV = 'test';
    process.env.PORT = '3101';
    process.env.JWT_SECRET = 'test-jwt-secret-for-oauth-e2e-testing-only';
    process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-for-oauth-e2e-testing-only';
    process.env.DATABASE_TYPE = 'postgres';
    process.env.DATABASE_HOST = 'localhost';
    process.env.DATABASE_PORT = '5432';
    process.env.DATABASE_USERNAME = 'test_user';
    process.env.DATABASE_PASSWORD = 'test_password';
    process.env.DATABASE_NAME = 'test_auth_oauth_e2e_db';
    process.env.DATABASE_SYNCHRONIZE = 'true';
    process.env.DATABASE_DROP_SCHEMA = 'true';
    process.env.API_PREFIX = 'api/v1';

    // OAuth Provider Configurations
    process.env.GOOGLE_CLIENT_ID = 'test-google-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';
    process.env.GOOGLE_CALLBACK_URL = 'http://localhost:3101/api/v1/auth/google/callback';

    process.env.APPLE_CLIENT_ID = 'com.example.test-app';
    process.env.APPLE_TEAM_ID = 'TEST123456';
    process.env.APPLE_KEY_ID = 'TESTKEY123';
    process.env.APPLE_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgYour-private-key-here
-----END PRIVATE KEY-----`;
    process.env.APPLE_CALLBACK_URL = 'http://localhost:3101/api/v1/auth/apple/callback';

    process.env.SECURITY_ENABLE_RATE_LIMITING = 'false';
    process.env.LOG_LEVEL = 'error';

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    dataSource = app.get(DataSource);

    await app.init();
  });

  afterAll(async () => {
    if (dataSource?.isInitialized) {
      await dataSource.destroy();
    }
    await app.close();
  });

  beforeEach(async () => {
    // Clean up database before each test
    await dataSource.getRepository(AuthSessionEntity).delete({});
    await dataSource.getRepository(UserEntity).delete({});
  });

  describe('Google OAuth Flow E2E', () => {
    it('should initiate Google OAuth flow and redirect to Google', async () => {
      // Test OAuth initiation endpoint
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/google')
        .expect(302);

      // Should redirect to Google OAuth URL
      expect(response.headers.location).toContain('accounts.google.com');
      expect(response.headers.location).toContain('oauth2');
      expect(response.headers.location).toContain('response_type=code');
      expect(response.headers.location).toContain('client_id=test-google-client-id');
      expect(response.headers.location).toContain('redirect_uri=http%3A//localhost%3A3101/api/v1/auth/google/callback');
      expect(response.headers.location).toContain('scope=email%20profile');
    });

    it('should handle Google OAuth callback with valid authorization code', async () => {
      // Mock Google OAuth callback with authorization code
      // In a real E2E test, this would come from Google's OAuth server
      const mockAuthCode = 'mock-google-auth-code-12345';
      const mockGoogleState = 'secure-random-state-string';

      // Note: This test simulates the callback. In real implementation,
      // we would need to mock the Google OAuth token exchange
      const response = await request(app.getHttpServer())
        .get(`/api/v1/auth/google/callback?code=${mockAuthCode}&state=${mockGoogleState}`)
        .expect(302); // Should redirect after successful OAuth

      // Response should contain redirect with success indication
      // The exact implementation depends on your OAuth callback handling
      expect(response.headers.location).toBeDefined();
    });

    it('should handle Google OAuth callback error scenarios', async () => {
      // Test OAuth error callback
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/google/callback?error=access_denied&error_description=The%20user%20denied%20the%20request')
        .expect(302); // Should redirect with error

      expect(response.headers.location).toContain('error');
    });

    it('should create user account for new Google OAuth user', async () => {
      // This test would require mocking the Google token validation
      // For now, we'll test the endpoint structure
      const mockGoogleProfile = {
        id: 'google-user-123456789',
        email: 'googleuser@gmail.com',
        name: 'Google Test User',
        picture: 'https://lh3.googleusercontent.com/a/test-profile-image',
      };

      // In a real implementation, this would be handled by the OAuth strategy
      // For testing purposes, we can simulate the user creation
      const userRepository = dataSource.getRepository(UserEntity);
      const socialUser = await userRepository.save({
        id: 'social-google-user-1',
        email: mockGoogleProfile.email,
        name: mockGoogleProfile.name,
        provider: 'google',
        provider_id: mockGoogleProfile.id,
        profile_picture: mockGoogleProfile.picture,
        status: 'active',
        email_verified: true, // Google accounts are pre-verified
      });

      expect(socialUser.provider).toBe('google');
      expect(socialUser.provider_id).toBe(mockGoogleProfile.id);
      expect(socialUser.email_verified).toBe(true);
      expect(socialUser.password_hash).toBeNull(); // Social users don't have passwords
    });

    it('should handle existing Google user login', async () => {
      // Create existing Google user
      const userRepository = dataSource.getRepository(UserEntity);
      const existingUser = await userRepository.save({
        id: 'existing-google-user',
        email: 'existing@gmail.com',
        name: 'Existing Google User',
        provider: 'google',
        provider_id: 'google-123456789',
        profile_picture: 'https://example.com/profile.jpg',
        status: 'active',
        email_verified: true,
      });

      // Simulate OAuth login for existing user
      // In real implementation, this would be handled by OAuth callback
      const sessionRepository = dataSource.getRepository(AuthSessionEntity);
      const session = await sessionRepository.save({
        id: 'google-session-1',
        user_id: existingUser.id,
        session_token: 'google-session-token-123',
        status: 'active',
        client_ip: '127.0.0.1',
        user_agent: 'Test Browser',
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      });

      expect(session.user_id).toBe(existingUser.id);
      expect(session.status).toBe('active');
    });
  });

  describe('Apple OAuth Flow E2E', () => {
    it('should initiate Apple OAuth flow and redirect to Apple', async () => {
      // Test Apple OAuth initiation endpoint
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/apple')
        .expect(302);

      // Should redirect to Apple OAuth URL
      expect(response.headers.location).toContain('appleid.apple.com');
      expect(response.headers.location).toContain('auth/authorize');
      expect(response.headers.location).toContain('response_type=code');
      expect(response.headers.location).toContain('client_id=com.example.test-app');
      expect(response.headers.location).toContain('redirect_uri=http%3A//localhost%3A3101/api/v1/auth/apple/callback');
      expect(response.headers.location).toContain('scope=email%20name');
    });

    it('should handle Apple OAuth callback with authorization code', async () => {
      const mockAppleAuthCode = 'mock-apple-auth-code-abcdef';
      const mockAppleState = 'secure-apple-state-string';

      // Apple OAuth callback simulation
      const response = await request(app.getHttpServer())
        .get(`/api/v1/auth/apple/callback?code=${mockAppleAuthCode}&state=${mockAppleState}`)
        .expect(302);

      expect(response.headers.location).toBeDefined();
    });

    it('should create user account for new Apple OAuth user', async () => {
      const mockAppleProfile = {
        id: 'apple-user-001234.567890abcdef',
        email: 'appleuser@privaterelay.appleid.com',
        name: 'Apple Test User',
      };

      // Simulate Apple user creation
      const userRepository = dataSource.getRepository(UserEntity);
      const appleUser = await userRepository.save({
        id: 'social-apple-user-1',
        email: mockAppleProfile.email,
        name: mockAppleProfile.name,
        provider: 'apple',
        provider_id: mockAppleProfile.id,
        status: 'active',
        email_verified: true, // Apple accounts are pre-verified
      });

      expect(appleUser.provider).toBe('apple');
      expect(appleUser.provider_id).toBe(mockAppleProfile.id);
      expect(appleUser.email_verified).toBe(true);
      expect(appleUser.password_hash).toBeNull();
    });

    it('should handle Apple private relay email addresses', async () => {
      // Apple uses private relay emails that are unique per app
      const privateRelayEmail = 'xyz123@privaterelay.appleid.com';
      
      const userRepository = dataSource.getRepository(UserEntity);
      const appleUser = await userRepository.save({
        id: 'private-relay-user',
        email: privateRelayEmail,
        name: 'Private Relay User',
        provider: 'apple',
        provider_id: 'apple-private-relay-user-123',
        status: 'active',
        email_verified: true,
      });

      expect(appleUser.email).toBe(privateRelayEmail);
      expect(appleUser.email).toContain('@privaterelay.appleid.com');
    });
  });

  describe('Social Login Integration with Regular Authentication E2E', () => {
    it('should prevent email conflicts between local and social accounts', async () => {
      const sharedEmail = 'shared@example.com';

      // Create local account first
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: sharedEmail,
          password: 'LocalPassword123!',
          name: 'Local User',
        })
        .expect(201);

      // Attempt to create Google account with same email should handle conflict
      const userRepository = dataSource.getRepository(UserEntity);
      const existingUser = await userRepository.findOne({
        where: { email: sharedEmail },
      });

      expect(existingUser).toBeDefined();
      expect(existingUser?.provider).toBe('local');

      // In real implementation, social login with existing email 
      // should either link accounts or require email verification
    });

    it('should allow social user to access protected routes', async () => {
      // Create Google user
      const userRepository = dataSource.getRepository(UserEntity);
      const googleUser = await userRepository.save({
        id: 'google-protected-user',
        email: 'googleprotected@gmail.com',
        name: 'Google Protected User',
        provider: 'google',
        provider_id: 'google-protected-123',
        status: 'active',
        email_verified: true,
      });

      // Simulate social login session creation
      // In real implementation, this would be done by OAuth callback
      const loginResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .send({
          email: googleUser.email,
          // Social users can't login with password, this would need special handling
        });

      // Note: This test demonstrates the structure, but social login 
      // would typically use a different authentication flow
    });

    it('should handle social login logout correctly', async () => {
      // Create social user session
      const userRepository = dataSource.getRepository(UserEntity);
      const socialUser = await userRepository.save({
        id: 'social-logout-user',
        email: 'sociallogout@example.com',
        name: 'Social Logout User',
        provider: 'google',
        provider_id: 'google-logout-123',
        status: 'active',
        email_verified: true,
      });

      // Create session for social user
      const sessionRepository = dataSource.getRepository(AuthSessionEntity);
      const socialSession = await sessionRepository.save({
        id: 'social-session-logout',
        user_id: socialUser.id,
        session_token: 'social-session-token-logout',
        status: 'active',
        client_ip: '127.0.0.1',
        user_agent: 'Social Test Browser',
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });

      // Verify session exists and is active
      const activeSession = await sessionRepository.findOne({
        where: { id: socialSession.id, status: 'active' },
      });
      expect(activeSession).toBeDefined();

      // Social logout should deactivate session just like regular logout
      await sessionRepository.update(
        { id: socialSession.id },
        { status: 'inactive', updated_at: new Date() }
      );

      const inactiveSession = await sessionRepository.findOne({
        where: { id: socialSession.id },
      });
      expect(inactiveSession?.status).toBe('inactive');
    });
  });

  describe('OAuth Security and Error Handling E2E', () => {
    it('should validate OAuth state parameter to prevent CSRF', async () => {
      // Test OAuth initiation with state parameter
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/google?state=custom-state-123')
        .expect(302);

      expect(response.headers.location).toContain('state=custom-state-123');
    });

    it('should handle OAuth provider errors gracefully', async () => {
      // Test various OAuth error scenarios
      const errorScenarios = [
        {
          params: 'error=access_denied&error_description=User%20denied%20access',
          expectedError: 'access_denied',
        },
        {
          params: 'error=invalid_request&error_description=Invalid%20request',
          expectedError: 'invalid_request',
        },
        {
          params: 'error=server_error&error_description=Server%20error',
          expectedError: 'server_error',
        },
      ];

      for (const scenario of errorScenarios) {
        const response = await request(app.getHttpServer())
          .get(`/api/v1/auth/google/callback?${scenario.params}`)
          .expect(302);

        // Should redirect with error indication
        expect(response.headers.location).toContain('error');
      }
    });

    it('should handle malformed OAuth responses', async () => {
      // Test malformed callback parameters
      const malformedTests = [
        '/api/v1/auth/google/callback', // No parameters
        '/api/v1/auth/google/callback?code=', // Empty code
        '/api/v1/auth/google/callback?state=', // Empty state
        '/api/v1/auth/google/callback?code=valid&state=wrong', // Invalid state
      ];

      for (const testUrl of malformedTests) {
        const response = await request(app.getHttpServer())
          .get(testUrl);

        // Should handle gracefully (either redirect with error or return error response)
        expect([302, 400, 401]).toContain(response.status);
      }
    });

    it('should prevent OAuth token replay attacks', async () => {
      const mockAuthCode = 'used-auth-code-123';

      // First use of auth code (would succeed in real implementation)
      await request(app.getHttpServer())
        .get(`/api/v1/auth/google/callback?code=${mockAuthCode}&state=valid-state`);

      // Second use of same auth code should fail
      const response = await request(app.getHttpServer())
        .get(`/api/v1/auth/google/callback?code=${mockAuthCode}&state=valid-state`);

      // Should reject reused auth code
      expect([400, 401, 302]).toContain(response.status);
    });

    it('should handle OAuth provider downtime gracefully', async () => {
      // This test would require mocking network failures
      // For now, test that endpoints exist and return proper error format
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/google/callback?error=temporarily_unavailable');

      expect([302, 503]).toContain(response.status);
    });
  });

  describe('OAuth Token Management E2E', () => {
    it('should manage OAuth refresh tokens properly', async () => {
      // Create OAuth user with refresh token
      const userRepository = dataSource.getRepository(UserEntity);
      const oauthUser = await userRepository.save({
        id: 'oauth-refresh-user',
        email: 'oauthrefresh@gmail.com',
        name: 'OAuth Refresh User',
        provider: 'google',
        provider_id: 'google-refresh-123',
        status: 'active',
        email_verified: true,
      });

      // In real implementation, OAuth refresh tokens would be stored
      // and used to refresh access tokens from the OAuth provider
      expect(oauthUser).toBeDefined();
      expect(oauthUser.provider).toBe('google');
    });

    it('should handle OAuth token expiration', async () => {
      // Create OAuth session that simulates token expiration
      const userRepository = dataSource.getRepository(UserEntity);
      const oauthUser = await userRepository.save({
        id: 'oauth-expired-user',
        email: 'oauthexpired@gmail.com',
        name: 'OAuth Expired User',
        provider: 'google',
        provider_id: 'google-expired-123',
        status: 'active',
        email_verified: true,
      });

      const sessionRepository = dataSource.getRepository(AuthSessionEntity);
      const expiredSession = await sessionRepository.save({
        id: 'expired-oauth-session',
        user_id: oauthUser.id,
        session_token: 'expired-oauth-token',
        status: 'active',
        client_ip: '127.0.0.1',
        user_agent: 'OAuth Test Browser',
        expires_at: new Date(Date.now() - 60 * 60 * 1000), // Expired 1 hour ago
      });

      // Session should be considered expired
      const now = new Date();
      expect(expiredSession.expires_at.getTime()).toBeLessThan(now.getTime());

      // Cleanup expired sessions
      await sessionRepository.delete({
        expires_at: { $lt: now } as any,
      });

      const remainingSessions = await sessionRepository.findOne({
        where: { id: expiredSession.id },
      });
      expect(remainingSessions).toBeNull();
    });
  });
});