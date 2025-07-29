import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../app/app.module';
import { DataSource } from 'typeorm';
import { UserEntity, TokenEntity, AuthSessionEntity } from '@auth/infrastructure';

describe('Authentication Complete Flow E2E Tests', () => {
  let app: INestApplication;
  let dataSource: DataSource;

  beforeAll(async () => {
    // Set test environment variables
    process.env.NODE_ENV = 'test';
    process.env.PORT = '3100';
    process.env.JWT_SECRET = 'test-jwt-secret-for-e2e-complete-flow-testing-only';
    process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-for-e2e-complete-flow-testing-only';
    process.env.DATABASE_TYPE = 'postgres';
    process.env.DATABASE_HOST = 'localhost';
    process.env.DATABASE_PORT = '5432';
    process.env.DATABASE_USERNAME = 'test_user';
    process.env.DATABASE_PASSWORD = 'test_password';
    process.env.DATABASE_NAME = 'test_auth_complete_e2e_db';
    process.env.DATABASE_SYNCHRONIZE = 'true';
    process.env.DATABASE_DROP_SCHEMA = 'true';
    process.env.API_PREFIX = 'api/v1';
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
    await dataSource.getRepository(TokenEntity).delete({});
    await dataSource.getRepository(UserEntity).delete({});
  });

  describe('Complete User Journey: Registration → Login → Protected Access → Logout', () => {
    it('should complete full authentication flow successfully', async () => {
      const userEmail = 'complete@example.com';
      const userPassword = 'SecurePassword123!';
      const userName = 'Complete Test User';

      // Step 1: User Registration
      const registrationResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: userEmail,
          password: userPassword,
          name: userName,
        })
        .expect(201);

      expect(registrationResponse.body.success).toBe(true);
      expect(registrationResponse.body.data.user.email).toBe(userEmail);
      expect(registrationResponse.body.data.tokens.accessToken).toBeDefined();
      expect(registrationResponse.body.data.tokens.refreshToken).toBeDefined();

      const registrationAccessToken = registrationResponse.body.data.tokens.accessToken;
      const registrationRefreshToken = registrationResponse.body.data.tokens.refreshToken;
      const userId = registrationResponse.body.data.user.id;

      // Step 2: Verify user can access protected resource with registration token
      const initialProfileResponse = await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${registrationAccessToken}`)
        .expect(200);

      expect(initialProfileResponse.body.data.user.email).toBe(userEmail);
      expect(initialProfileResponse.body.data.user.name).toBe(userName);

      // Step 3: User Logout (invalidates current session)
      await request(app.getHttpServer())
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${registrationAccessToken}`)
        .expect(200);

      // Step 4: Verify logout invalidated the token
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${registrationAccessToken}`)
        .expect(401);

      // Step 5: User Login with credentials
      const loginResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .send({
          email: userEmail,
          password: userPassword,
        })
        .expect(200);

      expect(loginResponse.body.success).toBe(true);
      expect(loginResponse.body.data.user.id).toBe(userId);
      expect(loginResponse.body.data.tokens.accessToken).toBeDefined();
      expect(loginResponse.body.data.tokens.refreshToken).toBeDefined();

      const loginAccessToken = loginResponse.body.data.tokens.accessToken;
      const loginRefreshToken = loginResponse.body.data.tokens.refreshToken;

      // Step 6: Access protected resource with new login token
      const profileResponse = await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${loginAccessToken}`)
        .expect(200);

      expect(profileResponse.body.data.user.email).toBe(userEmail);

      // Step 7: Update user profile
      const updatedName = 'Updated Complete User';
      const profilePicture = 'https://example.com/profile.jpg';

      const updateResponse = await request(app.getHttpServer())
        .put('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${loginAccessToken}`)
        .send({
          name: updatedName,
          profilePicture: profilePicture,
        })
        .expect(200);

      expect(updateResponse.body.data.user.name).toBe(updatedName);
      expect(updateResponse.body.data.user.profilePicture).toBe(profilePicture);

      // Step 8: Refresh tokens
      const refreshResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/refresh')
        .send({
          refreshToken: loginRefreshToken,
        })
        .expect(200);

      expect(refreshResponse.body.data.tokens.accessToken).toBeDefined();
      expect(refreshResponse.body.data.tokens.refreshToken).toBeDefined();
      expect(refreshResponse.body.data.tokens.accessToken).not.toBe(loginAccessToken);

      const newAccessToken = refreshResponse.body.data.tokens.accessToken;

      // Step 9: Verify new token works and profile was updated
      const finalProfileResponse = await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${newAccessToken}`)
        .expect(200);

      expect(finalProfileResponse.body.data.user.name).toBe(updatedName);
      expect(finalProfileResponse.body.data.user.profilePicture).toBe(profilePicture);

      // Step 10: Final logout
      await request(app.getHttpServer())
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${newAccessToken}`)
        .expect(200);

      // Step 11: Verify final logout invalidated the token
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${newAccessToken}`)
        .expect(401);

      // Verify database state
      const userRepository = dataSource.getRepository(UserEntity);
      const finalUser = await userRepository.findOne({ where: { id: userId } });
      expect(finalUser?.name).toBe(updatedName);
      expect(finalUser?.profile_picture).toBe(profilePicture);

      const sessionRepository = dataSource.getRepository(AuthSessionEntity);
      const activeSessions = await sessionRepository.find({
        where: { user_id: userId, status: 'active' },
      });
      expect(activeSessions).toHaveLength(0); // All sessions should be inactive
    });
  });

  describe('Multiple Session Management E2E', () => {
    let userId: string;
    const userEmail = 'multisession@example.com';
    const userPassword = 'SecurePassword123!';

    beforeEach(async () => {
      // Register user for multi-session tests
      const registrationResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: userEmail,
          password: userPassword,
          name: 'Multi Session User',
        });

      userId = registrationResponse.body.data.user.id;

      // Logout from registration session
      await request(app.getHttpServer())
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${registrationResponse.body.data.tokens.accessToken}`);
    });

    it('should handle multiple concurrent sessions', async () => {
      // Create multiple login sessions
      const loginPromises = Array.from({ length: 3 }, (_, i) =>
        request(app.getHttpServer())
          .post('/api/v1/auth/login')
          .send({
            email: userEmail,
            password: userPassword,
          })
          .set('User-Agent', `TestAgent-${i}`)
          .set('X-Forwarded-For', `192.168.1.${i + 1}`)
      );

      const loginResponses = await Promise.all(loginPromises);

      // All logins should succeed
      loginResponses.forEach((response, i) => {
        expect(response.status).toBe(200);
        expect(response.body.data.tokens.accessToken).toBeDefined();
      });

      const accessTokens = loginResponses.map(r => r.body.data.tokens.accessToken);

      // All tokens should work simultaneously
      const profilePromises = accessTokens.map(token =>
        request(app.getHttpServer())
          .get('/api/v1/auth/profile')
          .set('Authorization', `Bearer ${token}`)
      );

      const profileResponses = await Promise.all(profilePromises);
      profileResponses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.data.user.email).toBe(userEmail);
      });

      // Verify multiple active sessions in database
      const sessionRepository = dataSource.getRepository(AuthSessionEntity);
      const activeSessions = await sessionRepository.find({
        where: { user_id: userId, status: 'active' },
      });
      expect(activeSessions.length).toBe(3);

      // Logout from one session
      await request(app.getHttpServer())
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${accessTokens[0]}`)
        .expect(200);

      // First token should be invalid, others should still work
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${accessTokens[0]}`)
        .expect(401);

      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${accessTokens[1]}`)
        .expect(200);

      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${accessTokens[2]}`)
        .expect(200);

      // Verify session count reduced
      const remainingSessions = await sessionRepository.find({
        where: { user_id: userId, status: 'active' },
      });
      expect(remainingSessions.length).toBe(2);
    });
  });

  describe('Token Lifecycle E2E', () => {
    let userId: string;
    let accessToken: string;
    let refreshToken: string;

    beforeEach(async () => {
      const registrationResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'tokenlifecycle@example.com',
          password: 'SecurePassword123!',
          name: 'Token Lifecycle User',
        });

      userId = registrationResponse.body.data.user.id;
      accessToken = registrationResponse.body.data.tokens.accessToken;
      refreshToken = registrationResponse.body.data.tokens.refreshToken;
    });

    it('should handle complete token refresh cycle', async () => {
      // Use initial tokens
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      // Refresh tokens multiple times
      let currentRefreshToken = refreshToken;
      let currentAccessToken = accessToken;

      for (let i = 0; i < 3; i++) {
        const refreshResponse = await request(app.getHttpServer())
          .post('/api/v1/auth/refresh')
          .send({
            refreshToken: currentRefreshToken,
          })
          .expect(200);

        const newAccessToken = refreshResponse.body.data.tokens.accessToken;
        const newRefreshToken = refreshResponse.body.data.tokens.refreshToken;

        // New tokens should be different
        expect(newAccessToken).not.toBe(currentAccessToken);
        expect(newRefreshToken).not.toBe(currentRefreshToken);

        // Old access token should be invalid
        await request(app.getHttpServer())
          .get('/api/v1/auth/profile')
          .set('Authorization', `Bearer ${currentAccessToken}`)
          .expect(401);

        // New access token should work
        await request(app.getHttpServer())
          .get('/api/v1/auth/profile')
          .set('Authorization', `Bearer ${newAccessToken}`)
          .expect(200);

        // Old refresh token should be invalid
        if (i > 0) {
          await request(app.getHttpServer())
            .post('/api/v1/auth/refresh')
            .send({
              refreshToken: currentRefreshToken,
            })
            .expect(401);
        }

        currentAccessToken = newAccessToken;
        currentRefreshToken = newRefreshToken;
      }

      // Verify final tokens work
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${currentAccessToken}`)
        .expect(200);

      // Verify token rotation in database
      const tokenRepository = dataSource.getRepository(TokenEntity);
      const userTokens = await tokenRepository.find({
        where: { user_id: userId },
        order: { created_at: 'DESC' },
      });

      // Should have tokens from all refresh cycles
      expect(userTokens.length).toBeGreaterThan(2);
    });

    it('should handle refresh token reuse attack prevention', async () => {
      // Use refresh token once
      const firstRefreshResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/refresh')
        .send({
          refreshToken: refreshToken,
        })
        .expect(200);

      const newRefreshToken = firstRefreshResponse.body.data.tokens.refreshToken;

      // Try to reuse old refresh token (should fail)
      await request(app.getHttpServer())
        .post('/api/v1/auth/refresh')
        .send({
          refreshToken: refreshToken,
        })
        .expect(401);

      // New refresh token should still work
      await request(app.getHttpServer())
        .post('/api/v1/auth/refresh')
        .send({
          refreshToken: newRefreshToken,
        })
        .expect(200);
    });
  });

  describe('Error Recovery and Edge Cases E2E', () => {
    it('should handle registration → login → failed refresh → re-login flow', async () => {
      const userEmail = 'errorrecovery@example.com';
      const userPassword = 'SecurePassword123!';

      // Register user
      const registrationResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: userEmail,
          password: userPassword,
          name: 'Error Recovery User',
        })
        .expect(201);

      const userId = registrationResponse.body.data.user.id;
      let refreshToken = registrationResponse.body.data.tokens.refreshToken;

      // Logout to invalidate registration session
      await request(app.getHttpServer())
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${registrationResponse.body.data.tokens.accessToken}`);

      // Login again
      const loginResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .send({
          email: userEmail,
          password: userPassword,
        })
        .expect(200);

      // Try to refresh with old (invalid) refresh token
      await request(app.getHttpServer())
        .post('/api/v1/auth/refresh')
        .send({
          refreshToken: refreshToken,
        })
        .expect(401);

      // User should be able to login again after failed refresh
      const secondLoginResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .send({
          email: userEmail,
          password: userPassword,
        })
        .expect(200);

      expect(secondLoginResponse.body.data.user.id).toBe(userId);

      // New session should work normally
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${secondLoginResponse.body.data.tokens.accessToken}`)
        .expect(200);
    });

    it('should handle concurrent logout scenarios', async () => {
      const userEmail = 'concurrent@example.com';
      const userPassword = 'SecurePassword123!';

      // Register user
      const registrationResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: userEmail,
          password: userPassword,
          name: 'Concurrent User',
        });

      const accessToken = registrationResponse.body.data.tokens.accessToken;

      // Try multiple concurrent logouts
      const logoutPromises = Array.from({ length: 3 }, () =>
        request(app.getHttpServer())
          .post('/api/v1/auth/logout')
          .set('Authorization', `Bearer ${accessToken}`)
      );

      const logoutResponses = await Promise.all(logoutPromises);

      // First logout should succeed, others might succeed or fail gracefully
      const successfulLogouts = logoutResponses.filter(r => r.status === 200);
      expect(successfulLogouts.length).toBeGreaterThan(0);

      // Token should be invalid after logout
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(401);
    });

    it('should handle malformed request data gracefully', async () => {
      // Test with various malformed inputs
      const malformedTests = [
        {
          endpoint: '/api/v1/auth/register',
          method: 'post',
          data: { email: 'invalid', password: '123', name: '' },
          expectedStatus: 400,
        },
        {
          endpoint: '/api/v1/auth/login',
          method: 'post',
          data: { email: 'missing@password.com' },
          expectedStatus: 400,
        },
        {
          endpoint: '/api/v1/auth/refresh',
          method: 'post',
          data: { refreshToken: 'obviously-invalid-token' },
          expectedStatus: 401,
        },
      ];

      for (const test of malformedTests) {
        const response = await request(app.getHttpServer())
          [test.method](test.endpoint)
          .send(test.data);

        expect(response.status).toBe(test.expectedStatus);
        expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
        expect(response.body.timestamp).toBeDefined();
      }
    });
  });

  describe('Performance and Load E2E', () => {
    it('should handle burst of registration requests', async () => {
      const registrationPromises = Array.from({ length: 10 }, (_, i) =>
        request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            email: `burst${i}@example.com`,
            password: 'SecurePassword123!',
            name: `Burst User ${i}`,
          })
      );

      const start = Date.now();
      const responses = await Promise.all(registrationPromises);
      const duration = Date.now() - start;

      // All should succeed
      responses.forEach(response => {
        expect(response.status).toBe(201);
      });

      // Should complete within reasonable time (adjust threshold as needed)
      expect(duration).toBeLessThan(5000); // 5 seconds

      // Verify all users were created
      const userRepository = dataSource.getRepository(UserEntity);
      const burstUsers = await userRepository.count({
        where: { email: { $like: 'burst%@example.com' } as any },
      });
      expect(burstUsers).toBe(10);
    });

    it('should maintain session consistency under load', async () => {
      // Create a user first
      const registrationResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'loadtest@example.com',
          password: 'SecurePassword123!',
          name: 'Load Test User',
        });

      const accessToken = registrationResponse.body.data.tokens.accessToken;

      // Make multiple concurrent profile requests
      const profilePromises = Array.from({ length: 20 }, () =>
        request(app.getHttpServer())
          .get('/api/v1/auth/profile')
          .set('Authorization', `Bearer ${accessToken}`)
      );

      const responses = await Promise.all(profilePromises);

      // All should succeed with consistent data
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.data.user.email).toBe('loadtest@example.com');
        expect(response.body.data.user.name).toBe('Load Test User');
      });
    });
  });
});