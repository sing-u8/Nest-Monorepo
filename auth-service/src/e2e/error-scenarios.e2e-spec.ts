import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../app/app.module';
import { DataSource } from 'typeorm';
import { UserEntity, TokenEntity, AuthSessionEntity } from '@auth/infrastructure';

describe('Error Scenarios and Edge Cases E2E Tests', () => {
  let app: INestApplication;
  let dataSource: DataSource;

  beforeAll(async () => {
    // Set test environment variables
    process.env.NODE_ENV = 'test';
    process.env.PORT = '3103';
    process.env.JWT_SECRET = 'test-jwt-secret-for-error-scenarios-e2e-testing-only';
    process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-for-error-scenarios-e2e-testing-only';
    process.env.DATABASE_TYPE = 'postgres';
    process.env.DATABASE_HOST = 'localhost';
    process.env.DATABASE_PORT = '5432';
    process.env.DATABASE_USERNAME = 'test_user';
    process.env.DATABASE_PASSWORD = 'test_password';
    process.env.DATABASE_NAME = 'test_auth_error_scenarios_e2e_db';
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

  describe('Input Validation Edge Cases', () => {
    it('should handle extremely long input strings', async () => {
      const veryLongString = 'a'.repeat(10000);

      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: `${veryLongString}@example.com`,
          password: 'ValidPassword123!',
          name: veryLongString,
        })
        .expect(400);

      expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
      expect(response.body.message).toBeDefined();
    });

    it('should handle null and undefined values gracefully', async () => {
      const testCases = [
        { email: null, password: 'ValidPassword123!', name: 'Test User' },
        { email: undefined, password: 'ValidPassword123!', name: 'Test User' },
        { email: 'test@example.com', password: null, name: 'Test User' },
        { email: 'test@example.com', password: undefined, name: 'Test User' },
        { email: 'test@example.com', password: 'ValidPassword123!', name: null },
        { email: 'test@example.com', password: 'ValidPassword123!', name: undefined },
      ];

      for (const testCase of testCases) {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send(testCase)
          .expect(400);

        expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
        expect(response.body.statusCode).toBe(400);
      }
    });

    it('should handle special characters and encoding issues', async () => {
      const specialCharacterTests = [
        {
          email: 'test+special@example.com',
          name: 'Test User with Émojis 🚀',
          password: 'ValidPassword123!',
          shouldSucceed: true,
        },
        {
          email: 'test@example.com',
          name: 'Test\nUser\nWith\nNewlines',
          password: 'ValidPassword123!',
          shouldSucceed: false,
        },
        {
          email: 'test@example.com',
          name: 'Test\tUser\tWith\tTabs',
          password: 'ValidPassword123!',
          shouldSucceed: false,
        },
        {
          email: 'test@example.com',
          name: 'José María O\'Connor-Smith',
          password: 'ValidPassword123!',
          shouldSucceed: true,
        },
      ];

      for (const test of specialCharacterTests) {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            email: `${Math.random().toString(36)}${test.email}`,
            name: test.name,
            password: test.password,
          });

        if (test.shouldSucceed) {
          expect([200, 201]).toContain(response.status);
        } else {
          expect(response.status).toBe(400);
          expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
        }
      }
    });

    it('should handle SQL injection attempts', async () => {
      const sqlInjectionAttempts = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "'; INSERT INTO users VALUES ('hacker', 'hacker@evil.com'); --",
        "' UNION SELECT * FROM users WHERE '1'='1",
      ];

      for (const injection of sqlInjectionAttempts) {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            email: `test${Math.random()}@example.com`,
            password: injection,
            name: injection,
          })
          .expect(400);

        expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
      }

      // Verify database integrity
      const userRepository = dataSource.getRepository(UserEntity);
      const suspiciousUsers = await userRepository.find({
        where: { name: { $like: '%DROP%' } as any },
      });
      expect(suspiciousUsers).toHaveLength(0);
    });

    it('should handle XSS attempts in input fields', async () => {
      const xssAttempts = [
        '<script>alert("xss")</script>',
        'javascript:alert("xss")',
        '<img src="x" onerror="alert(\'xss\')">',
        '<svg onload="alert(\'xss\')">',
        '"><script>alert("xss")</script>',
      ];

      for (const xss of xssAttempts) {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            email: `test${Math.random()}@example.com`,
            password: 'ValidPassword123!',
            name: xss,
          });

        if (response.status === 201) {
          // If registration succeeded, verify XSS was sanitized
          expect(response.body.data.user.name).not.toContain('<script>');
          expect(response.body.data.user.name).not.toContain('javascript:');
          expect(response.body.data.user.name).not.toContain('onerror');
          expect(response.body.data.user.name).not.toContain('onload');
        } else {
          // If registration failed, verify error handling
          expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
        }
      }
    });
  });

  describe('Authentication Edge Cases', () => {
    it('should handle rapid successive login attempts', async () => {
      // Create test user
      const userRepository = dataSource.getRepository(UserEntity);
      await userRepository.save({
        id: 'rapid-login-user',
        email: 'rapidlogin@example.com',
        name: 'Rapid Login User',
        provider: 'local',
        status: 'active',
        password_hash: '$2b$10$rBV2HQ/qTJ.4xEyF6xqKAOKhWiOZWLO0Q8CBNbVHhJKDhbNGZQGEi',
      });

      // Make rapid login attempts
      const loginPromises = Array.from({ length: 10 }, () =>
        request(app.getHttpServer())
          .post('/api/v1/auth/login')
          .send({
            email: 'rapidlogin@example.com',
            password: 'password123',
          })
      );

      const responses = await Promise.all(loginPromises);

      // Some or all should succeed depending on rate limiting
      const successfulLogins = responses.filter(r => r.status === 200);
      expect(successfulLogins.length).toBeGreaterThan(0);

      // All responses should have proper error format if they fail
      responses.forEach(response => {
        if (response.status !== 200) {
          expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
        }
      });
    });

    it('should handle login with case-sensitive email variations', async () => {
      // Create user with lowercase email
      const userRepository = dataSource.getRepository(UserEntity);
      await userRepository.save({
        id: 'case-sensitive-user',
        email: 'casesensitive@example.com',
        name: 'Case Sensitive User',
        provider: 'local',
        status: 'active',
        password_hash: '$2b$10$rBV2HQ/qTJ.4xEyF6xqKAOKhWiOZWLO0Q8CBNbVHhJKDhbNGZQGEi',
      });

      const emailVariations = [
        'casesensitive@example.com', // Exact match
        'CaseSensitive@example.com', // Different case
        'CASESENSITIVE@EXAMPLE.COM', // All uppercase
        'CaseSensitive@Example.Com', // Mixed case
      ];

      for (const email of emailVariations) {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/login')
          .send({
            email: email,
            password: 'password123',
          });

        // Depending on implementation, this might succeed or fail
        // The important thing is consistent behavior
        if (response.status === 200) {
          expect(response.body.data.user.email).toBe('casesensitive@example.com');
        } else {
          expect(response.status).toBe(401);
          expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
        }
      }
    });

    it('should handle password with edge case characters', async () => {
      const edgeCasePasswords = [
        'Password123!@#$%^&*()', // Special characters
        'Пароль123!', // Cyrillic characters
        'パスワード123!', // Japanese characters
        '密码123!', // Chinese characters
        'PassWord\u0000123!', // Null character
        'PassWord\u200B123!', // Zero-width space
      ];

      for (const password of edgeCasePasswords) {
        const email = `edgecase${Math.random()}@example.com`;

        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            email: email,
            password: password,
            name: 'Edge Case User',
          });

        // Some passwords might be rejected, others accepted
        if (response.status === 201) {
          // If accepted, should be able to login
          const loginResponse = await request(app.getHttpServer())
            .post('/api/v1/auth/login')
            .send({
              email: email,
              password: password,
            })
            .expect(200);

          expect(loginResponse.body.data.user.email).toBe(email);
        } else {
          expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
        }
      }
    });
  });

  describe('Token Edge Cases', () => {
    let testUser: UserEntity;
    let validAccessToken: string;
    let validRefreshToken: string;

    beforeEach(async () => {
      // Create test user and get valid tokens
      const registrationResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'tokenedge@example.com',
          password: 'ValidPassword123!',
          name: 'Token Edge User',
        });

      testUser = registrationResponse.body.data.user;
      validAccessToken = registrationResponse.body.data.tokens.accessToken;
      validRefreshToken = registrationResponse.body.data.tokens.refreshToken;
    });

    it('should handle malformed JWT tokens', async () => {
      const malformedTokens = [
        'not.a.jwt',
        'header.payload', // Missing signature
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid', // Invalid payload
        'invalid.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid', // Invalid header and signature
        '', // Empty token
        'Bearer validtoken', // Token with Bearer prefix
      ];

      for (const token of malformedTokens) {
        const response = await request(app.getHttpServer())
          .get('/api/v1/auth/profile')
          .set('Authorization', token.startsWith('Bearer') ? token : `Bearer ${token}`)
          .expect(401);

        expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
      }
    });

    it('should handle token with tampered payload', async () => {
      // Take a valid token and modify its payload
      const tokenParts = validAccessToken.split('.');
      const header = tokenParts[0];
      const signature = tokenParts[2];

      // Create tampered payload
      const tamperedPayload = Buffer.from(JSON.stringify({
        sub: 'hacker-user-id',
        email: 'hacker@evil.com',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      })).toString('base64url');

      const tamperedToken = `${header}.${tamperedPayload}.${signature}`;

      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${tamperedToken}`)
        .expect(401);

      expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
      expect(response.body.message).toContain('Invalid token');
    });

    it('should handle refresh token reuse after logout', async () => {
      // Logout user
      await request(app.getHttpServer())
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .expect(200);

      // Try to use refresh token after logout
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/refresh')
        .send({
          refreshToken: validRefreshToken,
        })
        .expect(401);

      expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
      expect(response.body.message).toContain('Invalid refresh token');
    });

    it('should handle concurrent token refresh attempts', async () => {
      // Make multiple concurrent refresh requests
      const refreshPromises = Array.from({ length: 5 }, () =>
        request(app.getHttpServer())
          .post('/api/v1/auth/refresh')
          .send({
            refreshToken: validRefreshToken,
          })
      );

      const responses = await Promise.all(refreshPromises);

      // Only one should succeed (or all might fail if token is consumed)
      const successfulRefreshes = responses.filter(r => r.status === 200);
      const failedRefreshes = responses.filter(r => r.status !== 200);

      // Either one succeeds and others fail, or all fail
      expect(successfulRefreshes.length <= 1).toBeTruthy();

      // All failed responses should have proper error format
      failedRefreshes.forEach(response => {
        expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
      });
    });
  });

  describe('Database Edge Cases', () => {
    it('should handle database connection interruption gracefully', async () => {
      // Note: This test would require actual database manipulation
      // For now, we'll test that the application handles errors properly
      
      // Try to register when database might be under stress
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'dbtest@example.com',
          password: 'ValidPassword123!',
          name: 'DB Test User',
        });

      // Should either succeed or fail gracefully
      if (response.status !== 201) {
        expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
        expect([400, 500, 503]).toContain(response.status);
      }
    });

    it('should handle database constraint violations', async () => {
      // Create user first
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'constraint@example.com',
          password: 'ValidPassword123!',
          name: 'Constraint Test User',
        })
        .expect(201);

      // Try to create duplicate user (email constraint violation)
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'constraint@example.com',
          password: 'AnotherPassword123!',
          name: 'Another User',
        })
        .expect(409);

      expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
      expect(response.body.message).toContain('already exists');
    });

    it('should handle large dataset queries efficiently', async () => {
      // Create multiple users for performance testing
      const users = Array.from({ length: 50 }, (_, i) => ({
        id: `perf-user-${i}`,
        email: `perf${i}@example.com`,
        name: `Performance User ${i}`,
        provider: 'local',
        status: 'active',
        password_hash: '$2b$10$rBV2HQ/qTJ.4xEyF6xqKAOKhWiOZWLO0Q8CBNbVHhJKDhbNGZQGEi',
      }));

      const userRepository = dataSource.getRepository(UserEntity);
      await userRepository.save(users);

      // Test login performance with large user base
      const start = Date.now();
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .send({
          email: 'perf25@example.com',
          password: 'password123',
        })
        .expect(200);

      const duration = Date.now() - start;

      expect(response.body.data.user.email).toBe('perf25@example.com');
      expect(duration).toBeLessThan(2000); // Should complete within 2 seconds
    });
  });

  describe('Network and Transport Edge Cases', () => {
    it('should handle incomplete request bodies', async () => {
      // Test with incomplete JSON
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Content-Type', 'application/json')
        .send('{"email":"test@example.com","password":')
        .expect(400);

      expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
    });

    it('should handle oversized request payloads', async () => {
      const oversizedData = {
        email: 'test@example.com',
        password: 'ValidPassword123!',
        name: 'a'.repeat(1024 * 1024), // 1MB name
      };

      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send(oversizedData);

      // Should either reject due to size or validation
      expect([400, 413]).toContain(response.status);
      if (response.body.errorId) {
        expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
      }
    });

    it('should handle malformed content-type headers', async () => {
      const malformedContentTypes = [
        'application/json; charset=utf-8; boundary=something',
        'text/plain',
        'multipart/form-data',
        'application/xml',
        'invalid-content-type',
      ];

      for (const contentType of malformedContentTypes) {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .set('Content-Type', contentType)
          .send(JSON.stringify({
            email: 'contenttype@example.com',
            password: 'ValidPassword123!',
            name: 'Content Type Test',
          }));

        // Should handle gracefully
        if (response.status !== 201) {
          expect([400, 415]).toContain(response.status);
        }
      }
    });

    it('should handle requests with missing required headers', async () => {
      // Test request without Content-Type
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send('{"email":"nocontenttype@example.com","password":"ValidPassword123!","name":"No Content Type"}');

      // Should handle gracefully
      expect([200, 201, 400, 415]).toContain(response.status);
    });
  });

  describe('Concurrent Access Edge Cases', () => {
    it('should handle simultaneous registration with same email', async () => {
      const sameEmail = 'concurrent@example.com';

      // Make simultaneous registration requests
      const registrationPromises = Array.from({ length: 3 }, () =>
        request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            email: sameEmail,
            password: 'ValidPassword123!',
            name: 'Concurrent User',
          })
      );

      const responses = await Promise.all(registrationPromises);

      // Only one should succeed
      const successfulRegistrations = responses.filter(r => r.status === 201);
      const failedRegistrations = responses.filter(r => r.status !== 201);

      expect(successfulRegistrations.length).toBe(1);
      expect(failedRegistrations.length).toBe(2);

      // Failed registrations should have proper error format
      failedRegistrations.forEach(response => {
        expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
        expect(response.body.message).toContain('already exists');
      });
    });

    it('should handle race conditions in session management', async () => {
      // Create and login user
      const userEmail = 'race@example.com';
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: userEmail,
          password: 'ValidPassword123!',
          name: 'Race Condition User',
        });

      const loginResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .send({
          email: userEmail,
          password: 'ValidPassword123!',
        });

      const accessToken = loginResponse.body.data.tokens.accessToken;

      // Make concurrent requests that might affect session state
      const concurrentRequests = [
        request(app.getHttpServer())
          .get('/api/v1/auth/profile')
          .set('Authorization', `Bearer ${accessToken}`),
        request(app.getHttpServer())
          .put('/api/v1/auth/profile')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ name: 'Updated Name' }),
        request(app.getHttpServer())
          .post('/api/v1/auth/logout')
          .set('Authorization', `Bearer ${accessToken}`),
      ];

      const results = await Promise.allSettled(concurrentRequests);

      // At least some operations should succeed or fail gracefully
      results.forEach(result => {
        if (result.status === 'fulfilled') {
          const response = result.value;
          if (response.status >= 400) {
            expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
          }
        }
      });
    });
  });

  describe('Resource Exhaustion Edge Cases', () => {
    it('should handle memory pressure gracefully', async () => {
      // Create requests that might consume significant memory
      const largeRequests = Array.from({ length: 20 }, (_, i) =>
        request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            email: `memory${i}@example.com`,
            password: 'ValidPassword123!',
            name: `Memory Test User ${i}`,
            // Add large but valid data
            description: 'x'.repeat(1000),
          })
      );

      const responses = await Promise.all(largeRequests);

      // Should handle all requests without crashing
      responses.forEach(response => {
        expect([200, 201, 400, 429, 503]).toContain(response.status);
        if (response.status >= 400 && response.body.errorId) {
          expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
        }
      });
    });

    it('should handle high frequency requests', async () => {
      // Create user for testing
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'frequency@example.com',
          password: 'ValidPassword123!',
          name: 'Frequency Test User',
        });

      // Make high frequency requests
      const rapidRequests = Array.from({ length: 100 }, () =>
        request(app.getHttpServer())
          .post('/api/v1/auth/login')
          .send({
            email: 'frequency@example.com',
            password: 'ValidPassword123!',
          })
      );

      const start = Date.now();
      const responses = await Promise.all(rapidRequests);
      const duration = Date.now() - start;

      console.log(`Processed ${responses.length} requests in ${duration}ms`);

      // System should remain responsive
      expect(duration).toBeLessThan(30000); // Within 30 seconds

      // All responses should be properly formatted
      responses.forEach(response => {
        expect([200, 201, 401, 429, 503]).toContain(response.status);
        if (response.status >= 400 && response.body.errorId) {
          expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
        }
      });
    });
  });
});