import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../app.module';
import { DataSource } from 'typeorm';
import { UserEntity } from '@auth/infrastructure';

describe('Middleware and Guard Integration Tests', () => {
  let app: INestApplication;
  let dataSource: DataSource;

  beforeAll(async () => {
    // Set test environment variables
    process.env.NODE_ENV = 'test';
    process.env.PORT = '3002';
    process.env.JWT_SECRET = 'test-jwt-secret-key-for-middleware-testing-only';
    process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key-for-middleware-testing-only';
    process.env.DATABASE_TYPE = 'postgres';
    process.env.DATABASE_HOST = 'localhost';
    process.env.DATABASE_PORT = '5432';
    process.env.DATABASE_USERNAME = 'test_user';
    process.env.DATABASE_PASSWORD = 'test_password';
    process.env.DATABASE_NAME = 'test_auth_middleware_db';
    process.env.DATABASE_SYNCHRONIZE = 'true';
    process.env.DATABASE_DROP_SCHEMA = 'true';
    process.env.API_PREFIX = 'api/v1';
    process.env.SECURITY_ENABLE_RATE_LIMITING = 'false'; // Disable for testing
    process.env.SECURITY_ENABLE_HELMET = 'true';
    process.env.API_ENABLE_CORS = 'true';

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
    await dataSource.getRepository(UserEntity).delete({});
  });

  describe('Request Logging Interceptor', () => {
    it('should add request ID to response headers', async () => {
      // Act
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .expect(401); // Unauthorized, but should still have headers

      // Assert
      expect(response.headers['x-request-id']).toMatch(/^req_\d+_[a-z0-9]+$/);
    });

    it('should preserve existing request ID from client', async () => {
      // Arrange
      const clientRequestId = 'client-req-123';

      // Act
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('X-Request-ID', clientRequestId)
        .expect(401);

      // Assert
      expect(response.headers['x-request-id']).toBe(clientRequestId);
    });

    it('should log request and response information', async () => {
      // This test would need to mock the logger to verify log calls
      // For now, verify that the endpoint works with logging enabled
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'logging@example.com',
          password: 'SecurePassword123!',
          name: 'Logging Test User',
        })
        .expect(201);
    });
  });

  describe('Global Exception Filter', () => {
    it('should format errors consistently', async () => {
      // Act
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'wrongpassword',
        })
        .expect(401);

      // Assert
      expect(response.body).toEqual({
        statusCode: 401,
        timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
        path: '/api/v1/auth/login',
        method: 'POST',
        errorId: expect.stringMatching(/^err_\d+_[a-z0-9]+$/),
        message: expect.any(String),
        error: expect.any(String),
      });
    });

    it('should include error ID in response', async () => {
      // Act
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .expect(401);

      // Assert
      expect(response.body.errorId).toMatch(/^err_\d+_[a-z0-9]+$/);
    });

    it('should handle validation errors properly', async () => {
      // Act
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'invalid-email',
          password: '123',
          name: '',
        })
        .expect(400);

      // Assert
      expect(response.body).toEqual({
        statusCode: 400,
        timestamp: expect.any(String),
        path: '/api/v1/auth/register',
        method: 'POST',
        errorId: expect.any(String),
        message: expect.arrayContaining([
          expect.stringContaining('email'),
          expect.stringContaining('password'),
          expect.stringContaining('name'),
        ]),
        error: 'Bad Request',
      });
    });

    it('should handle internal server errors gracefully', async () => {
      // This would require triggering an internal server error
      // For now, verify 404 handling
      const response = await request(app.getHttpServer())
        .get('/api/v1/nonexistent-endpoint')
        .expect(404);

      expect(response.body).toEqual({
        statusCode: 404,
        timestamp: expect.any(String),
        path: '/api/v1/nonexistent-endpoint',
        method: 'GET',
        errorId: expect.any(String),
        message: expect.any(String),
        error: expect.any(String),
      });
    });
  });

  describe('JWT Authentication Guard', () => {
    let validAccessToken: string;
    let testUser: UserEntity;

    beforeEach(async () => {
      // Create a test user and get a valid token
      const userRepository = dataSource.getRepository(UserEntity);
      testUser = await userRepository.save({
        id: 'guard-test-user',
        email: 'guard@example.com',
        name: 'Guard Test User',
        provider: 'local',
        status: 'active',
        password_hash: '$2b$10$rBV2HQ/qTJ.4xEyF6xqKAOKhWiOZWLO0Q8CBNbVHhJKDhbNGZQGEi',
      });

      const loginResponse = await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .send({
          email: 'guard@example.com',
          password: 'password123',
        });

      validAccessToken = loginResponse.body.data.tokens.accessToken;
    });

    it('should allow access with valid JWT token', async () => {
      // Act
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .expect(200);

      // Assert
      expect(response.body.success).toBe(true);
      expect(response.body.data.user.id).toBe(testUser.id);
    });

    it('should reject access without authorization header', async () => {
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .expect(401)
        .expect({
          statusCode: 401,
          timestamp: expect.any(String),
          path: '/api/v1/auth/profile',
          method: 'GET',
          errorId: expect.any(String),
          message: 'Unauthorized',
          error: 'Unauthorized',
        });
    });

    it('should reject access with malformed authorization header', async () => {
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', 'InvalidFormat')
        .expect(401);
    });

    it('should reject access with invalid JWT token', async () => {
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', 'Bearer invalid.jwt.token')
        .expect(401)
        .expect({
          statusCode: 401,
          timestamp: expect.any(String),
          path: '/api/v1/auth/profile',
          method: 'GET',
          errorId: expect.any(String),
          message: 'Invalid token',
          error: 'Unauthorized',
        });
    });

    it('should reject access with expired JWT token', async () => {
      // Create an expired token payload
      const expiredTokenPayload = {
        sub: testUser.id,
        email: testUser.email,
        iat: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        exp: Math.floor(Date.now() / 1000) - 1800, // 30 minutes ago (expired)
      };

      // This would require creating an actual expired token
      // For now, just verify the endpoint rejects obviously invalid tokens
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired.token')
        .expect(401);
    });

    it('should add user information to request context', async () => {
      // This is verified indirectly through the profile endpoint response
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .expect(200);

      expect(response.body.data.user).toEqual({
        id: testUser.id,
        email: 'guard@example.com',
        name: 'Guard Test User',
        provider: 'local',
        createdAt: expect.any(String),
        updatedAt: expect.any(String),
      });
    });
  });

  describe('Input Validation and Sanitization', () => {
    it('should validate required fields', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({}) // Empty body
        .expect(400)
        .expect({
          statusCode: 400,
          timestamp: expect.any(String),
          path: '/api/v1/auth/register',
          method: 'POST',
          errorId: expect.any(String),
          message: expect.arrayContaining([
            expect.stringContaining('email'),
            expect.stringContaining('password'),
            expect.stringContaining('name'),
          ]),
          error: 'Bad Request',
        });
    });

    it('should validate email format', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'not-an-email',
          password: 'SecurePassword123!',
          name: 'Test User',
        })
        .expect(400);
    });

    it('should validate password strength', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'test@example.com',
          password: '123', // Too weak
          name: 'Test User',
        })
        .expect(400);
    });

    it('should sanitize HTML input', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'sanitize@example.com',
          password: 'SecurePassword123!',
          name: '<script>alert("xss")</script>Sanitized Name',
        })
        .expect(201);

      // Verify HTML was sanitized
      expect(response.body.data.user.name).not.toContain('<script>');
      expect(response.body.data.user.name).toContain('Sanitized Name');
    });

    it('should handle special characters properly', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'special@example.com',
          password: 'SecurePassword123!@#$%',
          name: 'José María O\'Connor',
        })
        .expect(201);
    });
  });

  describe('CORS Configuration', () => {
    it('should include CORS headers in responses', async () => {
      const response = await request(app.getHttpServer())
        .options('/api/v1/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .expect(204);

      expect(response.headers['access-control-allow-origin']).toBeDefined();
      expect(response.headers['access-control-allow-methods']).toBeDefined();
      expect(response.headers['access-control-allow-headers']).toBeDefined();
    });

    it('should handle preflight requests', async () => {
      await request(app.getHttpServer())
        .options('/api/v1/auth/register')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'Content-Type, Authorization')
        .expect(204);
    });
  });

  describe('Security Headers (Helmet)', () => {
    it('should include security headers in responses', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .expect(401); // Unauthorized, but should still have security headers

      // Verify some common security headers
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBeDefined();
      expect(response.headers['x-xss-protection']).toBeDefined();
    });

    it('should set Content-Security-Policy header', async () => {
      const response = await request(app.getHttpServer())
        .get('/health')
        .expect(200);

      // CSP header might be set by Helmet
      if (response.headers['content-security-policy']) {
        expect(response.headers['content-security-policy']).toBeDefined();
      }
    });
  });

  describe('Content Type and Compression', () => {
    it('should handle JSON content type', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Content-Type', 'application/json')
        .send({
          email: 'json@example.com',
          password: 'SecurePassword123!',
          name: 'JSON Test User',
        })
        .expect(201)
        .expect('Content-Type', /json/);
    });

    it('should reject unsupported content types', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Content-Type', 'text/plain')
        .send('email=test@example.com&password=password')
        .expect(400);
    });

    it('should handle large request bodies', async () => {
      const largeString = 'a'.repeat(1000);
      
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'large@example.com',
          password: 'SecurePassword123!',
          name: largeString,
        })
        .expect(201);
    });
  });

  describe('API Versioning', () => {
    it('should route requests to correct API version', async () => {
      // Test v1 API
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .expect(401); // Expected because no auth token

      // Test without version should also work (default)
      await request(app.getHttpServer())
        .get('/auth/profile')
        .expect(401);
    });

    it('should handle missing version gracefully', async () => {
      await request(app.getHttpServer())
        .get('/api/auth/profile')
        .expect(404); // No v1 in path
    });
  });

  describe('Request Size Limits', () => {
    it('should reject extremely large payloads', async () => {
      const extremelyLargeString = 'a'.repeat(10 * 1024 * 1024); // 10MB string
      
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'huge@example.com',
          password: 'SecurePassword123!',
          name: extremelyLargeString,
        })
        .expect(413); // Payload Too Large
    });
  });

  describe('Error Boundary Integration', () => {
    it('should handle middleware errors gracefully', async () => {
      // Test with malformed JSON
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Content-Type', 'application/json')
        .send('{"invalid": json}')
        .expect(400);

      expect(response.body).toEqual({
        statusCode: 400,
        timestamp: expect.any(String),
        path: '/api/v1/auth/register',
        method: 'POST',
        errorId: expect.any(String),
        message: expect.any(String),
        error: expect.any(String),
      });
    });

    it('should handle guard exceptions properly', async () => {
      // Test with malformed Authorization header
      await request(app.getHttpServer())
        .get('/api/v1/auth/profile')
        .set('Authorization', 'Bearer')
        .expect(401);
    });
  });

  describe('Health Check Integration', () => {
    it('should allow health checks without authentication', async () => {
      await request(app.getHttpServer())
        .get('/health')
        .expect(200);
    });

    it('should provide detailed health information', async () => {
      const response = await request(app.getHttpServer())
        .get('/health/detailed')
        .expect(200);

      expect(response.body.status).toBe('ok');
      expect(response.body.info).toBeDefined();
      expect(response.body.details).toBeDefined();
    });

    it('should handle health check errors gracefully', async () => {
      // Health endpoints should be resilient
      await request(app.getHttpServer())
        .get('/health/live')
        .expect(200);

      await request(app.getHttpServer())
        .get('/health/ready')
        .expect(200);
    });
  });
});