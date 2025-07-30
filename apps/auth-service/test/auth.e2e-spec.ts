import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app/app.module';
import { generateRandomEmail } from '../src/test/test-utils';

/**
 * End-to-End Tests for Authentication Service
 * 
 * Tests complete authentication flows including registration,
 * login, token refresh, and profile management.
 */
describe('Auth Service E2E Tests', () => {
  let app: INestApplication;
  let testUser: {
    email: string;
    password: string;
    name: string;
    accessToken?: string;
    refreshToken?: string;
    userId?: string;
  };

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    
    // Add global pipes
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      })
    );

    // Set global prefix
    app.setGlobalPrefix('api');

    await app.init();

    // Initialize test user data
    testUser = {
      email: generateRandomEmail(),
      password: 'TestPassword123!@#',
      name: 'E2E Test User',
    };
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Complete Authentication Flow', () => {
    describe('1. User Registration', () => {
      it('should register a new user successfully', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/auth/register')
          .send({
            email: testUser.email,
            password: testUser.password,
            name: testUser.name,
          })
          .expect(201);

        expect(response.body).toMatchObject({
          success: true,
          data: {
            user: {
              email: testUser.email,
              name: testUser.name,
              emailVerified: false,
              authProvider: 'LOCAL',
            },
            tokens: {
              accessToken: expect.any(String),
              refreshToken: expect.any(String),
              tokenType: 'Bearer',
              expiresIn: expect.any(Number),
            },
          },
        });

        // Store tokens for subsequent tests
        testUser.accessToken = response.body.data.tokens.accessToken;
        testUser.refreshToken = response.body.data.tokens.refreshToken;
        testUser.userId = response.body.data.user.id;
      });

      it('should not allow duplicate registration', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/auth/register')
          .send({
            email: testUser.email,
            password: testUser.password,
            name: testUser.name,
          })
          .expect(409);

        expect(response.body).toMatchObject({
          success: false,
          error: {
            code: 'USER_ALREADY_EXISTS',
            message: expect.stringContaining('already exists'),
          },
        });
      });
    });

    describe('2. User Login', () => {
      it('should login with valid credentials', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/auth/login')
          .send({
            email: testUser.email,
            password: testUser.password,
          })
          .set('User-Agent', 'E2E-Test-Agent/1.0')
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          data: {
            user: {
              id: testUser.userId,
              email: testUser.email,
              name: testUser.name,
            },
            tokens: {
              accessToken: expect.any(String),
              refreshToken: expect.any(String),
              tokenType: 'Bearer',
            },
            session: {
              id: expect.any(String),
            },
          },
        });

        // Update tokens
        testUser.accessToken = response.body.data.tokens.accessToken;
        testUser.refreshToken = response.body.data.tokens.refreshToken;
      });

      it('should fail login with wrong password', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/auth/login')
          .send({
            email: testUser.email,
            password: 'WrongPassword123!',
          })
          .expect(401);

        expect(response.body).toMatchObject({
          success: false,
          error: {
            code: 'INVALID_CREDENTIALS',
            message: expect.stringContaining('Invalid'),
          },
        });
      });

      it('should fail login with non-existent email', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/auth/login')
          .send({
            email: 'nonexistent@example.com',
            password: testUser.password,
          })
          .expect(401);

        expect(response.body).toMatchObject({
          success: false,
          error: {
            code: 'INVALID_CREDENTIALS',
          },
        });
      });
    });

    describe('3. Authenticated Endpoints', () => {
      it('should get current user with valid token', async () => {
        const response = await request(app.getHttpServer())
          .get('/api/auth/me')
          .set('Authorization', `Bearer ${testUser.accessToken}`)
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          data: {
            user: {
              id: testUser.userId,
              email: testUser.email,
              name: testUser.name,
            },
          },
        });
      });

      it('should fail with invalid token', async () => {
        const response = await request(app.getHttpServer())
          .get('/api/auth/me')
          .set('Authorization', 'Bearer invalid.token')
          .expect(401);

        expect(response.body).toMatchObject({
          success: false,
          error: {
            code: 'UNAUTHORIZED',
          },
        });
      });

      it('should fail without token', async () => {
        await request(app.getHttpServer())
          .get('/api/auth/me')
          .expect(401);
      });
    });

    describe('4. Token Refresh', () => {
      it('should refresh tokens successfully', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/auth/refresh')
          .send({
            refreshToken: testUser.refreshToken,
          })
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          data: {
            tokens: {
              accessToken: expect.any(String),
              refreshToken: expect.any(String),
              tokenType: 'Bearer',
            },
            user: {
              id: testUser.userId,
              email: testUser.email,
            },
          },
        });

        // Verify new tokens are different
        expect(response.body.data.tokens.accessToken).not.toBe(testUser.accessToken);
        expect(response.body.data.tokens.refreshToken).not.toBe(testUser.refreshToken);

        // Update tokens
        testUser.accessToken = response.body.data.tokens.accessToken;
        testUser.refreshToken = response.body.data.tokens.refreshToken;
      });

      it('should not allow reuse of old refresh token', async () => {
        const oldRefreshToken = testUser.refreshToken;
        
        // First refresh
        const firstRefresh = await request(app.getHttpServer())
          .post('/api/auth/refresh')
          .send({
            refreshToken: oldRefreshToken,
          })
          .expect(200);

        // Try to use old token again
        const response = await request(app.getHttpServer())
          .post('/api/auth/refresh')
          .send({
            refreshToken: oldRefreshToken,
          })
          .expect(401);

        expect(response.body).toMatchObject({
          success: false,
          error: {
            code: 'INVALID_REFRESH_TOKEN',
          },
        });
      });
    });

    describe('5. Profile Management', () => {
      it('should get user profile', async () => {
        const response = await request(app.getHttpServer())
          .get('/api/profile')
          .set('Authorization', `Bearer ${testUser.accessToken}`)
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          data: {
            profile: {
              id: testUser.userId,
              email: testUser.email,
              name: testUser.name,
              profilePicture: null,
              emailVerified: false,
            },
          },
        });
      });

      it('should update user profile', async () => {
        const newName = 'Updated E2E User';
        
        const response = await request(app.getHttpServer())
          .put('/api/profile')
          .set('Authorization', `Bearer ${testUser.accessToken}`)
          .send({
            name: newName,
          })
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          data: {
            profile: {
              id: testUser.userId,
              name: newName,
            },
          },
        });

        testUser.name = newName;
      });

      it('should validate profile update data', async () => {
        const response = await request(app.getHttpServer())
          .put('/api/profile')
          .set('Authorization', `Bearer ${testUser.accessToken}`)
          .send({
            name: 'A', // Too short
          })
          .expect(400);

        expect(response.body).toMatchObject({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: expect.stringContaining('name'),
          },
        });
      });
    });

    describe('6. Logout', () => {
      it('should logout successfully', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/auth/logout')
          .set('Authorization', `Bearer ${testUser.accessToken}`)
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          data: {
            message: 'Logged out successfully',
          },
        });
      });

      it('should not allow access after logout', async () => {
        await request(app.getHttpServer())
          .get('/api/auth/me')
          .set('Authorization', `Bearer ${testUser.accessToken}`)
          .expect(401);
      });
    });
  });

  describe('Health Checks', () => {
    it('should return health status', async () => {
      const response = await request(app.getHttpServer())
        .get('/health')
        .expect(200);

      expect(response.body).toMatchObject({
        status: 'ok',
        info: expect.any(Object),
        details: expect.any(Object),
      });
    });

    it('should return liveness status', async () => {
      const response = await request(app.getHttpServer())
        .get('/health/live')
        .expect(200);

      expect(response.body).toMatchObject({
        status: 'ok',
        timestamp: expect.any(String),
        uptime: expect.any(Number),
      });
    });

    it('should return readiness status', async () => {
      const response = await request(app.getHttpServer())
        .get('/health/ready')
        .expect(200);

      expect(response.body).toMatchObject({
        status: 'ok',
        details: expect.any(Object),
      });
    });
  });

  describe('API Documentation', () => {
    it('should serve Swagger documentation', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/docs-json')
        .expect(200);

      expect(response.body).toMatchObject({
        openapi: expect.stringMatching(/^3\./),
        info: {
          title: 'Auth Service API',
          version: expect.any(String),
        },
        paths: expect.any(Object),
      });
    });
  });

  describe('Rate Limiting', () => {
    it('should apply rate limiting to authentication endpoints', async () => {
      const email = generateRandomEmail();
      const requests = [];

      // Make many rapid requests
      for (let i = 0; i < 20; i++) {
        requests.push(
          request(app.getHttpServer())
            .post('/api/auth/login')
            .send({
              email,
              password: 'Test123!@#',
            })
        );
      }

      const responses = await Promise.all(requests);
      const statusCodes = responses.map(r => r.status);
      
      // Should have some rate limited responses
      expect(statusCodes).toContain(429);
      
      // Check rate limit headers
      const rateLimitedResponse = responses.find(r => r.status === 429);
      expect(rateLimitedResponse?.headers).toMatchObject({
        'x-ratelimit-limit': expect.any(String),
        'x-ratelimit-remaining': expect.any(String),
        'x-ratelimit-reset': expect.any(String),
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed JSON', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/register')
        .set('Content-Type', 'application/json')
        .send('{ invalid json')
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        error: {
          code: 'BAD_REQUEST',
        },
      });
    });

    it('should handle missing content type', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/register')
        .send('email=test@example.com')
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        error: expect.any(Object),
      });
    });

    it('should handle method not allowed', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/auth/register') // GET instead of POST
        .expect(404); // Or 405 depending on configuration

      expect(response.body).toMatchObject({
        success: false,
        error: expect.any(Object),
      });
    });
  });
});