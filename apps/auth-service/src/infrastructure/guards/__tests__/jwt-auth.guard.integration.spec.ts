import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as request from 'supertest';
import { APP_GUARD } from '@nestjs/core';
import { Controller, Get, Post, UseGuards } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

// Guards and strategies
import { JwtAuthGuard } from '../jwt-auth.guard';
import { JwtStrategy } from '../../strategies/jwt.strategy';
import { Public } from '../../../shared/decorators/public.decorator';

// Domain ports
import { UserRepository } from '../../../domain/ports/user.repository';
import { AuthSessionRepository } from '../../../domain/ports/auth-session.repository';

// Test utilities
import { createTestUser, createTestAuthSession, generateTestJwtToken } from '../../../test/test-utils';

/**
 * Test controller for JWT guard integration tests
 */
@Controller('test')
class TestController {
  @Public()
  @Get('public')
  getPublic() {
    return { message: 'Public endpoint' };
  }

  @Get('protected')
  getProtected() {
    return { message: 'Protected endpoint' };
  }

  @Post('protected')
  postProtected() {
    return { message: 'Protected POST endpoint' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('explicit-guard')
  getExplicitGuard() {
    return { message: 'Explicitly guarded endpoint' };
  }
}

/**
 * JWT Auth Guard Integration Tests
 * 
 * Tests the JwtAuthGuard with real HTTP requests to ensure proper
 * authentication and authorization behavior.
 */
describe('JwtAuthGuard (Integration)', () => {
  let app: INestApplication;
  let jwtService: JwtService;
  let userRepository: jest.Mocked<UserRepository>;
  let authSessionRepository: jest.Mocked<AuthSessionRepository>;

  beforeAll(async () => {
    // Create mock repositories
    const mockUserRepository = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      save: jest.fn(),
      existsByEmail: jest.fn(),
      update: jest.fn(),
      deactivate: jest.fn(),
      activate: jest.fn(),
      delete: jest.fn(),
      findByProvider: jest.fn(),
    };

    const mockAuthSessionRepository = {
      save: jest.fn(),
      findById: jest.fn(),
      findBySessionToken: jest.fn(),
      findByUserId: jest.fn(),
      revokeByUserId: jest.fn(),
      updateActivity: jest.fn(),
      cleanupExpiredSessions: jest.fn(),
    };

    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
        }),
      ],
      controllers: [TestController],
      providers: [
        JwtStrategy,
        {
          provide: APP_GUARD,
          useClass: JwtAuthGuard,
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
            verify: jest.fn(),
            decode: jest.fn(),
          },
        },
        {
          provide: UserRepository,
          useValue: mockUserRepository,
        },
        {
          provide: AuthSessionRepository,
          useValue: mockAuthSessionRepository,
        },
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    jwtService = moduleRef.get<JwtService>(JwtService);
    userRepository = moduleRef.get(UserRepository);
    authSessionRepository = moduleRef.get(AuthSessionRepository);

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Public endpoints', () => {
    it('should allow access to @Public decorated endpoints without token', async () => {
      // Act
      const response = await request(app.getHttpServer())
        .get('/test/public')
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'Public endpoint' });
      expect(userRepository.findById).not.toHaveBeenCalled();
    });

    it('should allow access to @Public endpoints with invalid token', async () => {
      // Act
      const response = await request(app.getHttpServer())
        .get('/test/public')
        .set('Authorization', 'Bearer invalid.token')
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'Public endpoint' });
    });
  });

  describe('Protected endpoints', () => {
    it('should deny access without authorization header', async () => {
      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .expect(401);
    });

    it('should deny access with malformed authorization header', async () => {
      // Act & Assert
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', 'InvalidFormat')
        .expect(401);

      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', 'Bearer')
        .expect(401);

      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', 'Basic dGVzdA==')
        .expect(401);
    });

    it('should deny access with invalid JWT token', async () => {
      // Arrange
      (jwtService.verify as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', 'Bearer invalid.jwt.token')
        .expect(401);
    });

    it('should allow access with valid JWT token and active user', async () => {
      // Arrange
      const testUser = createTestUser();
      const testSession = createTestAuthSession(testUser.id);
      
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: testUser.id,
        email: testUser.email,
        sessionId: testSession.id,
        type: 'ACCESS',
      });
      
      userRepository.findById.mockResolvedValue(testUser);
      authSessionRepository.findById.mockResolvedValue(testSession);

      // Act
      const response = await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer valid.jwt.token`)
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'Protected endpoint' });
      expect(userRepository.findById).toHaveBeenCalledWith(testUser.id);
      expect(authSessionRepository.findById).toHaveBeenCalledWith(testSession.id);
      expect(authSessionRepository.updateActivity).toHaveBeenCalledWith(testSession.id);
    });

    it('should deny access for inactive user', async () => {
      // Arrange
      const inactiveUser = createTestUser({ isActive: false });
      const testSession = createTestAuthSession(inactiveUser.id);
      
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: inactiveUser.id,
        email: inactiveUser.email,
        sessionId: testSession.id,
        type: 'ACCESS',
      });
      
      userRepository.findById.mockResolvedValue(inactiveUser);
      authSessionRepository.findById.mockResolvedValue(testSession);

      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer valid.jwt.token`)
        .expect(401);

      // Assert
      expect(userRepository.findById).toHaveBeenCalledWith(inactiveUser.id);
    });

    it('should deny access for non-existent user', async () => {
      // Arrange
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: 'non-existent-user-id',
        email: 'nonexistent@example.com',
        sessionId: 'session-id',
        type: 'ACCESS',
      });
      
      userRepository.findById.mockResolvedValue(null);

      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer valid.jwt.token`)
        .expect(401);
    });

    it('should deny access for revoked session', async () => {
      // Arrange
      const testUser = createTestUser();
      const revokedSession = createTestAuthSession(testUser.id, { isRevoked: true });
      
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: testUser.id,
        email: testUser.email,
        sessionId: revokedSession.id,
        type: 'ACCESS',
      });
      
      userRepository.findById.mockResolvedValue(testUser);
      authSessionRepository.findById.mockResolvedValue(revokedSession);

      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer valid.jwt.token`)
        .expect(401);
    });

    it('should deny access for expired session', async () => {
      // Arrange
      const testUser = createTestUser();
      const expiredSession = createTestAuthSession(testUser.id, {
        expiresAt: new Date(Date.now() - 3600000), // 1 hour ago
      });
      
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: testUser.id,
        email: testUser.email,
        sessionId: expiredSession.id,
        type: 'ACCESS',
      });
      
      userRepository.findById.mockResolvedValue(testUser);
      authSessionRepository.findById.mockResolvedValue(expiredSession);

      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer valid.jwt.token`)
        .expect(401);
    });

    it('should deny access for non-existent session', async () => {
      // Arrange
      const testUser = createTestUser();
      
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: testUser.id,
        email: testUser.email,
        sessionId: 'non-existent-session-id',
        type: 'ACCESS',
      });
      
      userRepository.findById.mockResolvedValue(testUser);
      authSessionRepository.findById.mockResolvedValue(null);

      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer valid.jwt.token`)
        .expect(401);
    });

    it('should deny access for refresh token instead of access token', async () => {
      // Arrange
      const testUser = createTestUser();
      const testSession = createTestAuthSession(testUser.id);
      
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: testUser.id,
        email: testUser.email,
        sessionId: testSession.id,
        type: 'REFRESH', // Wrong token type
      });
      
      userRepository.findById.mockResolvedValue(testUser);
      authSessionRepository.findById.mockResolvedValue(testSession);

      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer refresh.jwt.token`)
        .expect(401);
    });

    it('should work with different HTTP methods', async () => {
      // Arrange
      const testUser = createTestUser();
      const testSession = createTestAuthSession(testUser.id);
      
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: testUser.id,
        email: testUser.email,
        sessionId: testSession.id,
        type: 'ACCESS',
      });
      
      userRepository.findById.mockResolvedValue(testUser);
      authSessionRepository.findById.mockResolvedValue(testSession);

      // Act & Assert
      await request(app.getHttpServer())
        .post('/test/protected')
        .set('Authorization', `Bearer valid.jwt.token`)
        .expect(200);

      expect(response => {
        expect(response.body).toEqual({ message: 'Protected POST endpoint' });
      });
    });
  });

  describe('Explicit guard usage', () => {
    it('should protect endpoints with explicit @UseGuards decorator', async () => {
      // Act
      await request(app.getHttpServer())
        .get('/test/explicit-guard')
        .expect(401);
    });

    it('should allow access with valid token on explicitly guarded endpoint', async () => {
      // Arrange
      const testUser = createTestUser();
      const testSession = createTestAuthSession(testUser.id);
      
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: testUser.id,
        email: testUser.email,
        sessionId: testSession.id,
        type: 'ACCESS',
      });
      
      userRepository.findById.mockResolvedValue(testUser);
      authSessionRepository.findById.mockResolvedValue(testSession);

      // Act
      const response = await request(app.getHttpServer())
        .get('/test/explicit-guard')
        .set('Authorization', `Bearer valid.jwt.token`)
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'Explicitly guarded endpoint' });
    });
  });

  describe('Client information extraction', () => {
    it('should extract IP address from headers', async () => {
      // Arrange
      const testUser = createTestUser();
      const testSession = createTestAuthSession(testUser.id);
      
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: testUser.id,
        email: testUser.email,
        sessionId: testSession.id,
        type: 'ACCESS',
      });
      
      userRepository.findById.mockResolvedValue(testUser);
      authSessionRepository.findById.mockResolvedValue(testSession);

      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer valid.jwt.token`)
        .set('x-forwarded-for', '203.0.113.1')
        .set('user-agent', 'Test-Browser/1.0')
        .expect(200);

      // Assert
      expect(userRepository.findById).toHaveBeenCalled();
      expect(authSessionRepository.updateActivity).toHaveBeenCalled();
    });

    it('should handle requests without user agent', async () => {
      // Arrange
      const testUser = createTestUser();
      const testSession = createTestAuthSession(testUser.id);
      
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: testUser.id,
        email: testUser.email,
        sessionId: testSession.id,
        type: 'ACCESS',
      });
      
      userRepository.findById.mockResolvedValue(testUser);
      authSessionRepository.findById.mockResolvedValue(testSession);

      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer valid.jwt.token`)
        .expect(200);

      // Assert
      expect(authSessionRepository.updateActivity).toHaveBeenCalled();
    });
  });

  describe('Error handling', () => {
    it('should handle database errors gracefully', async () => {
      // Arrange
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: 'user-id',
        email: 'test@example.com',
        sessionId: 'session-id',
        type: 'ACCESS',
      });
      
      userRepository.findById.mockRejectedValue(new Error('Database connection error'));

      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer valid.jwt.token`)
        .expect(401);
    });

    it('should handle session update errors gracefully', async () => {
      // Arrange
      const testUser = createTestUser();
      const testSession = createTestAuthSession(testUser.id);
      
      (jwtService.verify as jest.Mock).mockReturnValue({
        sub: testUser.id,
        email: testUser.email,
        sessionId: testSession.id,
        type: 'ACCESS',
      });
      
      userRepository.findById.mockResolvedValue(testUser);
      authSessionRepository.findById.mockResolvedValue(testSession);
      authSessionRepository.updateActivity.mockRejectedValue(new Error('Update failed'));

      // Act - Should still allow access even if activity update fails
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer valid.jwt.token`)
        .expect(200);
    });
  });

  describe('Token variations', () => {
    it('should handle tokens with different case in Bearer prefix', async () => {
      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', 'bearer valid.jwt.token')
        .expect(401);

      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', 'BEARER valid.jwt.token')
        .expect(401);
    });

    it('should handle tokens with extra spaces', async () => {
      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', '  Bearer  valid.jwt.token  ')
        .expect(401);
    });

    it('should handle very long tokens', async () => {
      // Arrange
      const longToken = 'a'.repeat(1000);

      // Act
      await request(app.getHttpServer())
        .get('/test/protected')
        .set('Authorization', `Bearer ${longToken}`)
        .expect(401);
    });
  });
});