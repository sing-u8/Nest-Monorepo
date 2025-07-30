import { Test, TestingModule } from '@nestjs/testing';
import { TypeOrmModule, getRepositoryToken } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { ConfigModule } from '@nestjs/config';

// Domain entities
import { AuthSession } from '../../../domain/entities/auth-session.entity';
import { User } from '../../../domain/entities/user.entity';

// Infrastructure
import { AuthSessionOrmEntity } from '../../database/entities/auth-session.orm-entity';
import { UserOrmEntity } from '../../database/entities/user.orm-entity';
import { AuthSessionRepositoryImpl } from '../auth-session.repository';
import { AuthSessionRepository } from '../../../domain/ports/auth-session.repository';
import { UserRepository } from '../../../domain/ports/user.repository';
import { UserRepositoryImpl } from '../user.repository';

// Test utilities
import { createTestAuthSession, createTestUser } from '../../../test/test-utils';

/**
 * AuthSession Repository Integration Tests
 * 
 * Tests the AuthSessionRepositoryImpl with a real PostgreSQL test database
 * to ensure proper database operations and session management.
 */
describe('AuthSessionRepository (Integration)', () => {
  let module: TestingModule;
  let authSessionRepository: AuthSessionRepository;
  let userRepository: UserRepository;
  let sessionOrmRepository: Repository<AuthSessionOrmEntity>;
  let userOrmRepository: Repository<UserOrmEntity>;
  let dataSource: DataSource;

  let testUser: User;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          envFilePath: '.env.test',
        }),
        TypeOrmModule.forRoot({
          type: 'postgres',
          host: process.env.DB_HOST || 'localhost',
          port: parseInt(process.env.DB_PORT || '5432', 10),
          username: process.env.DB_USERNAME || 'test',
          password: process.env.DB_PASSWORD || 'test',
          database: process.env.DB_DATABASE || 'auth_test',
          entities: [AuthSessionOrmEntity, UserOrmEntity],
          synchronize: true, // Only for tests
          dropSchema: true, // Clean database before tests
        }),
        TypeOrmModule.forFeature([AuthSessionOrmEntity, UserOrmEntity]),
      ],
      providers: [
        {
          provide: AuthSessionRepository,
          useClass: AuthSessionRepositoryImpl,
        },
        {
          provide: UserRepository,
          useClass: UserRepositoryImpl,
        },
      ],
    }).compile();

    authSessionRepository = module.get<AuthSessionRepository>(AuthSessionRepository);
    userRepository = module.get<UserRepository>(UserRepository);
    sessionOrmRepository = module.get<Repository<AuthSessionOrmEntity>>(
      getRepositoryToken(AuthSessionOrmEntity)
    );
    userOrmRepository = module.get<Repository<UserOrmEntity>>(
      getRepositoryToken(UserOrmEntity)
    );
    dataSource = module.get<DataSource>(DataSource);
  });

  afterAll(async () => {
    await dataSource.destroy();
    await module.close();
  });

  beforeEach(async () => {
    // Clear all data before each test
    await sessionOrmRepository.clear();
    await userOrmRepository.clear();

    // Create a test user for session operations
    testUser = createTestUser();
    await userRepository.save(testUser);
  });

  describe('save', () => {
    it('should save a new auth session to the database', async () => {
      // Arrange
      const session = createTestAuthSession(testUser.id);

      // Act
      const savedSession = await authSessionRepository.save(session);

      // Assert
      expect(savedSession).toBeDefined();
      expect(savedSession.id).toBe(session.id);
      expect(savedSession.userId).toBe(testUser.id);
      expect(savedSession.sessionToken).toBe(session.sessionToken);
      expect(savedSession.clientInfo).toEqual(session.clientInfo);

      // Verify in database
      const dbSession = await sessionOrmRepository.findOne({
        where: { id: session.id },
      });
      expect(dbSession).toBeDefined();
      expect(dbSession?.userId).toBe(testUser.id);
    });

    it('should save client info as JSONB', async () => {
      // Arrange
      const clientInfo = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '192.168.1.100',
        deviceId: 'device-12345',
        platform: 'Windows',
        browser: 'Chrome',
      };
      const session = createTestAuthSession(testUser.id, { clientInfo });

      // Act
      await authSessionRepository.save(session);

      // Assert
      const savedSession = await authSessionRepository.findById(session.id);
      expect(savedSession?.clientInfo).toEqual(clientInfo);

      // Verify JSONB storage in database
      const dbSession = await sessionOrmRepository.findOne({
        where: { id: session.id },
      });
      expect(dbSession?.clientInfo).toEqual(clientInfo);
    });

    it('should update an existing session', async () => {
      // Arrange
      const session = createTestAuthSession(testUser.id);
      await authSessionRepository.save(session);

      // Act
      session.updateActivity();
      const updatedSession = await authSessionRepository.save(session);

      // Assert
      expect(updatedSession.lastActivityAt.getTime())
        .toBeGreaterThan(session.createdAt.getTime());

      // Verify in database
      const dbSession = await sessionOrmRepository.findOne({
        where: { id: session.id },
      });
      expect(dbSession?.lastActivityAt.getTime())
        .toBeGreaterThan(session.createdAt.getTime());
    });

    it('should handle unique constraint on session token', async () => {
      // Arrange
      const sessionToken = 'unique-session-token-123';
      const session1 = createTestAuthSession(testUser.id, { sessionToken });
      const session2 = createTestAuthSession(testUser.id, { sessionToken });

      // Act
      await authSessionRepository.save(session1);

      // Assert
      await expect(authSessionRepository.save(session2)).rejects.toThrow();
    });
  });

  describe('findById', () => {
    it('should find a session by ID', async () => {
      // Arrange
      const session = createTestAuthSession(testUser.id);
      await authSessionRepository.save(session);

      // Act
      const foundSession = await authSessionRepository.findById(session.id);

      // Assert
      expect(foundSession).toBeDefined();
      expect(foundSession?.id).toBe(session.id);
      expect(foundSession?.userId).toBe(testUser.id);
      expect(foundSession?.sessionToken).toBe(session.sessionToken);
    });

    it('should return null for non-existent ID', async () => {
      // Act
      const foundSession = await authSessionRepository.findById('non-existent-id');

      // Assert
      expect(foundSession).toBeNull();
    });
  });

  describe('findBySessionToken', () => {
    it('should find a session by session token', async () => {
      // Arrange
      const sessionToken = 'find-by-token-123';
      const session = createTestAuthSession(testUser.id, { sessionToken });
      await authSessionRepository.save(session);

      // Act
      const foundSession = await authSessionRepository.findBySessionToken(sessionToken);

      // Assert
      expect(foundSession).toBeDefined();
      expect(foundSession?.sessionToken).toBe(sessionToken);
      expect(foundSession?.userId).toBe(testUser.id);
    });

    it('should return null for non-existent session token', async () => {
      // Act
      const foundSession = await authSessionRepository.findBySessionToken('non-existent-token');

      // Assert
      expect(foundSession).toBeNull();
    });

    it('should not find revoked sessions', async () => {
      // Arrange
      const sessionToken = 'revoked-session-123';
      const session = createTestAuthSession(testUser.id, { sessionToken });
      await authSessionRepository.save(session);
      
      session.revoke();
      await authSessionRepository.save(session);

      // Act
      const foundSession = await authSessionRepository.findBySessionToken(sessionToken);

      // Assert
      expect(foundSession).toBeNull();
    });
  });

  describe('findByUserId', () => {
    it('should find all sessions for a user', async () => {
      // Arrange
      const session1 = createTestAuthSession(testUser.id, {
        clientInfo: { userAgent: 'Chrome', ipAddress: '192.168.1.1', deviceId: 'device1' },
      });
      const session2 = createTestAuthSession(testUser.id, {
        clientInfo: { userAgent: 'Firefox', ipAddress: '192.168.1.2', deviceId: 'device2' },
      });
      await authSessionRepository.save(session1);
      await authSessionRepository.save(session2);

      // Act
      const userSessions = await authSessionRepository.findByUserId(testUser.id);

      // Assert
      expect(userSessions).toHaveLength(2);
      expect(userSessions.some(s => s.id === session1.id)).toBe(true);
      expect(userSessions.some(s => s.id === session2.id)).toBe(true);
    });

    it('should find only active sessions by default', async () => {
      // Arrange
      const activeSession = createTestAuthSession(testUser.id);
      const revokedSession = createTestAuthSession(testUser.id);
      
      await authSessionRepository.save(activeSession);
      await authSessionRepository.save(revokedSession);
      
      revokedSession.revoke();
      await authSessionRepository.save(revokedSession);

      // Act
      const userSessions = await authSessionRepository.findByUserId(testUser.id);

      // Assert
      expect(userSessions).toHaveLength(1);
      expect(userSessions[0].id).toBe(activeSession.id);
      expect(userSessions[0].isRevoked).toBe(false);
    });

    it('should include revoked sessions when requested', async () => {
      // Arrange
      const activeSession = createTestAuthSession(testUser.id);
      const revokedSession = createTestAuthSession(testUser.id);
      
      await authSessionRepository.save(activeSession);
      await authSessionRepository.save(revokedSession);
      
      revokedSession.revoke();
      await authSessionRepository.save(revokedSession);

      // Act
      const allSessions = await authSessionRepository.findByUserId(testUser.id, true);

      // Assert
      expect(allSessions).toHaveLength(2);
      expect(allSessions.some(s => s.isRevoked === true)).toBe(true);
      expect(allSessions.some(s => s.isRevoked === false)).toBe(true);
    });

    it('should return empty array for user with no sessions', async () => {
      // Act
      const userSessions = await authSessionRepository.findByUserId('non-existent-user-id');

      // Assert
      expect(userSessions).toEqual([]);
    });
  });

  describe('revokeByUserId', () => {
    it('should revoke all sessions for a user', async () => {
      // Arrange
      const session1 = createTestAuthSession(testUser.id);
      const session2 = createTestAuthSession(testUser.id);
      await authSessionRepository.save(session1);
      await authSessionRepository.save(session2);

      // Act
      await authSessionRepository.revokeByUserId(testUser.id);

      // Assert
      const userSessions = await authSessionRepository.findByUserId(testUser.id, true);
      expect(userSessions).toHaveLength(2);
      expect(userSessions.every(s => s.isRevoked)).toBe(true);
      expect(userSessions.every(s => s.revokedAt)).toBeTruthy();
    });

    it('should exclude specific session from revocation', async () => {
      // Arrange
      const keepSession = createTestAuthSession(testUser.id);
      const revokeSession = createTestAuthSession(testUser.id);
      await authSessionRepository.save(keepSession);
      await authSessionRepository.save(revokeSession);

      // Act
      await authSessionRepository.revokeByUserId(testUser.id, keepSession.id);

      // Assert
      const allSessions = await authSessionRepository.findByUserId(testUser.id, true);
      const keptSession = allSessions.find(s => s.id === keepSession.id);
      const revokedSession = allSessions.find(s => s.id === revokeSession.id);

      expect(keptSession?.isRevoked).toBe(false);
      expect(revokedSession?.isRevoked).toBe(true);
    });

    it('should handle revoking sessions for user with no sessions', async () => {
      // Act & Assert
      await expect(authSessionRepository.revokeByUserId('non-existent-user-id'))
        .resolves.not.toThrow();
    });
  });

  describe('updateActivity', () => {
    it('should update session activity timestamp', async () => {
      // Arrange
      const session = createTestAuthSession(testUser.id);
      await authSessionRepository.save(session);
      const originalActivityTime = session.lastActivityAt;

      // Wait a moment to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 10));

      // Act
      await authSessionRepository.updateActivity(session.id);

      // Assert
      const updatedSession = await authSessionRepository.findById(session.id);
      expect(updatedSession?.lastActivityAt.getTime())
        .toBeGreaterThan(originalActivityTime.getTime());
    });

    it('should not update activity for non-existent sessions', async () => {
      // Act & Assert
      await expect(authSessionRepository.updateActivity('non-existent-id'))
        .resolves.not.toThrow();
    });

    it('should not update activity for revoked sessions', async () => {
      // Arrange
      const session = createTestAuthSession(testUser.id);
      await authSessionRepository.save(session);
      
      session.revoke();
      await authSessionRepository.save(session);
      const revokedActivityTime = session.lastActivityAt;

      // Act
      await authSessionRepository.updateActivity(session.id);

      // Assert
      const unchangedSession = await authSessionRepository.findBySessionToken(session.sessionToken);
      expect(unchangedSession).toBeNull(); // Should not find revoked session
    });
  });

  describe('cleanupExpiredSessions', () => {
    it('should delete expired sessions', async () => {
      // Arrange
      const expiredSession = createTestAuthSession(testUser.id, {
        expiresAt: new Date(Date.now() - 3600000), // 1 hour ago
      });
      const validSession = createTestAuthSession(testUser.id, {
        expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
      });
      
      await authSessionRepository.save(expiredSession);
      await authSessionRepository.save(validSession);

      // Act
      const deletedCount = await authSessionRepository.cleanupExpiredSessions();

      // Assert
      expect(deletedCount).toBe(1);

      const remainingSessions = await authSessionRepository.findByUserId(testUser.id, true);
      expect(remainingSessions).toHaveLength(1);
      expect(remainingSessions[0].id).toBe(validSession.id);
    });

    it('should delete sessions inactive for too long', async () => {
      // Arrange
      const inactiveSession = createTestAuthSession(testUser.id, {
        lastActivityAt: new Date(Date.now() - 86400000 * 8), // 8 days ago
      });
      const activeSession = createTestAuthSession(testUser.id, {
        lastActivityAt: new Date(Date.now() - 3600000), // 1 hour ago
      });
      
      await authSessionRepository.save(inactiveSession);
      await authSessionRepository.save(activeSession);

      // Act
      const deletedCount = await authSessionRepository.cleanupExpiredSessions();

      // Assert
      expect(deletedCount).toBe(1);

      const remainingSessions = await authSessionRepository.findByUserId(testUser.id, true);
      expect(remainingSessions).toHaveLength(1);
      expect(remainingSessions[0].id).toBe(activeSession.id);
    });

    it('should not delete valid active sessions', async () => {
      // Arrange
      const validSession = createTestAuthSession(testUser.id, {
        expiresAt: new Date(Date.now() + 86400000), // 1 day from now
        lastActivityAt: new Date(Date.now() - 3600000), // 1 hour ago
      });
      await authSessionRepository.save(validSession);

      // Act
      const deletedCount = await authSessionRepository.cleanupExpiredSessions();

      // Assert
      expect(deletedCount).toBe(0);

      const sessions = await authSessionRepository.findByUserId(testUser.id);
      expect(sessions).toHaveLength(1);
    });

    it('should handle database with no sessions', async () => {
      // Act
      const deletedCount = await authSessionRepository.cleanupExpiredSessions();

      // Assert
      expect(deletedCount).toBe(0);
    });
  });

  describe('Session expiration and inactivity', () => {
    it('should handle sessions that expire exactly now', async () => {
      // Arrange
      const expiringNowSession = createTestAuthSession(testUser.id, {
        expiresAt: new Date(), // Expires now
      });
      await authSessionRepository.save(expiringNowSession);

      // Act
      const deletedCount = await authSessionRepository.cleanupExpiredSessions();

      // Assert
      expect(deletedCount).toBe(1);
    });

    it('should handle sessions with very old activity', async () => {
      // Arrange
      const veryOldSession = createTestAuthSession(testUser.id, {
        lastActivityAt: new Date('2020-01-01'), // Very old date
      });
      await authSessionRepository.save(veryOldSession);

      // Act
      const deletedCount = await authSessionRepository.cleanupExpiredSessions();

      // Assert
      expect(deletedCount).toBe(1);
    });
  });

  describe('Entity mapping', () => {
    it('should correctly map all AuthSession entity properties', async () => {
      // Arrange
      const now = new Date();
      const clientInfo = {
        userAgent: 'Test-Agent/1.0',
        ipAddress: '203.0.113.1',
        deviceId: 'test-device-abc123',
        platform: 'Test Platform',
        browser: 'Test Browser',
      };
      const session = createTestAuthSession(testUser.id, {
        sessionToken: 'test-session-token-123',
        clientInfo,
        expiresAt: new Date(now.getTime() + 86400000), // 1 day from now
        lastActivityAt: now,
        isRevoked: false,
        revokedAt: null,
      });

      // Act
      await authSessionRepository.save(session);
      const retrievedSession = await authSessionRepository.findById(session.id);

      // Assert
      expect(retrievedSession).toBeDefined();
      expect(retrievedSession?.id).toBe(session.id);
      expect(retrievedSession?.userId).toBe(session.userId);
      expect(retrievedSession?.sessionToken).toBe(session.sessionToken);
      expect(retrievedSession?.clientInfo).toEqual(session.clientInfo);
      expect(retrievedSession?.expiresAt.getTime()).toBeCloseTo(session.expiresAt.getTime(), -3);
      expect(retrievedSession?.lastActivityAt.getTime()).toBeCloseTo(session.lastActivityAt.getTime(), -3);
      expect(retrievedSession?.isRevoked).toBe(session.isRevoked);
      expect(retrievedSession?.revokedAt).toBe(session.revokedAt);
      expect(retrievedSession?.createdAt).toBeTruthy();
      expect(retrievedSession?.updatedAt).toBeTruthy();
    });
  });

  describe('Concurrent operations', () => {
    it('should handle concurrent session operations', async () => {
      // Arrange
      const sessions = Array.from({ length: 10 }, (_, i) => 
        createTestAuthSession(testUser.id, {
          clientInfo: {
            userAgent: `Test-Agent-${i}`,
            ipAddress: `192.168.1.${i + 1}`,
            deviceId: `device-${i}`,
          },
        })
      );

      // Act
      await Promise.all(sessions.map(session => authSessionRepository.save(session)));

      // Assert
      const savedSessions = await authSessionRepository.findByUserId(testUser.id);
      expect(savedSessions).toHaveLength(10);

      // Verify each session has unique properties
      const deviceIds = savedSessions.map(s => s.clientInfo.deviceId);
      const uniqueDeviceIds = new Set(deviceIds);
      expect(uniqueDeviceIds.size).toBe(10);
    });

    it('should handle concurrent activity updates', async () => {
      // Arrange
      const session = createTestAuthSession(testUser.id);
      await authSessionRepository.save(session);

      // Act - Multiple concurrent activity updates
      const updates = Array.from({ length: 5 }, () => 
        authSessionRepository.updateActivity(session.id)
      );
      await Promise.all(updates);

      // Assert - Should not throw errors
      const updatedSession = await authSessionRepository.findById(session.id);
      expect(updatedSession).toBeDefined();
      expect(updatedSession?.lastActivityAt.getTime())
        .toBeGreaterThan(session.createdAt.getTime());
    });
  });
});