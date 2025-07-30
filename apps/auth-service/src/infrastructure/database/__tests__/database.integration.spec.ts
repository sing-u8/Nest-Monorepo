import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

import { DatabaseModule } from '../database.module';
import { DatabaseHealthIndicator } from '../database.health';
import { UserOrmEntity } from '../entities/user.orm-entity';
import { TokenOrmEntity } from '../entities/token.orm-entity';
import { AuthSessionOrmEntity } from '../entities/auth-session.orm-entity';
import { UserRepositoryImpl } from '../../repositories/user.repository.impl';
import { TokenRepositoryImpl } from '../../repositories/token.repository.impl';
import { AuthSessionRepositoryImpl } from '../../repositories/auth-session.repository.impl';

/**
 * Database Integration Tests
 * 
 * Tests the database module configuration, connections, and
 * repository implementations with an actual test database.
 */
describe('Database Integration', () => {
  let module: TestingModule;
  let dataSource: DataSource;
  let healthIndicator: DatabaseHealthIndicator;
  let userRepository: UserRepositoryImpl;
  let tokenRepository: TokenRepositoryImpl;
  let sessionRepository: AuthSessionRepositoryImpl;

  // Test database configuration
  const testDbConfig = {
    type: 'postgres' as const,
    host: process.env.TEST_DB_HOST || 'localhost',
    port: parseInt(process.env.TEST_DB_PORT || '5433', 10),
    username: process.env.TEST_DB_USERNAME || 'test_auth_service',
    password: process.env.TEST_DB_PASSWORD || 'test_password',
    database: process.env.TEST_DB_NAME || 'test_auth_service_db',
    entities: [UserOrmEntity, TokenOrmEntity, AuthSessionOrmEntity],
    synchronize: true, // OK for tests
    dropSchema: true, // Clean slate for each test
    logging: false,
  };

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          envFilePath: '.env.test',
        }),
        TypeOrmModule.forRoot(testDbConfig),
        DatabaseModule,
      ],
    }).compile();

    dataSource = module.get<DataSource>(DataSource);
    healthIndicator = module.get<DatabaseHealthIndicator>(DatabaseHealthIndicator);
    userRepository = module.get<UserRepositoryImpl>(UserRepositoryImpl);
    tokenRepository = module.get<TokenRepositoryImpl>(TokenRepositoryImpl);
    sessionRepository = module.get<AuthSessionRepositoryImpl>(AuthSessionRepositoryImpl);
  });

  afterAll(async () => {
    if (dataSource) {
      await dataSource.destroy();
    }
    await module.close();
  });

  describe('Database Connection', () => {
    it('should be initialized and connected', () => {
      expect(dataSource).toBeDefined();
      expect(dataSource.isInitialized).toBe(true);
    });

    it('should have all entities registered', () => {
      const entityNames = dataSource.entityMetadatas.map(meta => meta.name);
      expect(entityNames).toContain('UserOrmEntity');
      expect(entityNames).toContain('TokenOrmEntity');
      expect(entityNames).toContain('AuthSessionOrmEntity');
    });

    it('should execute basic queries', async () => {
      const result = await dataSource.query('SELECT 1 as test');
      expect(result).toEqual([{ test: 1 }]);
    });
  });

  describe('Database Health Check', () => {
    it('should report healthy status', async () => {
      const result = await healthIndicator.isHealthy('database');
      
      expect(result).toBeDefined();
      expect(result.database.status).toBe('up');
      expect(result.database.connection.isInitialized).toBe(true);
      expect(result.database.responseTime).toMatch(/^\d+ms$/);
    });

    it('should perform quick connection check', async () => {
      const isHealthy = await healthIndicator.quickCheck();
      expect(isHealthy).toBe(true);
    });

    it('should get database information', async () => {
      const info = await healthIndicator.getDatabaseInfo();
      
      expect(info).toBeDefined();
      expect(info.version).toBeDefined();
      expect(info.currentDatabase).toBeDefined();
      expect(info.driver).toBe('postgres');
      expect(info.entities).toEqual(
        expect.arrayContaining(['UserOrmEntity', 'TokenOrmEntity', 'AuthSessionOrmEntity'])
      );
    });
  });

  describe('Repository Implementations', () => {
    beforeEach(async () => {
      // Clean up tables before each test
      await dataSource.query('TRUNCATE TABLE auth_sessions CASCADE');
      await dataSource.query('TRUNCATE TABLE tokens CASCADE');
      await dataSource.query('TRUNCATE TABLE users CASCADE');
    });

    describe('UserRepository', () => {
      it('should save and retrieve users', async () => {
        // Create a test user using the domain entity
        const testUser = {
          id: 'user_test_123',
          email: 'test@example.com',
          passwordHash: 'hashed_password',
          name: 'Test User',
          profilePicture: null,
          isActive: true,
          emailVerified: false,
          authProvider: 'LOCAL' as const,
          providerId: null,
          lastLoginAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        // Save user
        await userRepository.save(testUser as any);

        // Retrieve user
        const foundUser = await userRepository.findById('user_test_123');
        expect(foundUser).toBeDefined();
        expect(foundUser?.email).toBe('test@example.com');
        expect(foundUser?.name).toBe('Test User');
      });

      it('should find user by email', async () => {
        const testUser = {
          id: 'user_email_test',
          email: 'email.test@example.com',
          passwordHash: 'hashed_password',
          name: 'Email Test',
          profilePicture: null,
          isActive: true,
          emailVerified: false,
          authProvider: 'LOCAL' as const,
          providerId: null,
          lastLoginAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        await userRepository.save(testUser as any);

        const foundUser = await userRepository.findByEmail('email.test@example.com');
        expect(foundUser).toBeDefined();
        expect(foundUser?.id).toBe('user_email_test');
      });

      it('should check if user exists by email', async () => {
        const testUser = {
          id: 'user_exists_test',
          email: 'exists@example.com',
          passwordHash: 'hashed_password',
          name: 'Exists Test',
          profilePicture: null,
          isActive: true,
          emailVerified: false,
          authProvider: 'LOCAL' as const,
          providerId: null,
          lastLoginAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        await userRepository.save(testUser as any);

        const exists = await userRepository.existsByEmail('exists@example.com');
        expect(exists).toBe(true);

        const notExists = await userRepository.existsByEmail('not.exists@example.com');
        expect(notExists).toBe(false);
      });
    });

    describe('TokenRepository', () => {
      let testUserId: string;

      beforeEach(async () => {
        // Create a test user first
        testUserId = 'user_token_test';
        const testUser = {
          id: testUserId,
          email: 'token.test@example.com',
          passwordHash: 'hashed_password',
          name: 'Token Test',
          profilePicture: null,
          isActive: true,
          emailVerified: false,
          authProvider: 'LOCAL' as const,
          providerId: null,
          lastLoginAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        await userRepository.save(testUser as any);
      });

      it('should save and retrieve tokens', async () => {
        const testToken = {
          id: 'token_test_123',
          userId: testUserId,
          type: 'ACCESS' as const,
          value: 'test_token_value',
          expiresAt: new Date(Date.now() + 3600000),
          isRevoked: false,
          revokedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        await tokenRepository.save(testToken as any);

        const foundToken = await tokenRepository.findByValue('test_token_value');
        expect(foundToken).toBeDefined();
        expect(foundToken?.userId).toBe(testUserId);
        expect(foundToken?.type).toBe('ACCESS');
      });

      it('should find tokens by user ID and type', async () => {
        const accessToken = {
          id: 'access_token_123',
          userId: testUserId,
          type: 'ACCESS' as const,
          value: 'access_token_value',
          expiresAt: new Date(Date.now() + 3600000),
          isRevoked: false,
          revokedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const refreshToken = {
          id: 'refresh_token_123',
          userId: testUserId,
          type: 'REFRESH' as const,
          value: 'refresh_token_value',
          expiresAt: new Date(Date.now() + 86400000),
          isRevoked: false,
          revokedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        await tokenRepository.save(accessToken as any);
        await tokenRepository.save(refreshToken as any);

        const userTokens = await tokenRepository.findByUserId(testUserId);
        expect(userTokens).toHaveLength(2);

        const accessTokens = await tokenRepository.findByUserIdAndType(testUserId, 'ACCESS' as any);
        expect(accessTokens).toHaveLength(1);
        expect(accessTokens[0].type).toBe('ACCESS');
      });

      it('should revoke tokens', async () => {
        const testToken = {
          id: 'revoke_token_123',
          userId: testUserId,
          type: 'ACCESS' as const,
          value: 'revoke_token_value',
          expiresAt: new Date(Date.now() + 3600000),
          isRevoked: false,
          revokedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        await tokenRepository.save(testToken as any);

        await tokenRepository.revoke('revoke_token_123');

        const revokedToken = await tokenRepository.findByValue('revoke_token_value');
        expect(revokedToken?.isRevoked).toBe(true);
        expect(revokedToken?.revokedAt).toBeInstanceOf(Date);
      });
    });

    describe('AuthSessionRepository', () => {
      let testUserId: string;

      beforeEach(async () => {
        // Create a test user first
        testUserId = 'user_session_test';
        const testUser = {
          id: testUserId,
          email: 'session.test@example.com',
          passwordHash: 'hashed_password',
          name: 'Session Test',
          profilePicture: null,
          isActive: true,
          emailVerified: false,
          authProvider: 'LOCAL' as const,
          providerId: null,
          lastLoginAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        await userRepository.save(testUser as any);
      });

      it('should save and retrieve sessions', async () => {
        const testSession = {
          id: 'session_test_123',
          userId: testUserId,
          sessionToken: 'test_session_token',
          clientInfo: {
            userAgent: 'Test-Agent/1.0',
            ipAddress: '192.168.1.1',
            deviceId: 'test_device_123',
          },
          expiresAt: new Date(Date.now() + 86400000),
          lastActivityAt: new Date(),
          isRevoked: false,
          revokedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        await sessionRepository.save(testSession as any);

        const foundSession = await sessionRepository.findBySessionToken('test_session_token');
        expect(foundSession).toBeDefined();
        expect(foundSession?.userId).toBe(testUserId);
        expect(foundSession?.clientInfo.userAgent).toBe('Test-Agent/1.0');
      });

      it('should update session activity', async () => {
        const testSession = {
          id: 'activity_session_123',
          userId: testUserId,
          sessionToken: 'activity_session_token',
          clientInfo: {
            userAgent: 'Test-Agent/1.0',
            ipAddress: '192.168.1.1',
            deviceId: 'test_device_123',
          },
          expiresAt: new Date(Date.now() + 86400000),
          lastActivityAt: new Date(),
          isRevoked: false,
          revokedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        await sessionRepository.save(testSession as any);

        // Wait a moment to ensure timestamp difference
        await new Promise(resolve => setTimeout(resolve, 10));

        await sessionRepository.updateActivity('activity_session_123');

        const updatedSession = await sessionRepository.findById('activity_session_123');
        expect(updatedSession?.lastActivityAt.getTime()).toBeGreaterThan(
          testSession.lastActivityAt.getTime()
        );
      });

      it('should revoke sessions', async () => {
        const testSession = {
          id: 'revoke_session_123',
          userId: testUserId,
          sessionToken: 'revoke_session_token',
          clientInfo: {
            userAgent: 'Test-Agent/1.0',
            ipAddress: '192.168.1.1',
            deviceId: 'test_device_123',
          },
          expiresAt: new Date(Date.now() + 86400000),
          lastActivityAt: new Date(),
          isRevoked: false,
          revokedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        await sessionRepository.save(testSession as any);

        await sessionRepository.revoke('revoke_session_123');

        const revokedSession = await sessionRepository.findById('revoke_session_123');
        expect(revokedSession?.isRevoked).toBe(true);
        expect(revokedSession?.revokedAt).toBeInstanceOf(Date);
      });
    });
  });

  describe('Database Performance', () => {
    it('should execute queries within reasonable time', async () => {
      const startTime = Date.now();
      
      await dataSource.query(`
        SELECT 
          table_name,
          column_name,
          data_type 
        FROM information_schema.columns 
        WHERE table_schema = 'public'
        ORDER BY table_name, ordinal_position
      `);
      
      const executionTime = Date.now() - startTime;
      expect(executionTime).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should handle concurrent queries', async () => {
      const queries = Array.from({ length: 10 }, (_, i) => 
        dataSource.query(`SELECT ${i + 1} as query_number`)
      );

      const results = await Promise.all(queries);
      
      expect(results).toHaveLength(10);
      results.forEach((result, index) => {
        expect(result[0].query_number).toBe(index + 1);
      });
    });
  });
});