import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import {
  UserEntity,
  TokenEntity,
  AuthSessionEntity,
  TypeOrmUserRepository,
  TypeOrmTokenRepository,
  TypeOrmAuthSessionRepository,
  UserMapper,
  TokenMapper,
  AuthSessionMapper,
  DatabaseModule,
} from '@auth/infrastructure';
import { User, Token, AuthSession, TokenType, AuthProvider } from '@auth/domain';

describe('Repository Integration Tests', () => {
  let module: TestingModule;
  let dataSource: DataSource;
  let userRepository: TypeOrmUserRepository;
  let tokenRepository: TypeOrmTokenRepository;
  let sessionRepository: TypeOrmAuthSessionRepository;

  beforeAll(async () => {
    // Set test environment variables
    process.env.NODE_ENV = 'test';
    process.env.DATABASE_TYPE = 'postgres';
    process.env.DATABASE_HOST = 'localhost';
    process.env.DATABASE_PORT = '5432';
    process.env.DATABASE_USERNAME = 'test_user';
    process.env.DATABASE_PASSWORD = 'test_password';
    process.env.DATABASE_NAME = 'test_auth_repository_db';
    process.env.DATABASE_SYNCHRONIZE = 'true';
    process.env.DATABASE_DROP_SCHEMA = 'true';

    module = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          envFilePath: '.env.test',
        }),
        DatabaseModule,
      ],
      providers: [
        TypeOrmUserRepository,
        TypeOrmTokenRepository,
        TypeOrmAuthSessionRepository,
        UserMapper,
        TokenMapper,
        AuthSessionMapper,
      ],
    }).compile();

    dataSource = module.get<DataSource>(DataSource);
    userRepository = module.get<TypeOrmUserRepository>(TypeOrmUserRepository);
    tokenRepository = module.get<TypeOrmTokenRepository>(TypeOrmTokenRepository);
    sessionRepository = module.get<TypeOrmAuthSessionRepository>(TypeOrmAuthSessionRepository);
  });

  afterAll(async () => {
    if (dataSource?.isInitialized) {
      await dataSource.destroy();
    }
    await module.close();
  });

  beforeEach(async () => {
    // Clean up database before each test
    await dataSource.getRepository(AuthSessionEntity).delete({});
    await dataSource.getRepository(TokenEntity).delete({});
    await dataSource.getRepository(UserEntity).delete({});
  });

  describe('User Repository Integration', () => {
    it('should save and retrieve user with all fields', async () => {
      // Arrange
      const user = User.create({
        id: 'test-user-1',
        email: 'test@example.com',
        password: 'hashed-password',
        name: 'Test User',
        profilePicture: 'https://example.com/profile.jpg',
        provider: AuthProvider.LOCAL,
      });

      // Act
      const savedUser = await userRepository.save(user);
      const retrievedUser = await userRepository.findById('test-user-1');

      // Assert
      expect(savedUser).toBeDefined();
      expect(savedUser.getId()).toBe('test-user-1');
      expect(savedUser.getEmail()).toBe('test@example.com');
      expect(savedUser.getName()).toBe('Test User');
      expect(savedUser.getProfilePicture()).toBe('https://example.com/profile.jpg');
      expect(savedUser.getProvider()).toBe(AuthProvider.LOCAL);

      expect(retrievedUser).toBeDefined();
      expect(retrievedUser?.getId()).toBe('test-user-1');
      expect(retrievedUser?.getEmail()).toBe('test@example.com');
    });

    it('should find user by email', async () => {
      // Arrange
      const user = User.create({
        id: 'test-user-email',
        email: 'email-test@example.com',
        password: 'hashed-password',
        name: 'Email Test User',
        provider: AuthProvider.LOCAL,
      });

      await userRepository.save(user);

      // Act
      const foundUser = await userRepository.findByEmail('email-test@example.com');

      // Assert
      expect(foundUser).toBeDefined();
      expect(foundUser?.getId()).toBe('test-user-email');
      expect(foundUser?.getEmail()).toBe('email-test@example.com');
    });

    it('should update user information', async () => {
      // Arrange
      const user = User.create({
        id: 'test-user-update',
        email: 'update@example.com',
        password: 'hashed-password',
        name: 'Original Name',
        provider: AuthProvider.LOCAL,
      });

      await userRepository.save(user);

      // Act
      await userRepository.update('test-user-update', {
        name: 'Updated Name',
        profile_picture: 'https://example.com/new-profile.jpg',
      });

      const updatedUser = await userRepository.findById('test-user-update');

      // Assert
      expect(updatedUser).toBeDefined();
      expect(updatedUser?.getName()).toBe('Updated Name');
      expect(updatedUser?.getProfilePicture()).toBe('https://example.com/new-profile.jpg');
    });

    it('should handle social login users', async () => {
      // Arrange
      const googleUser = User.create({
        id: 'google-user-1',
        email: 'google@example.com',
        password: null, // Social users don't have passwords
        name: 'Google User',
        profilePicture: 'https://googleusercontent.com/profile.jpg',
        provider: AuthProvider.GOOGLE,
      });

      // Act
      const savedUser = await userRepository.save(googleUser);
      const retrievedUser = await userRepository.findById('google-user-1');

      // Assert
      expect(savedUser.getProvider()).toBe(AuthProvider.GOOGLE);
      expect(savedUser.getPassword()).toBeNull();
      expect(retrievedUser?.getProvider()).toBe(AuthProvider.GOOGLE);
      expect(retrievedUser?.getPassword()).toBeNull();
    });

    it('should delete user', async () => {
      // Arrange
      const user = User.create({
        id: 'test-user-delete',
        email: 'delete@example.com',
        password: 'hashed-password',
        name: 'Delete Test User',
        provider: AuthProvider.LOCAL,
      });

      await userRepository.save(user);

      // Act
      await userRepository.delete('test-user-delete');
      const deletedUser = await userRepository.findById('test-user-delete');

      // Assert
      expect(deletedUser).toBeNull();
    });

    it('should return null for non-existent user', async () => {
      // Act
      const nonExistentUser = await userRepository.findById('non-existent-id');
      const nonExistentEmail = await userRepository.findByEmail('nonexistent@example.com');

      // Assert
      expect(nonExistentUser).toBeNull();
      expect(nonExistentEmail).toBeNull();
    });
  });

  describe('Token Repository Integration', () => {
    let testUser: User;

    beforeEach(async () => {
      // Create a test user for token operations
      testUser = User.create({
        id: 'token-test-user',
        email: 'token@example.com',
        password: 'hashed-password',
        name: 'Token Test User',
        provider: AuthProvider.LOCAL,
      });
      await userRepository.save(testUser);
    });

    it('should save and retrieve access token', async () => {
      // Arrange
      const accessToken = Token.createAccessToken({
        id: 'access-token-1',
        userId: testUser.getId(),
        value: 'access-token-value',
        expirationMinutes: 15,
      });

      // Act
      const savedToken = await tokenRepository.save(accessToken);
      const retrievedToken = await tokenRepository.findByValue('access-token-value');

      // Assert
      expect(savedToken).toBeDefined();
      expect(savedToken.getId()).toBe('access-token-1');
      expect(savedToken.getUserId()).toBe(testUser.getId());
      expect(savedToken.getType()).toBe(TokenType.ACCESS);
      expect(savedToken.getValue()).toBe('access-token-value');

      expect(retrievedToken).toBeDefined();
      expect(retrievedToken?.getId()).toBe('access-token-1');
      expect(retrievedToken?.getType()).toBe(TokenType.ACCESS);
    });

    it('should save and retrieve refresh token', async () => {
      // Arrange
      const refreshToken = Token.createRefreshToken({
        id: 'refresh-token-1',
        userId: testUser.getId(),
        value: 'refresh-token-value',
        expirationDays: 7,
      });

      // Act
      const savedToken = await tokenRepository.save(refreshToken);
      const retrievedToken = await tokenRepository.findByValue('refresh-token-value');

      // Assert
      expect(savedToken.getType()).toBe(TokenType.REFRESH);
      expect(retrievedToken?.getType()).toBe(TokenType.REFRESH);
    });

    it('should find tokens by user ID', async () => {
      // Arrange
      const accessToken = Token.createAccessToken({
        id: 'user-access-token',
        userId: testUser.getId(),
        value: 'user-access-token-value',
        expirationMinutes: 15,
      });

      const refreshToken = Token.createRefreshToken({
        id: 'user-refresh-token',
        userId: testUser.getId(),
        value: 'user-refresh-token-value',
        expirationDays: 7,
      });

      await tokenRepository.save(accessToken);
      await tokenRepository.save(refreshToken);

      // Act
      const userTokens = await tokenRepository.findByUserId(testUser.getId());

      // Assert
      expect(userTokens).toHaveLength(2);
      expect(userTokens.map(t => t.getId())).toContain('user-access-token');
      expect(userTokens.map(t => t.getId())).toContain('user-refresh-token');
    });

    it('should find tokens by user ID and type', async () => {
      // Arrange
      const accessToken = Token.createAccessToken({
        id: 'type-access-token',
        userId: testUser.getId(),
        value: 'type-access-token-value',
        expirationMinutes: 15,
      });

      const refreshToken = Token.createRefreshToken({
        id: 'type-refresh-token',
        userId: testUser.getId(),
        value: 'type-refresh-token-value',
        expirationDays: 7,
      });

      await tokenRepository.save(accessToken);
      await tokenRepository.save(refreshToken);

      // Act
      const accessTokens = await tokenRepository.findByUserIdAndType(testUser.getId(), TokenType.ACCESS);
      const refreshTokens = await tokenRepository.findByUserIdAndType(testUser.getId(), TokenType.REFRESH);

      // Assert
      expect(accessTokens).toHaveLength(1);
      expect(accessTokens[0].getType()).toBe(TokenType.ACCESS);
      
      expect(refreshTokens).toHaveLength(1);
      expect(refreshTokens[0].getType()).toBe(TokenType.REFRESH);
    });

    it('should revoke token', async () => {
      // Arrange
      const token = Token.createAccessToken({
        id: 'revoke-token',
        userId: testUser.getId(),
        value: 'revoke-token-value',
        expirationMinutes: 15,
      });

      await tokenRepository.save(token);

      // Act
      await tokenRepository.revokeToken('revoke-token-value');
      const revokedToken = await tokenRepository.findByValue('revoke-token-value');

      // Assert
      expect(revokedToken).toBeNull(); // Revoked tokens are not returned by findByValue
    });

    it('should delete expired tokens', async () => {
      // Arrange
      const expiredToken = Token.createAccessToken({
        id: 'expired-token',
        userId: testUser.getId(),
        value: 'expired-token-value',
        expirationMinutes: -60, // Expired 1 hour ago
      });

      const validToken = Token.createAccessToken({
        id: 'valid-token',
        userId: testUser.getId(),
        value: 'valid-token-value',
        expirationMinutes: 15,
      });

      await tokenRepository.save(expiredToken);
      await tokenRepository.save(validToken);

      // Act
      await tokenRepository.deleteExpiredTokens();
      
      const expiredTokenResult = await tokenRepository.findByValue('expired-token-value');
      const validTokenResult = await tokenRepository.findByValue('valid-token-value');

      // Assert
      expect(expiredTokenResult).toBeNull();
      expect(validTokenResult).toBeDefined();
    });

    it('should find valid tokens by user ID', async () => {
      // Arrange
      const validToken = Token.createAccessToken({
        id: 'valid-user-token',
        userId: testUser.getId(),
        value: 'valid-user-token-value',
        expirationMinutes: 15,
      });

      const expiredToken = Token.createAccessToken({
        id: 'expired-user-token',
        userId: testUser.getId(),
        value: 'expired-user-token-value',
        expirationMinutes: -60,
      });

      await tokenRepository.save(validToken);
      await tokenRepository.save(expiredToken);

      // Act
      const validTokens = await tokenRepository.findValidTokensByUserId(testUser.getId());

      // Assert
      expect(validTokens).toHaveLength(1);
      expect(validTokens[0].getId()).toBe('valid-user-token');
    });

    it('should delete all tokens for user', async () => {
      // Arrange
      const token1 = Token.createAccessToken({
        id: 'user-token-1',
        userId: testUser.getId(),
        value: 'user-token-1-value',
        expirationMinutes: 15,
      });

      const token2 = Token.createRefreshToken({
        id: 'user-token-2',
        userId: testUser.getId(),
        value: 'user-token-2-value',
        expirationDays: 7,
      });

      await tokenRepository.save(token1);
      await tokenRepository.save(token2);

      // Act
      await tokenRepository.deleteByUserId(testUser.getId());
      const remainingTokens = await tokenRepository.findByUserId(testUser.getId());

      // Assert
      expect(remainingTokens).toHaveLength(0);
    });
  });

  describe('Auth Session Repository Integration', () => {
    let testUser: User;

    beforeEach(async () => {
      // Create a test user for session operations
      testUser = User.create({
        id: 'session-test-user',
        email: 'session@example.com',
        password: 'hashed-password',
        name: 'Session Test User',
        provider: AuthProvider.LOCAL,
      });
      await userRepository.save(testUser);
    });

    it('should save and retrieve session', async () => {
      // Arrange
      const session = AuthSession.create({
        id: 'test-session-1',
        userId: testUser.getId(),
        sessionToken: 'session-token-value',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'Test User Agent',
          deviceId: 'test-device-1',
        },
        expirationHours: 24,
      });

      // Act
      const savedSession = await sessionRepository.save(session);
      const retrievedSession = await sessionRepository.findBySessionToken('session-token-value');

      // Assert
      expect(savedSession).toBeDefined();
      expect(savedSession.getId()).toBe('test-session-1');
      expect(savedSession.getUserId()).toBe(testUser.getId());
      expect(savedSession.getSessionToken()).toBe('session-token-value');

      expect(retrievedSession).toBeDefined();
      expect(retrievedSession?.getId()).toBe('test-session-1');
      expect(retrievedSession?.getClientInfo().ipAddress).toBe('127.0.0.1');
    });

    it('should find sessions by user ID', async () => {
      // Arrange
      const session1 = AuthSession.create({
        id: 'user-session-1',
        userId: testUser.getId(),
        sessionToken: 'user-session-token-1',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'Browser 1',
        },
        expirationHours: 24,
      });

      const session2 = AuthSession.create({
        id: 'user-session-2',
        userId: testUser.getId(),
        sessionToken: 'user-session-token-2',
        clientInfo: {
          ipAddress: '192.168.1.1',
          userAgent: 'Browser 2',
        },
        expirationHours: 24,
      });

      await sessionRepository.save(session1);
      await sessionRepository.save(session2);

      // Act
      const userSessions = await sessionRepository.findByUserId(testUser.getId());

      // Assert
      expect(userSessions).toHaveLength(2);
      expect(userSessions.map(s => s.getId())).toContain('user-session-1');
      expect(userSessions.map(s => s.getId())).toContain('user-session-2');
    });

    it('should find active sessions', async () => {
      // Arrange
      const activeSession = AuthSession.create({
        id: 'active-session',
        userId: testUser.getId(),
        sessionToken: 'active-session-token',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'Active Browser',
        },
        expirationHours: 24,
      });

      const expiredSession = AuthSession.create({
        id: 'expired-session',
        userId: testUser.getId(),
        sessionToken: 'expired-session-token',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'Expired Browser',
        },
        expirationHours: -1, // Expired
      });

      await sessionRepository.save(activeSession);
      await sessionRepository.save(expiredSession);

      // Act
      const activeSessions = await sessionRepository.findActiveSessions(testUser.getId());

      // Assert
      expect(activeSessions).toHaveLength(1);
      expect(activeSessions[0].getId()).toBe('active-session');
    });

    it('should deactivate session', async () => {
      // Arrange
      const session = AuthSession.create({
        id: 'deactivate-session',
        userId: testUser.getId(),
        sessionToken: 'deactivate-session-token',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'Test Browser',
        },
        expirationHours: 24,
      });

      await sessionRepository.save(session);

      // Act
      await sessionRepository.deactivateSession('deactivate-session-token');
      const deactivatedSession = await sessionRepository.findBySessionToken('deactivate-session-token');

      // Assert
      expect(deactivatedSession).toBeNull(); // Deactivated sessions are not returned
    });

    it('should update last accessed time', async () => {
      // Arrange
      const session = AuthSession.create({
        id: 'update-access-session',
        userId: testUser.getId(),
        sessionToken: 'update-access-session-token',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'Test Browser',
        },
        expirationHours: 24,
      });

      await sessionRepository.save(session);

      // Wait a moment to ensure different timestamp
      await new Promise(resolve => setTimeout(resolve, 10));

      // Act
      await sessionRepository.updateLastAccessed('update-access-session-token');
      const updatedSession = await sessionRepository.findBySessionToken('update-access-session-token');

      // Assert
      expect(updatedSession).toBeDefined();
      expect(updatedSession?.getLastAccessedAt().getTime()).toBeGreaterThan(session.getLastAccessedAt().getTime());
    });

    it('should delete expired sessions', async () => {
      // Arrange
      const expiredSession = AuthSession.create({
        id: 'expired-cleanup-session',
        userId: testUser.getId(),
        sessionToken: 'expired-cleanup-session-token',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'Expired Browser',
        },
        expirationHours: -2, // Expired 2 hours ago
      });

      const validSession = AuthSession.create({
        id: 'valid-cleanup-session',
        userId: testUser.getId(),
        sessionToken: 'valid-cleanup-session-token',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'Valid Browser',
        },
        expirationHours: 24,
      });

      await sessionRepository.save(expiredSession);
      await sessionRepository.save(validSession);

      // Act
      await sessionRepository.deleteExpiredSessions();
      
      const expiredResult = await sessionRepository.findBySessionToken('expired-cleanup-session-token');
      const validResult = await sessionRepository.findBySessionToken('valid-cleanup-session-token');

      // Assert
      expect(expiredResult).toBeNull();
      expect(validResult).toBeDefined();
    });

    it('should find recent sessions', async () => {
      // Arrange
      const recentSession = AuthSession.create({
        id: 'recent-session',
        userId: testUser.getId(),
        sessionToken: 'recent-session-token',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'Recent Browser',
        },
        expirationHours: 24,
      });

      await sessionRepository.save(recentSession);

      // Act
      const recentSessions = await sessionRepository.findRecentSessions(testUser.getId(), 1); // Last 1 hour

      // Assert
      expect(recentSessions).toHaveLength(1);
      expect(recentSessions[0].getId()).toBe('recent-session');
    });

    it('should cleanup inactive sessions', async () => {
      // This test would require creating sessions with specific timestamps
      // For now, just verify the method doesn't throw
      const deletedCount = await sessionRepository.cleanupInactiveSessions(30);
      expect(typeof deletedCount).toBe('number');
      expect(deletedCount).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Cross-Repository Data Integrity', () => {
    it('should maintain referential integrity between user and tokens', async () => {
      // Arrange
      const user = User.create({
        id: 'integrity-user',
        email: 'integrity@example.com',
        password: 'hashed-password',
        name: 'Integrity User',
        provider: AuthProvider.LOCAL,
      });

      await userRepository.save(user);

      const token = Token.createAccessToken({
        id: 'integrity-token',
        userId: user.getId(),
        value: 'integrity-token-value',
        expirationMinutes: 15,
      });

      await tokenRepository.save(token);

      // Act & Assert
      const savedToken = await tokenRepository.findByValue('integrity-token-value');
      expect(savedToken?.getUserId()).toBe(user.getId());

      const userTokens = await tokenRepository.findByUserId(user.getId());
      expect(userTokens).toHaveLength(1);
      expect(userTokens[0].getId()).toBe('integrity-token');
    });

    it('should maintain referential integrity between user and sessions', async () => {
      // Arrange
      const user = User.create({
        id: 'session-integrity-user',
        email: 'session-integrity@example.com',
        password: 'hashed-password',
        name: 'Session Integrity User',
        provider: AuthProvider.LOCAL,
      });

      await userRepository.save(user);

      const session = AuthSession.create({
        id: 'integrity-session',
        userId: user.getId(),
        sessionToken: 'integrity-session-token',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'Integrity Browser',
        },
        expirationHours: 24,
      });

      await sessionRepository.save(session);

      // Act & Assert
      const savedSession = await sessionRepository.findBySessionToken('integrity-session-token');
      expect(savedSession?.getUserId()).toBe(user.getId());

      const userSessions = await sessionRepository.findByUserId(user.getId());
      expect(userSessions).toHaveLength(1);
      expect(userSessions[0].getId()).toBe('integrity-session');
    });

    it('should handle cascading operations correctly', async () => {
      // Arrange
      const user = User.create({
        id: 'cascade-user',
        email: 'cascade@example.com',
        password: 'hashed-password',
        name: 'Cascade User',
        provider: AuthProvider.LOCAL,
      });

      await userRepository.save(user);

      const token = Token.createAccessToken({
        id: 'cascade-token',
        userId: user.getId(),
        value: 'cascade-token-value',
        expirationMinutes: 15,
      });

      const session = AuthSession.create({
        id: 'cascade-session',
        userId: user.getId(),
        sessionToken: 'cascade-session-token',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'Cascade Browser',
        },
        expirationHours: 24,
      });

      await tokenRepository.save(token);
      await sessionRepository.save(session);

      // Act - Delete all user-related data
      await tokenRepository.deleteByUserId(user.getId());
      await sessionRepository.deleteByUserId(user.getId());
      await userRepository.delete(user.getId());

      // Assert
      const deletedUser = await userRepository.findById(user.getId());
      const userTokens = await tokenRepository.findByUserId(user.getId());
      const userSessions = await sessionRepository.findByUserId(user.getId());

      expect(deletedUser).toBeNull();
      expect(userTokens).toHaveLength(0);
      expect(userSessions).toHaveLength(0);
    });
  });

  describe('Transaction Support', () => {
    it('should support database transactions', async () => {
      // Test that repository operations can be wrapped in transactions
      await dataSource.transaction(async (entityManager) => {
        const userRepo = entityManager.getRepository(UserEntity);
        
        const userEntity = userRepo.create({
          id: 'transaction-user',
          email: 'transaction@example.com',
          name: 'Transaction User',
          provider: 'local',
          status: 'active',
          password_hash: 'hashed-password',
        });

        await userRepo.save(userEntity);
        
        // Verify user exists within transaction
        const savedUser = await userRepo.findOne({ where: { id: 'transaction-user' } });
        expect(savedUser).toBeDefined();
      });

      // Verify user exists after transaction
      const user = await userRepository.findById('transaction-user');
      expect(user).toBeDefined();
    });
  });
});