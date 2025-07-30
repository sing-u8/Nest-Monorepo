import { Test, TestingModule } from '@nestjs/testing';
import { TypeOrmModule, getRepositoryToken } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { ConfigModule } from '@nestjs/config';

// Domain entities
import { Token } from '../../../domain/entities/token.entity';
import { User } from '../../../domain/entities/user.entity';
import { TokenType } from '../../../domain/models/auth.models';

// Infrastructure
import { TokenOrmEntity } from '../../database/entities/token.orm-entity';
import { UserOrmEntity } from '../../database/entities/user.orm-entity';
import { TokenRepositoryImpl } from '../token.repository';
import { TokenRepository } from '../../../domain/ports/token.repository';
import { UserRepository } from '../../../domain/ports/user.repository';
import { UserRepositoryImpl } from '../user.repository';

// Test utilities
import { createTestToken, createTestUser } from '../../../test/test-utils';

/**
 * Token Repository Integration Tests
 * 
 * Tests the TokenRepositoryImpl with a real PostgreSQL test database
 * to ensure proper database operations and token management.
 */
describe('TokenRepository (Integration)', () => {
  let module: TestingModule;
  let tokenRepository: TokenRepository;
  let userRepository: UserRepository;
  let tokenOrmRepository: Repository<TokenOrmEntity>;
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
          entities: [TokenOrmEntity, UserOrmEntity],
          synchronize: true, // Only for tests
          dropSchema: true, // Clean database before tests
        }),
        TypeOrmModule.forFeature([TokenOrmEntity, UserOrmEntity]),
      ],
      providers: [
        {
          provide: TokenRepository,
          useClass: TokenRepositoryImpl,
        },
        {
          provide: UserRepository,
          useClass: UserRepositoryImpl,
        },
      ],
    }).compile();

    tokenRepository = module.get<TokenRepository>(TokenRepository);
    userRepository = module.get<UserRepository>(UserRepository);
    tokenOrmRepository = module.get<Repository<TokenOrmEntity>>(
      getRepositoryToken(TokenOrmEntity)
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
    await tokenOrmRepository.clear();
    await userOrmRepository.clear();

    // Create a test user for token operations
    testUser = createTestUser();
    await userRepository.save(testUser);
  });

  describe('save', () => {
    it('should save a new token to the database', async () => {
      // Arrange
      const token = createTestToken(testUser.id, TokenType.ACCESS);

      // Act
      const savedToken = await tokenRepository.save(token);

      // Assert
      expect(savedToken).toBeDefined();
      expect(savedToken.id).toBe(token.id);
      expect(savedToken.userId).toBe(testUser.id);
      expect(savedToken.type).toBe(TokenType.ACCESS);
      expect(savedToken.value).toBe(token.value);

      // Verify in database
      const dbToken = await tokenOrmRepository.findOne({
        where: { id: token.id },
      });
      expect(dbToken).toBeDefined();
      expect(dbToken?.userId).toBe(testUser.id);
    });

    it('should save both access and refresh tokens', async () => {
      // Arrange
      const accessToken = createTestToken(testUser.id, TokenType.ACCESS);
      const refreshToken = createTestToken(testUser.id, TokenType.REFRESH);

      // Act
      await tokenRepository.save(accessToken);
      await tokenRepository.save(refreshToken);

      // Assert
      const savedAccessToken = await tokenRepository.findById(accessToken.id);
      const savedRefreshToken = await tokenRepository.findById(refreshToken.id);

      expect(savedAccessToken?.type).toBe(TokenType.ACCESS);
      expect(savedRefreshToken?.type).toBe(TokenType.REFRESH);
    });

    it('should update an existing token', async () => {
      // Arrange
      const token = createTestToken(testUser.id, TokenType.ACCESS);
      await tokenRepository.save(token);

      // Act
      token.revoke();
      const updatedToken = await tokenRepository.save(token);

      // Assert
      expect(updatedToken.isRevoked).toBe(true);
      expect(updatedToken.revokedAt).toBeTruthy();

      // Verify in database
      const dbToken = await tokenOrmRepository.findOne({
        where: { id: token.id },
      });
      expect(dbToken?.isRevoked).toBe(true);
      expect(dbToken?.revokedAt).toBeTruthy();
    });

    it('should handle unique constraint on token value', async () => {
      // Arrange
      const tokenValue = 'unique-token-value-123';
      const token1 = createTestToken(testUser.id, TokenType.ACCESS, { value: tokenValue });
      const token2 = createTestToken(testUser.id, TokenType.ACCESS, { value: tokenValue });

      // Act
      await tokenRepository.save(token1);

      // Assert
      await expect(tokenRepository.save(token2)).rejects.toThrow();
    });
  });

  describe('findById', () => {
    it('should find a token by ID', async () => {
      // Arrange
      const token = createTestToken(testUser.id, TokenType.REFRESH);
      await tokenRepository.save(token);

      // Act
      const foundToken = await tokenRepository.findById(token.id);

      // Assert
      expect(foundToken).toBeDefined();
      expect(foundToken?.id).toBe(token.id);
      expect(foundToken?.userId).toBe(testUser.id);
      expect(foundToken?.type).toBe(TokenType.REFRESH);
    });

    it('should return null for non-existent ID', async () => {
      // Act
      const foundToken = await tokenRepository.findById('non-existent-id');

      // Assert
      expect(foundToken).toBeNull();
    });
  });

  describe('findByValue', () => {
    it('should find a token by its value', async () => {
      // Arrange
      const tokenValue = 'find-by-value-token-123';
      const token = createTestToken(testUser.id, TokenType.ACCESS, { value: tokenValue });
      await tokenRepository.save(token);

      // Act
      const foundToken = await tokenRepository.findByValue(tokenValue);

      // Assert
      expect(foundToken).toBeDefined();
      expect(foundToken?.value).toBe(tokenValue);
      expect(foundToken?.userId).toBe(testUser.id);
    });

    it('should return null for non-existent token value', async () => {
      // Act
      const foundToken = await tokenRepository.findByValue('non-existent-token');

      // Assert
      expect(foundToken).toBeNull();
    });

    it('should not find revoked tokens', async () => {
      // Arrange
      const tokenValue = 'revoked-token-123';
      const token = createTestToken(testUser.id, TokenType.ACCESS, { value: tokenValue });
      await tokenRepository.save(token);
      
      token.revoke();
      await tokenRepository.save(token);

      // Act
      const foundToken = await tokenRepository.findByValue(tokenValue);

      // Assert
      expect(foundToken).toBeNull();
    });
  });

  describe('findByUserId', () => {
    it('should find all tokens for a user', async () => {
      // Arrange
      const accessToken = createTestToken(testUser.id, TokenType.ACCESS);
      const refreshToken = createTestToken(testUser.id, TokenType.REFRESH);
      await tokenRepository.save(accessToken);
      await tokenRepository.save(refreshToken);

      // Act
      const userTokens = await tokenRepository.findByUserId(testUser.id);

      // Assert
      expect(userTokens).toHaveLength(2);
      expect(userTokens.some(t => t.type === TokenType.ACCESS)).toBe(true);
      expect(userTokens.some(t => t.type === TokenType.REFRESH)).toBe(true);
    });

    it('should find only active tokens by default', async () => {
      // Arrange
      const activeToken = createTestToken(testUser.id, TokenType.ACCESS);
      const revokedToken = createTestToken(testUser.id, TokenType.REFRESH);
      
      await tokenRepository.save(activeToken);
      await tokenRepository.save(revokedToken);
      
      revokedToken.revoke();
      await tokenRepository.save(revokedToken);

      // Act
      const userTokens = await tokenRepository.findByUserId(testUser.id);

      // Assert
      expect(userTokens).toHaveLength(1);
      expect(userTokens[0].id).toBe(activeToken.id);
      expect(userTokens[0].isRevoked).toBe(false);
    });

    it('should filter by token type', async () => {
      // Arrange
      const accessToken1 = createTestToken(testUser.id, TokenType.ACCESS);
      const accessToken2 = createTestToken(testUser.id, TokenType.ACCESS);
      const refreshToken = createTestToken(testUser.id, TokenType.REFRESH);
      
      await tokenRepository.save(accessToken1);
      await tokenRepository.save(accessToken2);
      await tokenRepository.save(refreshToken);

      // Act
      const accessTokens = await tokenRepository.findByUserId(testUser.id, TokenType.ACCESS);
      const refreshTokens = await tokenRepository.findByUserId(testUser.id, TokenType.REFRESH);

      // Assert
      expect(accessTokens).toHaveLength(2);
      expect(refreshTokens).toHaveLength(1);
      expect(accessTokens.every(t => t.type === TokenType.ACCESS)).toBe(true);
      expect(refreshTokens.every(t => t.type === TokenType.REFRESH)).toBe(true);
    });

    it('should return empty array for user with no tokens', async () => {
      // Act
      const userTokens = await tokenRepository.findByUserId('non-existent-user-id');

      // Assert
      expect(userTokens).toEqual([]);
    });
  });

  describe('revokeByUserId', () => {
    it('should revoke all tokens for a user', async () => {
      // Arrange
      const accessToken = createTestToken(testUser.id, TokenType.ACCESS);
      const refreshToken = createTestToken(testUser.id, TokenType.REFRESH);
      await tokenRepository.save(accessToken);
      await tokenRepository.save(refreshToken);

      // Act
      await tokenRepository.revokeByUserId(testUser.id);

      // Assert
      const userTokens = await tokenRepository.findByUserId(testUser.id, undefined, true);
      expect(userTokens).toHaveLength(2);
      expect(userTokens.every(t => t.isRevoked)).toBe(true);
      expect(userTokens.every(t => t.revokedAt)).toBeTruthy();
    });

    it('should revoke only tokens of specific type', async () => {
      // Arrange
      const accessToken = createTestToken(testUser.id, TokenType.ACCESS);
      const refreshToken = createTestToken(testUser.id, TokenType.REFRESH);
      await tokenRepository.save(accessToken);
      await tokenRepository.save(refreshToken);

      // Act
      await tokenRepository.revokeByUserId(testUser.id, TokenType.ACCESS);

      // Assert
      const allTokens = await tokenRepository.findByUserId(testUser.id, undefined, true);
      const accessTokenFound = allTokens.find(t => t.id === accessToken.id);
      const refreshTokenFound = allTokens.find(t => t.id === refreshToken.id);

      expect(accessTokenFound?.isRevoked).toBe(true);
      expect(refreshTokenFound?.isRevoked).toBe(false);
    });

    it('should handle revoking tokens for user with no tokens', async () => {
      // Act & Assert
      await expect(tokenRepository.revokeByUserId('non-existent-user-id'))
        .resolves.not.toThrow();
    });
  });

  describe('deleteExpired', () => {
    it('should delete expired tokens', async () => {
      // Arrange
      const expiredToken = createTestToken(testUser.id, TokenType.ACCESS, {
        expiresAt: new Date(Date.now() - 3600000), // 1 hour ago
      });
      const validToken = createTestToken(testUser.id, TokenType.REFRESH, {
        expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
      });
      
      await tokenRepository.save(expiredToken);
      await tokenRepository.save(validToken);

      // Act
      const deletedCount = await tokenRepository.deleteExpired();

      // Assert
      expect(deletedCount).toBe(1);

      const remainingTokens = await tokenRepository.findByUserId(testUser.id, undefined, true);
      expect(remainingTokens).toHaveLength(1);
      expect(remainingTokens[0].id).toBe(validToken.id);
    });

    it('should not delete non-expired tokens', async () => {
      // Arrange
      const futureToken = createTestToken(testUser.id, TokenType.ACCESS, {
        expiresAt: new Date(Date.now() + 86400000), // 1 day from now
      });
      await tokenRepository.save(futureToken);

      // Act
      const deletedCount = await tokenRepository.deleteExpired();

      // Assert
      expect(deletedCount).toBe(0);

      const tokens = await tokenRepository.findByUserId(testUser.id);
      expect(tokens).toHaveLength(1);
    });

    it('should handle database with no tokens', async () => {
      // Act
      const deletedCount = await tokenRepository.deleteExpired();

      // Assert
      expect(deletedCount).toBe(0);
    });
  });

  describe('countActiveByUserId', () => {
    it('should count active tokens for a user', async () => {
      // Arrange
      const activeToken1 = createTestToken(testUser.id, TokenType.ACCESS);
      const activeToken2 = createTestToken(testUser.id, TokenType.REFRESH);
      const revokedToken = createTestToken(testUser.id, TokenType.ACCESS);
      
      await tokenRepository.save(activeToken1);
      await tokenRepository.save(activeToken2);
      await tokenRepository.save(revokedToken);
      
      revokedToken.revoke();
      await tokenRepository.save(revokedToken);

      // Act
      const activeCount = await tokenRepository.countActiveByUserId(testUser.id);

      // Assert
      expect(activeCount).toBe(2);
    });

    it('should count tokens by type', async () => {
      // Arrange
      const accessToken1 = createTestToken(testUser.id, TokenType.ACCESS);
      const accessToken2 = createTestToken(testUser.id, TokenType.ACCESS);
      const refreshToken = createTestToken(testUser.id, TokenType.REFRESH);
      
      await tokenRepository.save(accessToken1);
      await tokenRepository.save(accessToken2);
      await tokenRepository.save(refreshToken);

      // Act
      const accessCount = await tokenRepository.countActiveByUserId(testUser.id, TokenType.ACCESS);
      const refreshCount = await tokenRepository.countActiveByUserId(testUser.id, TokenType.REFRESH);

      // Assert
      expect(accessCount).toBe(2);
      expect(refreshCount).toBe(1);
    });

    it('should return 0 for user with no tokens', async () => {
      // Act
      const count = await tokenRepository.countActiveByUserId('non-existent-user-id');

      // Assert
      expect(count).toBe(0);
    });
  });

  describe('Token expiration handling', () => {
    it('should handle tokens near expiration', async () => {
      // Arrange
      const soonToExpire = createTestToken(testUser.id, TokenType.ACCESS, {
        expiresAt: new Date(Date.now() + 1000), // 1 second from now
      });
      await tokenRepository.save(soonToExpire);

      // Act - Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 1100));
      const deletedCount = await tokenRepository.deleteExpired();

      // Assert
      expect(deletedCount).toBe(1);
    });

    it('should handle very old expired tokens', async () => {
      // Arrange
      const veryOldToken = createTestToken(testUser.id, TokenType.ACCESS, {
        expiresAt: new Date('2020-01-01'), // Very old date
      });
      await tokenRepository.save(veryOldToken);

      // Act
      const deletedCount = await tokenRepository.deleteExpired();

      // Assert
      expect(deletedCount).toBe(1);
    });
  });

  describe('Entity mapping', () => {
    it('should correctly map all Token entity properties', async () => {
      // Arrange
      const now = new Date();
      const token = createTestToken(testUser.id, TokenType.REFRESH, {
        value: 'test-token-value-123',
        expiresAt: new Date(now.getTime() + 86400000), // 1 day from now
        isRevoked: false,
        revokedAt: null,
      });

      // Act
      await tokenRepository.save(token);
      const retrievedToken = await tokenRepository.findById(token.id);

      // Assert
      expect(retrievedToken).toBeDefined();
      expect(retrievedToken?.id).toBe(token.id);
      expect(retrievedToken?.userId).toBe(token.userId);
      expect(retrievedToken?.type).toBe(token.type);
      expect(retrievedToken?.value).toBe(token.value);
      expect(retrievedToken?.expiresAt.getTime()).toBeCloseTo(token.expiresAt.getTime(), -3);
      expect(retrievedToken?.isRevoked).toBe(token.isRevoked);
      expect(retrievedToken?.revokedAt).toBe(token.revokedAt);
      expect(retrievedToken?.createdAt).toBeTruthy();
      expect(retrievedToken?.updatedAt).toBeTruthy();
    });
  });

  describe('Concurrent operations', () => {
    it('should handle concurrent token operations', async () => {
      // Arrange
      const tokens = Array.from({ length: 10 }, (_, i) => 
        createTestToken(testUser.id, i % 2 === 0 ? TokenType.ACCESS : TokenType.REFRESH)
      );

      // Act
      await Promise.all(tokens.map(token => tokenRepository.save(token)));

      // Assert
      const savedTokens = await tokenRepository.findByUserId(testUser.id);
      expect(savedTokens).toHaveLength(10);

      const accessTokens = savedTokens.filter(t => t.type === TokenType.ACCESS);
      const refreshTokens = savedTokens.filter(t => t.type === TokenType.REFRESH);
      expect(accessTokens).toHaveLength(5);
      expect(refreshTokens).toHaveLength(5);
    });
  });
});