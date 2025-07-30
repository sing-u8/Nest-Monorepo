import { Test, TestingModule } from '@nestjs/testing';
import { TypeOrmModule, getRepositoryToken } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { ConfigModule } from '@nestjs/config';

// Domain entities
import { User } from '../../../domain/entities/user.entity';
import { AuthProvider } from '../../../domain/models/auth.models';

// Infrastructure
import { UserOrmEntity } from '../../database/entities/user.orm-entity';
import { UserRepositoryImpl } from '../user.repository';
import { UserRepository } from '../../../domain/ports/user.repository';

// Test utilities
import { createTestUser } from '../../../test/test-utils';

/**
 * User Repository Integration Tests
 * 
 * Tests the UserRepositoryImpl with a real PostgreSQL test database
 * to ensure proper database operations and entity mapping.
 */
describe('UserRepository (Integration)', () => {
  let module: TestingModule;
  let userRepository: UserRepository;
  let ormRepository: Repository<UserOrmEntity>;
  let dataSource: DataSource;

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
          entities: [UserOrmEntity],
          synchronize: true, // Only for tests
          dropSchema: true, // Clean database before tests
        }),
        TypeOrmModule.forFeature([UserOrmEntity]),
      ],
      providers: [
        {
          provide: UserRepository,
          useClass: UserRepositoryImpl,
        },
      ],
    }).compile();

    userRepository = module.get<UserRepository>(UserRepository);
    ormRepository = module.get<Repository<UserOrmEntity>>(
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
    await ormRepository.clear();
  });

  describe('save', () => {
    it('should save a new user to the database', async () => {
      // Arrange
      const user = createTestUser({
        email: 'test@example.com',
        name: 'Test User',
      });

      // Act
      const savedUser = await userRepository.save(user);

      // Assert
      expect(savedUser).toBeDefined();
      expect(savedUser.id).toBe(user.id);
      expect(savedUser.email).toBe(user.email);
      expect(savedUser.name).toBe(user.name);

      // Verify in database
      const dbUser = await ormRepository.findOne({
        where: { id: user.id },
      });
      expect(dbUser).toBeDefined();
      expect(dbUser?.email).toBe(user.email);
    });

    it('should update an existing user', async () => {
      // Arrange
      const user = createTestUser();
      await userRepository.save(user);

      // Act
      user.updateProfile('Updated Name', 'https://example.com/pic.jpg');
      const updatedUser = await userRepository.save(user);

      // Assert
      expect(updatedUser.name).toBe('Updated Name');
      expect(updatedUser.profilePicture).toBe('https://example.com/pic.jpg');

      // Verify in database
      const dbUser = await ormRepository.findOne({
        where: { id: user.id },
      });
      expect(dbUser?.name).toBe('Updated Name');
      expect(dbUser?.profilePicture).toBe('https://example.com/pic.jpg');
    });

    it('should handle unique constraint violations', async () => {
      // Arrange
      const email = 'duplicate@example.com';
      const user1 = createTestUser({ email });
      const user2 = createTestUser({ email });

      // Act
      await userRepository.save(user1);

      // Assert
      await expect(userRepository.save(user2)).rejects.toThrow();
    });

    it('should save OAuth provider information', async () => {
      // Arrange
      const user = createTestUser({
        authProvider: AuthProvider.GOOGLE,
        providerId: 'google_123456',
      });

      // Act
      const savedUser = await userRepository.save(user);

      // Assert
      expect(savedUser.authProvider).toBe(AuthProvider.GOOGLE);
      expect(savedUser.providerId).toBe('google_123456');

      // Verify in database
      const dbUser = await ormRepository.findOne({
        where: { id: user.id },
      });
      expect(dbUser?.authProvider).toBe(AuthProvider.GOOGLE);
      expect(dbUser?.providerId).toBe('google_123456');
    });
  });

  describe('findById', () => {
    it('should find a user by ID', async () => {
      // Arrange
      const user = createTestUser();
      await userRepository.save(user);

      // Act
      const foundUser = await userRepository.findById(user.id);

      // Assert
      expect(foundUser).toBeDefined();
      expect(foundUser?.id).toBe(user.id);
      expect(foundUser?.email).toBe(user.email);
    });

    it('should return null for non-existent ID', async () => {
      // Act
      const foundUser = await userRepository.findById('non-existent-id');

      // Assert
      expect(foundUser).toBeNull();
    });
  });

  describe('findByEmail', () => {
    it('should find a user by email', async () => {
      // Arrange
      const email = 'findbyemail@example.com';
      const user = createTestUser({ email });
      await userRepository.save(user);

      // Act
      const foundUser = await userRepository.findByEmail(email);

      // Assert
      expect(foundUser).toBeDefined();
      expect(foundUser?.email).toBe(email);
      expect(foundUser?.id).toBe(user.id);
    });

    it('should return null for non-existent email', async () => {
      // Act
      const foundUser = await userRepository.findByEmail('nonexistent@example.com');

      // Assert
      expect(foundUser).toBeNull();
    });

    it('should handle email case sensitivity properly', async () => {
      // Arrange
      const email = 'CaseSensitive@Example.com';
      const user = createTestUser({ email: email.toLowerCase() });
      await userRepository.save(user);

      // Act
      const foundUser = await userRepository.findByEmail(email.toLowerCase());

      // Assert
      expect(foundUser).toBeDefined();
      expect(foundUser?.email).toBe(email.toLowerCase());
    });
  });

  describe('existsByEmail', () => {
    it('should return true for existing email', async () => {
      // Arrange
      const email = 'exists@example.com';
      const user = createTestUser({ email });
      await userRepository.save(user);

      // Act
      const exists = await userRepository.existsByEmail(email);

      // Assert
      expect(exists).toBe(true);
    });

    it('should return false for non-existent email', async () => {
      // Act
      const exists = await userRepository.existsByEmail('notexists@example.com');

      // Assert
      expect(exists).toBe(false);
    });
  });

  describe('update', () => {
    it('should update user fields', async () => {
      // Arrange
      const user = createTestUser();
      await userRepository.save(user);

      // Act
      const updateData = {
        name: 'Updated Name',
        profilePicture: 'https://example.com/new-pic.jpg',
        emailVerified: true,
      };
      await userRepository.update(user.id, updateData);

      // Assert
      const updatedUser = await userRepository.findById(user.id);
      expect(updatedUser?.name).toBe(updateData.name);
      expect(updatedUser?.profilePicture).toBe(updateData.profilePicture);
      expect(updatedUser?.emailVerified).toBe(true);
    });

    it('should track lastLoginAt updates', async () => {
      // Arrange
      const user = createTestUser();
      await userRepository.save(user);
      const loginTime = new Date();

      // Act
      await userRepository.update(user.id, { lastLoginAt: loginTime });

      // Assert
      const updatedUser = await userRepository.findById(user.id);
      expect(updatedUser?.lastLoginAt).toBeTruthy();
      expect(updatedUser?.lastLoginAt?.getTime()).toBeCloseTo(loginTime.getTime(), -3);
    });

    it('should not update non-existent users', async () => {
      // Act & Assert
      await expect(userRepository.update('non-existent-id', { name: 'Test' }))
        .resolves.not.toThrow();
      
      // Verify no users were created
      const count = await ormRepository.count();
      expect(count).toBe(0);
    });
  });

  describe('deactivate', () => {
    it('should deactivate an active user', async () => {
      // Arrange
      const user = createTestUser({ isActive: true });
      await userRepository.save(user);

      // Act
      await userRepository.deactivate(user.id);

      // Assert
      const deactivatedUser = await userRepository.findById(user.id);
      expect(deactivatedUser?.isActive).toBe(false);
    });

    it('should handle deactivating already inactive users', async () => {
      // Arrange
      const user = createTestUser({ isActive: false });
      await userRepository.save(user);

      // Act
      await userRepository.deactivate(user.id);

      // Assert
      const stillInactiveUser = await userRepository.findById(user.id);
      expect(stillInactiveUser?.isActive).toBe(false);
    });
  });

  describe('activate', () => {
    it('should activate an inactive user', async () => {
      // Arrange
      const user = createTestUser({ isActive: false });
      await userRepository.save(user);

      // Act
      await userRepository.activate(user.id);

      // Assert
      const activatedUser = await userRepository.findById(user.id);
      expect(activatedUser?.isActive).toBe(true);
    });
  });

  describe('delete', () => {
    it('should delete a user from the database', async () => {
      // Arrange
      const user = createTestUser();
      await userRepository.save(user);

      // Act
      await userRepository.delete(user.id);

      // Assert
      const deletedUser = await userRepository.findById(user.id);
      expect(deletedUser).toBeNull();

      // Verify in database
      const dbUser = await ormRepository.findOne({
        where: { id: user.id },
      });
      expect(dbUser).toBeNull();
    });

    it('should handle deleting non-existent users', async () => {
      // Act & Assert
      await expect(userRepository.delete('non-existent-id'))
        .resolves.not.toThrow();
    });
  });

  describe('findByProvider', () => {
    it('should find a user by provider and provider ID', async () => {
      // Arrange
      const user = createTestUser({
        authProvider: AuthProvider.APPLE,
        providerId: 'apple_unique_123',
      });
      await userRepository.save(user);

      // Act
      const foundUser = await userRepository.findByProvider(
        AuthProvider.APPLE,
        'apple_unique_123'
      );

      // Assert
      expect(foundUser).toBeDefined();
      expect(foundUser?.id).toBe(user.id);
      expect(foundUser?.authProvider).toBe(AuthProvider.APPLE);
      expect(foundUser?.providerId).toBe('apple_unique_123');
    });

    it('should return null for non-existent provider combination', async () => {
      // Act
      const foundUser = await userRepository.findByProvider(
        AuthProvider.GOOGLE,
        'non_existent_id'
      );

      // Assert
      expect(foundUser).toBeNull();
    });

    it('should handle multiple users with different providers', async () => {
      // Arrange
      const googleUser = createTestUser({
        email: 'google@example.com',
        authProvider: AuthProvider.GOOGLE,
        providerId: 'google_123',
      });
      const appleUser = createTestUser({
        email: 'apple@example.com',
        authProvider: AuthProvider.APPLE,
        providerId: 'apple_123',
      });
      await userRepository.save(googleUser);
      await userRepository.save(appleUser);

      // Act
      const foundGoogleUser = await userRepository.findByProvider(
        AuthProvider.GOOGLE,
        'google_123'
      );
      const foundAppleUser = await userRepository.findByProvider(
        AuthProvider.APPLE,
        'apple_123'
      );

      // Assert
      expect(foundGoogleUser?.id).toBe(googleUser.id);
      expect(foundAppleUser?.id).toBe(appleUser.id);
    });
  });

  describe('Entity mapping', () => {
    it('should correctly map all User entity properties', async () => {
      // Arrange
      const now = new Date();
      const user = createTestUser({
        email: 'mapping@example.com',
        name: 'Mapping Test',
        profilePicture: 'https://example.com/pic.jpg',
        isActive: true,
        emailVerified: true,
        authProvider: AuthProvider.LOCAL,
        providerId: null,
        lastLoginAt: now,
      });

      // Act
      await userRepository.save(user);
      const retrievedUser = await userRepository.findById(user.id);

      // Assert
      expect(retrievedUser).toBeDefined();
      expect(retrievedUser?.id).toBe(user.id);
      expect(retrievedUser?.email).toBe(user.email);
      expect(retrievedUser?.passwordHash).toBe(user.passwordHash);
      expect(retrievedUser?.name).toBe(user.name);
      expect(retrievedUser?.profilePicture).toBe(user.profilePicture);
      expect(retrievedUser?.isActive).toBe(user.isActive);
      expect(retrievedUser?.emailVerified).toBe(user.emailVerified);
      expect(retrievedUser?.authProvider).toBe(user.authProvider);
      expect(retrievedUser?.providerId).toBe(user.providerId);
      expect(retrievedUser?.lastLoginAt).toBeTruthy();
      expect(retrievedUser?.createdAt).toBeTruthy();
      expect(retrievedUser?.updatedAt).toBeTruthy();
    });
  });

  describe('Concurrent operations', () => {
    it('should handle concurrent saves without data loss', async () => {
      // Arrange
      const users = Array.from({ length: 10 }, (_, i) => 
        createTestUser({ email: `concurrent${i}@example.com` })
      );

      // Act
      await Promise.all(users.map(user => userRepository.save(user)));

      // Assert
      const count = await ormRepository.count();
      expect(count).toBe(10);

      // Verify all users were saved
      for (const user of users) {
        const found = await userRepository.findById(user.id);
        expect(found).toBeDefined();
        expect(found?.email).toBe(user.email);
      }
    });
  });
});