import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '@auth/domain';
import { AuthProvider, UserStatus } from '@auth/shared';
import { TypeOrmUserRepository } from './typeorm-user.repository';
import { UserEntity } from '../database/entities/user.entity';

describe('TypeOrmUserRepository', () => {
  let repository: TypeOrmUserRepository;
  let mockRepository: jest.Mocked<Repository<UserEntity>>;

  const mockUserEntity: UserEntity = {
    id: 'user123',
    email: 'test@example.com',
    password: 'hashedPassword123',
    name: 'Test User',
    profile_picture: 'https://example.com/profile.jpg',
    provider: 'local',
    provider_id: null,
    email_verified: true,
    status: 'active',
    last_login_at: new Date('2023-01-01'),
    created_at: new Date('2023-01-01'),
    updated_at: new Date('2023-01-01'),
  };

  beforeEach(async () => {
    const mockRepo = {
      findOne: jest.fn(),
      find: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
      count: jest.fn(),
      update: jest.fn(),
      createQueryBuilder: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TypeOrmUserRepository,
        {
          provide: getRepositoryToken(UserEntity),
          useValue: mockRepo,
        },
      ],
    }).compile();

    repository = module.get<TypeOrmUserRepository>(TypeOrmUserRepository);
    mockRepository = module.get(getRepositoryToken(UserEntity));
  });

  describe('findById', () => {
    it('should find user by ID', async () => {
      mockRepository.findOne.mockResolvedValue(mockUserEntity);

      const result = await repository.findById('user123');

      expect(mockRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'user123' }
      });
      expect(result).toBeInstanceOf(User);
      expect(result?.id).toBe('user123');
    });

    it('should return null when user not found', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      const result = await repository.findById('nonexistent');

      expect(result).toBeNull();
    });

    it('should handle database errors', async () => {
      mockRepository.findOne.mockRejectedValue(new Error('Database error'));

      await expect(repository.findById('user123')).rejects.toThrow(
        'Failed to find user by ID: user123'
      );
    });
  });

  describe('findByEmail', () => {
    it('should find user by email', async () => {
      mockRepository.findOne.mockResolvedValue(mockUserEntity);

      const result = await repository.findByEmail('test@example.com');

      expect(mockRepository.findOne).toHaveBeenCalledWith({
        where: { email: 'test@example.com' }
      });
      expect(result).toBeInstanceOf(User);
      expect(result?.email).toBe('test@example.com');
    });

    it('should return null when user not found', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      const result = await repository.findByEmail('nonexistent@example.com');

      expect(result).toBeNull();
    });
  });

  describe('findByProviderId', () => {
    it('should find user by provider ID', async () => {
      const socialUser = {
        ...mockUserEntity,
        provider: 'google',
        provider_id: 'google123',
      };
      mockRepository.findOne.mockResolvedValue(socialUser);

      const result = await repository.findByProviderId('google', 'google123');

      expect(mockRepository.findOne).toHaveBeenCalledWith({
        where: { 
          provider: 'google',
          provider_id: 'google123'
        }
      });
      expect(result).toBeInstanceOf(User);
    });
  });

  describe('save', () => {
    it('should create new user', async () => {
      const domainUser = User.create({
        id: 'user123',
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User',
        provider: AuthProvider.LOCAL,
      });

      mockRepository.findOne.mockResolvedValue(null); // User doesn't exist
      mockRepository.save.mockResolvedValue(mockUserEntity);

      const result = await repository.save(domainUser);

      expect(mockRepository.save).toHaveBeenCalled();
      expect(result).toBeInstanceOf(User);
    });

    it('should update existing user', async () => {
      const domainUser = User.create({
        id: 'user123',
        email: 'test@example.com',
        password: 'password123',
        name: 'Updated User',
        provider: AuthProvider.LOCAL,
      });

      mockRepository.findOne.mockResolvedValue(mockUserEntity); // User exists
      mockRepository.save.mockResolvedValue({ ...mockUserEntity, name: 'Updated User' });

      const result = await repository.save(domainUser);

      expect(mockRepository.save).toHaveBeenCalled();
      expect(result).toBeInstanceOf(User);
    });

    it('should handle save errors', async () => {
      const domainUser = User.create({
        id: 'user123',
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User',
        provider: AuthProvider.LOCAL,
      });

      mockRepository.findOne.mockRejectedValue(new Error('Database error'));

      await expect(repository.save(domainUser)).rejects.toThrow('Failed to save user');
    });
  });

  describe('delete', () => {
    it('should delete user successfully', async () => {
      mockRepository.delete.mockResolvedValue({ affected: 1, raw: {} });

      const result = await repository.delete('user123');

      expect(mockRepository.delete).toHaveBeenCalledWith({ id: 'user123' });
      expect(result).toBe(true);
    });

    it('should return false when user not found', async () => {
      mockRepository.delete.mockResolvedValue({ affected: 0, raw: {} });

      const result = await repository.delete('nonexistent');

      expect(result).toBe(false);
    });
  });

  describe('existsByEmail', () => {
    it('should return true when email exists', async () => {
      mockRepository.count.mockResolvedValue(1);

      const result = await repository.existsByEmail('test@example.com');

      expect(mockRepository.count).toHaveBeenCalledWith({
        where: { email: 'test@example.com' }
      });
      expect(result).toBe(true);
    });

    it('should return false when email does not exist', async () => {
      mockRepository.count.mockResolvedValue(0);

      const result = await repository.existsByEmail('nonexistent@example.com');

      expect(result).toBe(false);
    });
  });

  describe('findAll', () => {
    it('should find all users with pagination', async () => {
      const mockQueryBuilder = {
        skip: jest.fn().mockReturnThis(),
        take: jest.fn().mockReturnThis(),
        orderBy: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([mockUserEntity]),
      };

      mockRepository.createQueryBuilder.mockReturnValue(mockQueryBuilder);

      const result = await repository.findAll({
        skip: 0,
        take: 10,
        orderBy: { field: 'createdAt', direction: 'desc' }
      });

      expect(mockQueryBuilder.skip).toHaveBeenCalledWith(0);
      expect(mockQueryBuilder.take).toHaveBeenCalledWith(10);
      expect(mockQueryBuilder.orderBy).toHaveBeenCalledWith('user.created_at', 'DESC');
      expect(result).toHaveLength(1);
      expect(result[0]).toBeInstanceOf(User);
    });

    it('should find all users with default ordering', async () => {
      const mockQueryBuilder = {
        skip: jest.fn().mockReturnThis(),
        take: jest.fn().mockReturnThis(),
        orderBy: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([mockUserEntity]),
      };

      mockRepository.createQueryBuilder.mockReturnValue(mockQueryBuilder);

      const result = await repository.findAll();

      expect(mockQueryBuilder.orderBy).toHaveBeenCalledWith('user.created_at', 'DESC');
      expect(result).toHaveLength(1);
    });
  });

  describe('count', () => {
    it('should return user count', async () => {
      mockRepository.count.mockResolvedValue(5);

      const result = await repository.count();

      expect(result).toBe(5);
    });
  });

  describe('findByStatus', () => {
    it('should find users by status', async () => {
      mockRepository.find.mockResolvedValue([mockUserEntity]);

      const result = await repository.findByStatus('active');

      expect(mockRepository.find).toHaveBeenCalledWith({
        where: { status: 'active' },
        order: { created_at: 'DESC' }
      });
      expect(result).toHaveLength(1);
      expect(result[0]).toBeInstanceOf(User);
    });
  });

  describe('updateLastLogin', () => {
    it('should update last login timestamp', async () => {
      const timestamp = new Date();
      mockRepository.update.mockResolvedValue({ affected: 1, raw: {}, generatedMaps: [] });

      await repository.updateLastLogin('user123', timestamp);

      expect(mockRepository.update).toHaveBeenCalledWith(
        { id: 'user123' },
        { last_login_at: timestamp }
      );
    });

    it('should handle update errors', async () => {
      const timestamp = new Date();
      mockRepository.update.mockRejectedValue(new Error('Database error'));

      await expect(repository.updateLastLogin('user123', timestamp))
        .rejects.toThrow('Failed to update last login for user: user123');
    });
  });
});