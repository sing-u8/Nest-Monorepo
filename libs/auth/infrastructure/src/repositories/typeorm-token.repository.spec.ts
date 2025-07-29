import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TypeOrmTokenRepository } from './typeorm-token.repository';
import { TokenEntity } from '../database/entities/token.entity';
import { TokenMapper } from '../database/mappers/token.mapper';
import { Token } from '@auth/domain';
import { TokenType } from '@auth/shared';

describe('TypeOrmTokenRepository', () => {
  let repository: TypeOrmTokenRepository;
  let tokenEntityRepository: jest.Mocked<Repository<TokenEntity>>;
  let tokenMapper: jest.Mocked<TokenMapper>;

  const mockTokenEntity: TokenEntity = {
    id: 'token-123',
    userId: 'user-123',
    type: TokenType.ACCESS,
    value: 'token-value',
    expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes from now
    isRevoked: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockToken = Token.createAccessToken({
    id: 'token-123',
    userId: 'user-123',
    value: 'token-value',
    expirationMinutes: 15,
  });

  beforeEach(async () => {
    const mockEntityRepository = {
      find: jest.fn(),
      findOne: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      createQueryBuilder: jest.fn(() => ({
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getMany: jest.fn(),
        getOne: jest.fn(),
        delete: jest.fn().mockReturnThis(),
        execute: jest.fn(),
      })),
    };

    const mockMapper = {
      toDomain: jest.fn(),
      toEntity: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TypeOrmTokenRepository,
        {
          provide: getRepositoryToken(TokenEntity),
          useValue: mockEntityRepository,
        },
        {
          provide: TokenMapper,
          useValue: mockMapper,
        },
      ],
    }).compile();

    repository = module.get<TypeOrmTokenRepository>(TypeOrmTokenRepository);
    tokenEntityRepository = module.get(getRepositoryToken(TokenEntity));
    tokenMapper = module.get(TokenMapper);
  });

  describe('findByUserId', () => {
    it('should find tokens by user ID', async () => {
      // Arrange
      const userId = 'user-123';
      tokenEntityRepository.find.mockResolvedValue([mockTokenEntity]);
      tokenMapper.toDomain.mockReturnValue(mockToken);

      // Act
      const result = await repository.findByUserId(userId);

      // Assert
      expect(tokenEntityRepository.find).toHaveBeenCalledWith({
        where: { userId, isRevoked: false },
        order: { createdAt: 'DESC' },
      });
      expect(tokenMapper.toDomain).toHaveBeenCalledWith(mockTokenEntity);
      expect(result).toEqual([mockToken]);
    });

    it('should return empty array when no tokens found', async () => {
      // Arrange
      const userId = 'user-123';
      tokenEntityRepository.find.mockResolvedValue([]);

      // Act
      const result = await repository.findByUserId(userId);

      // Assert
      expect(result).toEqual([]);
    });

    it('should handle database errors', async () => {
      // Arrange
      const userId = 'user-123';
      tokenEntityRepository.find.mockRejectedValue(new Error('Database error'));

      // Act & Assert
      await expect(repository.findByUserId(userId)).rejects.toThrow('Database error');
    });
  });

  describe('findByValue', () => {
    it('should find token by value', async () => {
      // Arrange
      const tokenValue = 'token-value';
      tokenEntityRepository.findOne.mockResolvedValue(mockTokenEntity);
      tokenMapper.toDomain.mockReturnValue(mockToken);

      // Act
      const result = await repository.findByValue(tokenValue);

      // Assert
      expect(tokenEntityRepository.findOne).toHaveBeenCalledWith({
        where: { value: tokenValue, isRevoked: false },
      });
      expect(tokenMapper.toDomain).toHaveBeenCalledWith(mockTokenEntity);
      expect(result).toEqual(mockToken);
    });

    it('should return null when token not found', async () => {
      // Arrange
      const tokenValue = 'non-existent-token';
      tokenEntityRepository.findOne.mockResolvedValue(null);

      // Act
      const result = await repository.findByValue(tokenValue);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle database errors', async () => {
      // Arrange
      const tokenValue = 'token-value';
      tokenEntityRepository.findOne.mockRejectedValue(new Error('Database error'));

      // Act & Assert
      await expect(repository.findByValue(tokenValue)).rejects.toThrow('Database error');
    });
  });

  describe('save', () => {
    it('should save token', async () => {
      // Arrange
      tokenMapper.toEntity.mockReturnValue(mockTokenEntity);
      tokenEntityRepository.save.mockResolvedValue(mockTokenEntity);
      tokenMapper.toDomain.mockReturnValue(mockToken);

      // Act
      const result = await repository.save(mockToken);

      // Assert
      expect(tokenMapper.toEntity).toHaveBeenCalledWith(mockToken);
      expect(tokenEntityRepository.save).toHaveBeenCalledWith(mockTokenEntity);
      expect(tokenMapper.toDomain).toHaveBeenCalledWith(mockTokenEntity);
      expect(result).toEqual(mockToken);
    });

    it('should handle save errors', async () => {
      // Arrange
      tokenMapper.toEntity.mockReturnValue(mockTokenEntity);
      tokenEntityRepository.save.mockRejectedValue(new Error('Save error'));

      // Act & Assert
      await expect(repository.save(mockToken)).rejects.toThrow('Save error');
    });
  });

  describe('update', () => {
    it('should update token', async () => {
      // Arrange
      const tokenId = 'token-123';
      const updateData = { isRevoked: true };
      const updateResult = { affected: 1 };
      tokenEntityRepository.update.mockResolvedValue(updateResult as any);

      // Act
      await repository.update(tokenId, updateData);

      // Assert
      expect(tokenEntityRepository.update).toHaveBeenCalledWith(tokenId, updateData);
    });

    it('should handle update errors', async () => {
      // Arrange
      const tokenId = 'token-123';
      const updateData = { isRevoked: true };
      tokenEntityRepository.update.mockRejectedValue(new Error('Update error'));

      // Act & Assert
      await expect(repository.update(tokenId, updateData)).rejects.toThrow('Update error');
    });
  });

  describe('delete', () => {
    it('should delete token', async () => {
      // Arrange
      const tokenId = 'token-123';
      const deleteResult = { affected: 1 };
      tokenEntityRepository.delete.mockResolvedValue(deleteResult as any);

      // Act
      await repository.delete(tokenId);

      // Assert
      expect(tokenEntityRepository.delete).toHaveBeenCalledWith(tokenId);
    });

    it('should handle delete errors', async () => {
      // Arrange
      const tokenId = 'token-123';
      tokenEntityRepository.delete.mockRejectedValue(new Error('Delete error'));

      // Act & Assert
      await expect(repository.delete(tokenId)).rejects.toThrow('Delete error');
    });
  });

  describe('deleteByUserId', () => {
    it('should delete all tokens for user', async () => {
      // Arrange
      const userId = 'user-123';
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 3 }),
      };
      tokenEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act
      await repository.deleteByUserId(userId);

      // Assert
      expect(tokenEntityRepository.createQueryBuilder).toHaveBeenCalledWith();
      expect(queryBuilder.where).toHaveBeenCalledWith('userId = :userId', { userId });
      expect(queryBuilder.execute).toHaveBeenCalled();
    });

    it('should handle delete by user ID errors', async () => {
      // Arrange
      const userId = 'user-123';
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        execute: jest.fn().mockRejectedValue(new Error('Delete error')),
      };
      tokenEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act & Assert
      await expect(repository.deleteByUserId(userId)).rejects.toThrow('Delete error');
    });
  });

  describe('deleteExpiredTokens', () => {
    it('should delete expired tokens', async () => {
      // Arrange
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 5 }),
      };
      tokenEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act
      await repository.deleteExpiredTokens();

      // Assert
      expect(tokenEntityRepository.createQueryBuilder).toHaveBeenCalledWith();
      expect(queryBuilder.where).toHaveBeenCalledWith('expiresAt < :now', { now: expect.any(Date) });
      expect(queryBuilder.execute).toHaveBeenCalled();
    });

    it('should handle delete expired tokens errors', async () => {
      // Arrange
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        execute: jest.fn().mockRejectedValue(new Error('Delete error')),
      };
      tokenEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act & Assert
      await expect(repository.deleteExpiredTokens()).rejects.toThrow('Delete error');
    });
  });

  describe('findByUserIdAndType', () => {
    it('should find tokens by user ID and type', async () => {
      // Arrange
      const userId = 'user-123';
      const tokenType = TokenType.REFRESH;
      tokenEntityRepository.find.mockResolvedValue([mockTokenEntity]);
      tokenMapper.toDomain.mockReturnValue(mockToken);

      // Act
      const result = await repository.findByUserIdAndType(userId, tokenType);

      // Assert
      expect(tokenEntityRepository.find).toHaveBeenCalledWith({
        where: { userId, type: tokenType, isRevoked: false },
        order: { createdAt: 'DESC' },
      });
      expect(result).toEqual([mockToken]);
    });

    it('should return empty array for non-existent user and type combination', async () => {
      // Arrange
      const userId = 'user-123';
      const tokenType = TokenType.RESET_PASSWORD;
      tokenEntityRepository.find.mockResolvedValue([]);

      // Act
      const result = await repository.findByUserIdAndType(userId, tokenType);

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('revokeToken', () => {
    it('should revoke token by value', async () => {
      // Arrange
      const tokenValue = 'token-value';
      const updateResult = { affected: 1 };
      tokenEntityRepository.update.mockResolvedValue(updateResult as any);

      // Act
      await repository.revokeToken(tokenValue);

      // Assert
      expect(tokenEntityRepository.update).toHaveBeenCalledWith(
        { value: tokenValue },
        { isRevoked: true, updatedAt: expect.any(Date) }
      );
    });

    it('should handle revoke token errors', async () => {
      // Arrange
      const tokenValue = 'token-value';
      tokenEntityRepository.update.mockRejectedValue(new Error('Revoke error'));

      // Act & Assert
      await expect(repository.revokeToken(tokenValue)).rejects.toThrow('Revoke error');
    });
  });

  describe('findValidTokensByUserId', () => {
    it('should find valid (non-expired, non-revoked) tokens', async () => {
      // Arrange
      const userId = 'user-123';
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([mockTokenEntity]),
      };
      tokenEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);
      tokenMapper.toDomain.mockReturnValue(mockToken);

      // Act
      const result = await repository.findValidTokensByUserId(userId);

      // Assert
      expect(queryBuilder.where).toHaveBeenCalledWith('userId = :userId', { userId });
      expect(queryBuilder.andWhere).toHaveBeenCalledWith('isRevoked = :isRevoked', { isRevoked: false });
      expect(queryBuilder.andWhere).toHaveBeenCalledWith('expiresAt > :now', { now: expect.any(Date) });
      expect(result).toEqual([mockToken]);
    });

    it('should return empty array when no valid tokens found', async () => {
      // Arrange
      const userId = 'user-123';
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([]),
      };
      tokenEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act
      const result = await repository.findValidTokensByUserId(userId);

      // Assert
      expect(result).toEqual([]);
    });
  });
});