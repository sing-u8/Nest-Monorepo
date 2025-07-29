import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TypeOrmAuthSessionRepository } from './typeorm-auth-session.repository';
import { AuthSessionEntity } from '../database/entities/auth-session.entity';
import { AuthSessionMapper } from '../database/mappers/auth-session.mapper';
import { AuthSession } from '@auth/domain';

describe('TypeOrmAuthSessionRepository', () => {
  let repository: TypeOrmAuthSessionRepository;
  let sessionEntityRepository: jest.Mocked<Repository<AuthSessionEntity>>;
  let sessionMapper: jest.Mocked<AuthSessionMapper>;

  const mockSessionEntity: AuthSessionEntity = {
    id: 'session-123',
    userId: 'user-123',
    sessionToken: 'session-token-value',
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours from now
    isActive: true,
    lastAccessedAt: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockSession = AuthSession.create({
    id: 'session-123',
    userId: 'user-123',
    sessionToken: 'session-token-value',
    clientInfo: {
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
    },
    expirationHours: 24,
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
        orderBy: jest.fn().mockReturnThis(),
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
        TypeOrmAuthSessionRepository,
        {
          provide: getRepositoryToken(AuthSessionEntity),
          useValue: mockEntityRepository,
        },
        {
          provide: AuthSessionMapper,
          useValue: mockMapper,
        },
      ],
    }).compile();

    repository = module.get<TypeOrmAuthSessionRepository>(TypeOrmAuthSessionRepository);
    sessionEntityRepository = module.get(getRepositoryToken(AuthSessionEntity));
    sessionMapper = module.get(AuthSessionMapper);
  });

  describe('findByUserId', () => {
    it('should find sessions by user ID', async () => {
      // Arrange
      const userId = 'user-123';
      sessionEntityRepository.find.mockResolvedValue([mockSessionEntity]);
      sessionMapper.toDomain.mockReturnValue(mockSession);

      // Act
      const result = await repository.findByUserId(userId);

      // Assert
      expect(sessionEntityRepository.find).toHaveBeenCalledWith({
        where: { userId, isActive: true },
        order: { lastAccessedAt: 'DESC' },
      });
      expect(sessionMapper.toDomain).toHaveBeenCalledWith(mockSessionEntity);
      expect(result).toEqual([mockSession]);
    });

    it('should return empty array when no sessions found', async () => {
      // Arrange
      const userId = 'user-123';
      sessionEntityRepository.find.mockResolvedValue([]);

      // Act
      const result = await repository.findByUserId(userId);

      // Assert
      expect(result).toEqual([]);
    });

    it('should handle database errors', async () => {
      // Arrange
      const userId = 'user-123';
      sessionEntityRepository.find.mockRejectedValue(new Error('Database error'));

      // Act & Assert
      await expect(repository.findByUserId(userId)).rejects.toThrow('Database error');
    });
  });

  describe('findBySessionToken', () => {
    it('should find session by token', async () => {
      // Arrange
      const sessionToken = 'session-token-value';
      sessionEntityRepository.findOne.mockResolvedValue(mockSessionEntity);
      sessionMapper.toDomain.mockReturnValue(mockSession);

      // Act
      const result = await repository.findBySessionToken(sessionToken);

      // Assert
      expect(sessionEntityRepository.findOne).toHaveBeenCalledWith({
        where: { sessionToken, isActive: true },
      });
      expect(sessionMapper.toDomain).toHaveBeenCalledWith(mockSessionEntity);
      expect(result).toEqual(mockSession);
    });

    it('should return null when session not found', async () => {
      // Arrange
      const sessionToken = 'non-existent-token';
      sessionEntityRepository.findOne.mockResolvedValue(null);

      // Act
      const result = await repository.findBySessionToken(sessionToken);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle database errors', async () => {
      // Arrange
      const sessionToken = 'session-token-value';
      sessionEntityRepository.findOne.mockRejectedValue(new Error('Database error'));

      // Act & Assert
      await expect(repository.findBySessionToken(sessionToken)).rejects.toThrow('Database error');
    });
  });

  describe('save', () => {
    it('should save session', async () => {
      // Arrange
      sessionMapper.toEntity.mockReturnValue(mockSessionEntity);
      sessionEntityRepository.save.mockResolvedValue(mockSessionEntity);
      sessionMapper.toDomain.mockReturnValue(mockSession);

      // Act
      const result = await repository.save(mockSession);

      // Assert
      expect(sessionMapper.toEntity).toHaveBeenCalledWith(mockSession);
      expect(sessionEntityRepository.save).toHaveBeenCalledWith(mockSessionEntity);
      expect(sessionMapper.toDomain).toHaveBeenCalledWith(mockSessionEntity);
      expect(result).toEqual(mockSession);
    });

    it('should handle save errors', async () => {
      // Arrange
      sessionMapper.toEntity.mockReturnValue(mockSessionEntity);
      sessionEntityRepository.save.mockRejectedValue(new Error('Save error'));

      // Act & Assert
      await expect(repository.save(mockSession)).rejects.toThrow('Save error');
    });
  });

  describe('update', () => {
    it('should update session', async () => {
      // Arrange
      const sessionId = 'session-123';
      const updateData = { lastAccessedAt: new Date() };
      const updateResult = { affected: 1 };
      sessionEntityRepository.update.mockResolvedValue(updateResult as any);

      // Act
      await repository.update(sessionId, updateData);

      // Assert
      expect(sessionEntityRepository.update).toHaveBeenCalledWith(sessionId, updateData);
    });

    it('should handle update errors', async () => {
      // Arrange
      const sessionId = 'session-123';
      const updateData = { lastAccessedAt: new Date() };
      sessionEntityRepository.update.mockRejectedValue(new Error('Update error'));

      // Act & Assert
      await expect(repository.update(sessionId, updateData)).rejects.toThrow('Update error');
    });
  });

  describe('delete', () => {
    it('should delete session', async () => {
      // Arrange
      const sessionId = 'session-123';
      const deleteResult = { affected: 1 };
      sessionEntityRepository.delete.mockResolvedValue(deleteResult as any);

      // Act
      await repository.delete(sessionId);

      // Assert
      expect(sessionEntityRepository.delete).toHaveBeenCalledWith(sessionId);
    });

    it('should handle delete errors', async () => {
      // Arrange
      const sessionId = 'session-123';
      sessionEntityRepository.delete.mockRejectedValue(new Error('Delete error'));

      // Act & Assert
      await expect(repository.delete(sessionId)).rejects.toThrow('Delete error');
    });
  });

  describe('deleteByUserId', () => {
    it('should delete all sessions for user', async () => {
      // Arrange
      const userId = 'user-123';
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 3 }),
      };
      sessionEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act
      await repository.deleteByUserId(userId);

      // Assert
      expect(sessionEntityRepository.createQueryBuilder).toHaveBeenCalledWith();
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
      sessionEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act & Assert
      await expect(repository.deleteByUserId(userId)).rejects.toThrow('Delete error');
    });
  });

  describe('deleteExpiredSessions', () => {
    it('should delete expired sessions', async () => {
      // Arrange
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 5 }),
      };
      sessionEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act
      await repository.deleteExpiredSessions();

      // Assert
      expect(sessionEntityRepository.createQueryBuilder).toHaveBeenCalledWith();
      expect(queryBuilder.where).toHaveBeenCalledWith('expiresAt < :now', { now: expect.any(Date) });
      expect(queryBuilder.execute).toHaveBeenCalled();
    });

    it('should handle delete expired sessions errors', async () => {
      // Arrange
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        execute: jest.fn().mockRejectedValue(new Error('Delete error')),
      };
      sessionEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act & Assert
      await expect(repository.deleteExpiredSessions()).rejects.toThrow('Delete error');
    });
  });

  describe('findActiveSessions', () => {
    it('should find active sessions for user', async () => {
      // Arrange
      const userId = 'user-123';
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        orderBy: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([mockSessionEntity]),
      };
      sessionEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);
      sessionMapper.toDomain.mockReturnValue(mockSession);

      // Act
      const result = await repository.findActiveSessions(userId);

      // Assert
      expect(queryBuilder.where).toHaveBeenCalledWith('userId = :userId', { userId });
      expect(queryBuilder.andWhere).toHaveBeenCalledWith('isActive = :isActive', { isActive: true });
      expect(queryBuilder.andWhere).toHaveBeenCalledWith('expiresAt > :now', { now: expect.any(Date) });
      expect(queryBuilder.orderBy).toHaveBeenCalledWith('lastAccessedAt', 'DESC');
      expect(result).toEqual([mockSession]);
    });

    it('should return empty array when no active sessions found', async () => {
      // Arrange
      const userId = 'user-123';
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        orderBy: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([]),
      };
      sessionEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act
      const result = await repository.findActiveSessions(userId);

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('deactivateSession', () => {
    it('should deactivate session by token', async () => {
      // Arrange
      const sessionToken = 'session-token-value';
      const updateResult = { affected: 1 };
      sessionEntityRepository.update.mockResolvedValue(updateResult as any);

      // Act
      await repository.deactivateSession(sessionToken);

      // Assert
      expect(sessionEntityRepository.update).toHaveBeenCalledWith(
        { sessionToken },
        { isActive: false, updatedAt: expect.any(Date) }
      );
    });

    it('should handle deactivate session errors', async () => {
      // Arrange
      const sessionToken = 'session-token-value';
      sessionEntityRepository.update.mockRejectedValue(new Error('Deactivate error'));

      // Act & Assert
      await expect(repository.deactivateSession(sessionToken)).rejects.toThrow('Deactivate error');
    });
  });

  describe('updateLastAccessed', () => {
    it('should update last accessed time', async () => {
      // Arrange
      const sessionToken = 'session-token-value';
      const updateResult = { affected: 1 };
      sessionEntityRepository.update.mockResolvedValue(updateResult as any);

      // Act
      await repository.updateLastAccessed(sessionToken);

      // Assert
      expect(sessionEntityRepository.update).toHaveBeenCalledWith(
        { sessionToken, isActive: true },
        { lastAccessedAt: expect.any(Date), updatedAt: expect.any(Date) }
      );
    });

    it('should handle update last accessed errors', async () => {
      // Arrange
      const sessionToken = 'session-token-value';
      sessionEntityRepository.update.mockRejectedValue(new Error('Update error'));

      // Act & Assert
      await expect(repository.updateLastAccessed(sessionToken)).rejects.toThrow('Update error');
    });
  });

  describe('findRecentSessions', () => {
    it('should find recent sessions within time limit', async () => {
      // Arrange
      const userId = 'user-123';
      const hoursLimit = 24;
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        orderBy: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([mockSessionEntity]),
      };
      sessionEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);
      sessionMapper.toDomain.mockReturnValue(mockSession);

      // Act
      const result = await repository.findRecentSessions(userId, hoursLimit);

      // Assert
      expect(queryBuilder.where).toHaveBeenCalledWith('userId = :userId', { userId });
      expect(queryBuilder.andWhere).toHaveBeenCalledWith('createdAt > :timeLimit', { 
        timeLimit: expect.any(Date) 
      });
      expect(queryBuilder.orderBy).toHaveBeenCalledWith('createdAt', 'DESC');
      expect(result).toEqual([mockSession]);
    });

    it('should use default time limit when not specified', async () => {
      // Arrange
      const userId = 'user-123';
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        orderBy: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([]),
      };
      sessionEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act
      const result = await repository.findRecentSessions(userId);

      // Assert
      expect(queryBuilder.andWhere).toHaveBeenCalledWith('createdAt > :timeLimit', { 
        timeLimit: expect.any(Date) 
      });
      expect(result).toEqual([]);
    });
  });

  describe('cleanupInactiveSessions', () => {
    it('should cleanup inactive sessions older than specified days', async () => {
      // Arrange
      const daysOld = 30;
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 10 }),
      };
      sessionEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act
      const result = await repository.cleanupInactiveSessions(daysOld);

      // Assert
      expect(queryBuilder.where).toHaveBeenCalledWith('isActive = :isActive', { isActive: false });
      expect(queryBuilder.andWhere).toHaveBeenCalledWith('updatedAt < :cutoffDate', { 
        cutoffDate: expect.any(Date) 
      });
      expect(result).toBe(10);
    });

    it('should use default cleanup period when not specified', async () => {
      // Arrange
      const queryBuilder = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 5 }),
      };
      sessionEntityRepository.createQueryBuilder.mockReturnValue(queryBuilder as any);

      // Act
      const result = await repository.cleanupInactiveSessions();

      // Assert
      expect(result).toBe(5);
    });
  });
});