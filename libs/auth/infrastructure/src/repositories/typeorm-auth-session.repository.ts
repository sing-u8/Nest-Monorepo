import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { AuthSession, AuthSessionRepository } from '@auth/domain';
import { AuthSessionEntity } from '../database/entities/auth-session.entity';
import { AuthSessionMapper } from '../database/mappers/auth-session.mapper';

/**
 * TypeORM AuthSession Repository Implementation
 * 
 * Implements the AuthSessionRepository port interface using TypeORM for data persistence.
 * Handles session storage, retrieval, and cleanup operations with proper indexing.
 */
@Injectable()
export class TypeOrmAuthSessionRepository implements AuthSessionRepository {
  constructor(
    @InjectRepository(AuthSessionEntity)
    private readonly sessionRepository: Repository<AuthSessionEntity>
  ) {}

  /**
   * Find a session by its unique ID
   */
  async findById(id: string): Promise<AuthSession | null> {
    try {
      const sessionEntity = await this.sessionRepository.findOne({
        where: { id }
      });

      return sessionEntity ? AuthSessionMapper.toDomain(sessionEntity) : null;
    } catch (error) {
      console.error('Error finding session by ID:', error);
      throw new Error(`Failed to find session by ID: ${id}`);
    }
  }

  /**
   * Find a session by its token
   */
  async findByToken(sessionToken: string): Promise<AuthSession | null> {
    try {
      const sessionEntity = await this.sessionRepository.findOne({
        where: { session_token: sessionToken }
      });

      return sessionEntity ? AuthSessionMapper.toDomain(sessionEntity) : null;
    } catch (error) {
      console.error('Error finding session by token:', error);
      throw new Error('Failed to find session by token');
    }
  }

  /**
   * Find all sessions for a specific user
   */
  async findByUserId(userId: string): Promise<AuthSession[]> {
    try {
      const sessionEntities = await this.sessionRepository.find({
        where: { user_id: userId },
        order: { created_at: 'DESC' }
      });

      return AuthSessionMapper.toDomainArray(sessionEntities);
    } catch (error) {
      console.error('Error finding sessions by user ID:', error);
      throw new Error(`Failed to find sessions for user: ${userId}`);
    }
  }

  /**
   * Find active sessions for a specific user
   */
  async findActiveByUserId(userId: string): Promise<AuthSession[]> {
    try {
      const now = new Date();
      const sessionEntities = await this.sessionRepository.find({
        where: { 
          user_id: userId,
          status: 'active'
        },
        order: { last_activity_at: 'DESC' }
      });

      // Filter out expired sessions at application level for domain logic consistency
      const activeSessions = sessionEntities.filter(session => session.expires_at > now);
      
      return AuthSessionMapper.toDomainArray(activeSessions);
    } catch (error) {
      console.error('Error finding active sessions by user ID:', error);
      throw new Error(`Failed to find active sessions for user: ${userId}`);
    }
  }

  /**
   * Save a new session or update an existing one
   */
  async save(session: AuthSession): Promise<AuthSession> {
    try {
      const sessionObject = session.toObject();
      const sessionId = sessionObject['id'];

      // Check if session exists
      const existingSession = await this.sessionRepository.findOne({
        where: { id: sessionId }
      });

      let savedEntity: AuthSessionEntity;

      if (existingSession) {
        // Update existing session
        const updatedEntity = AuthSessionMapper.updatePersistence(existingSession, session);
        savedEntity = await this.sessionRepository.save(updatedEntity);
      } else {
        // Create new session
        const newEntity = AuthSessionMapper.toPersistence(session);
        savedEntity = await this.sessionRepository.save(newEntity);
      }

      return AuthSessionMapper.toDomain(savedEntity);
    } catch (error) {
      console.error('Error saving session:', error);
      throw new Error('Failed to save session');
    }
  }

  /**
   * Delete a session by its ID
   */
  async delete(id: string): Promise<boolean> {
    try {
      const result = await this.sessionRepository.delete({ id });
      return result.affected !== undefined && result.affected > 0;
    } catch (error) {
      console.error('Error deleting session:', error);
      throw new Error(`Failed to delete session: ${id}`);
    }
  }

  /**
   * Delete all sessions for a specific user
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.sessionRepository.delete({ user_id: userId });
      return result.affected || 0;
    } catch (error) {
      console.error('Error deleting sessions by user ID:', error);
      throw new Error(`Failed to delete sessions for user: ${userId}`);
    }
  }

  /**
   * Invalidate a session by its token
   */
  async invalidateByToken(sessionToken: string): Promise<boolean> {
    try {
      const result = await this.sessionRepository.update(
        { session_token: sessionToken },
        { status: 'inactive' }
      );
      return result.affected !== undefined && result.affected > 0;
    } catch (error) {
      console.error('Error invalidating session by token:', error);
      throw new Error('Failed to invalidate session by token');
    }
  }

  /**
   * Invalidate all sessions for a specific user
   */
  async invalidateByUserId(userId: string): Promise<number> {
    try {
      const result = await this.sessionRepository.update(
        { 
          user_id: userId,
          status: 'active'
        },
        { status: 'inactive' }
      );
      return result.affected || 0;
    } catch (error) {
      console.error('Error invalidating sessions by user ID:', error);
      throw new Error(`Failed to invalidate sessions for user: ${userId}`);
    }
  }

  /**
   * Find expired sessions
   */
  async findExpired(): Promise<AuthSession[]> {
    try {
      const now = new Date();
      const sessionEntities = await this.sessionRepository.find({
        where: {
          expires_at: LessThan(now)
        },
        order: { expires_at: 'ASC' }
      });

      return AuthSessionMapper.toDomainArray(sessionEntities);
    } catch (error) {
      console.error('Error finding expired sessions:', error);
      throw new Error('Failed to find expired sessions');
    }
  }

  /**
   * Delete expired sessions
   */
  async deleteExpired(): Promise<number> {
    try {
      const now = new Date();
      const result = await this.sessionRepository.delete({
        expires_at: LessThan(now)
      });
      return result.affected || 0;
    } catch (error) {
      console.error('Error deleting expired sessions:', error);
      throw new Error('Failed to delete expired sessions');
    }
  }

  /**
   * Find idle sessions that haven't been used for a specified time
   */
  async findIdle(idleMinutes: number): Promise<AuthSession[]> {
    try {
      const idleThreshold = new Date(Date.now() - (idleMinutes * 60 * 1000));
      const sessionEntities = await this.sessionRepository.find({
        where: {
          last_activity_at: LessThan(idleThreshold),
          status: 'active'
        },
        order: { last_activity_at: 'ASC' }
      });

      return AuthSessionMapper.toDomainArray(sessionEntities);
    } catch (error) {
      console.error('Error finding idle sessions:', error);
      throw new Error(`Failed to find idle sessions: ${idleMinutes} minutes`);
    }
  }

  /**
   * Update last activity timestamp for a session
   */
  async updateActivity(sessionToken: string, timestamp: Date): Promise<boolean> {
    try {
      const result = await this.sessionRepository.update(
        { session_token: sessionToken },
        { last_activity_at: timestamp }
      );
      return result.affected !== undefined && result.affected > 0;
    } catch (error) {
      console.error('Error updating session activity:', error);
      throw new Error('Failed to update session activity');
    }
  }

  /**
   * Find sessions by device ID
   */
  async findByDeviceId(deviceId: string): Promise<AuthSession[]> {
    try {
      const sessionEntities = await this.sessionRepository.find({
        where: { device_id: deviceId },
        order: { created_at: 'DESC' }
      });

      return AuthSessionMapper.toDomainArray(sessionEntities);
    } catch (error) {
      console.error('Error finding sessions by device ID:', error);
      throw new Error(`Failed to find sessions for device: ${deviceId}`);
    }
  }

  /**
   * Find sessions by IP address
   */
  async findByIpAddress(ipAddress: string): Promise<AuthSession[]> {
    try {
      const sessionEntities = await this.sessionRepository.find({
        where: { ip_address: ipAddress },
        order: { created_at: 'DESC' }
      });

      return AuthSessionMapper.toDomainArray(sessionEntities);
    } catch (error) {
      console.error('Error finding sessions by IP address:', error);
      throw new Error(`Failed to find sessions for IP: ${ipAddress}`);
    }
  }

  /**
   * Count active sessions for a user
   */
  async countActiveByUserId(userId: string): Promise<number> {
    try {
      const now = new Date();
      return await this.sessionRepository
        .createQueryBuilder('session')
        .where('session.user_id = :userId', { userId })
        .andWhere('session.status = :status', { status: 'active' })
        .andWhere('session.expires_at > :now', { now })
        .getCount();
    } catch (error) {
      console.error('Error counting active sessions:', error);
      throw new Error(`Failed to count active sessions for user: ${userId}`);
    }
  }

  /**
   * Clean up old sessions (expired and inactive)
   */
  async cleanup(olderThan: Date): Promise<number> {
    try {
      // Delete sessions that are expired or inactive and older than the threshold
      const result = await this.sessionRepository
        .createQueryBuilder()
        .delete()
        .from(AuthSessionEntity)
        .where('expires_at < :olderThan', { olderThan })
        .orWhere('(status != :activeStatus AND updated_at < :olderThan)', { 
          activeStatus: 'active', 
          olderThan 
        })
        .execute();

      return result.affected || 0;
    } catch (error) {
      console.error('Error cleaning up sessions:', error);
      throw new Error('Failed to cleanup old sessions');
    }
  }

  /**
   * Check if a session token is valid and active
   */
  async isValidSession(sessionToken: string): Promise<boolean> {
    try {
      const now = new Date();
      const count = await this.sessionRepository.count({
        where: {
          session_token: sessionToken,
          status: 'active'
        }
      });
      
      if (count === 0) {
        return false;
      }

      // Also check expiration at database level
      const session = await this.sessionRepository.findOne({
        where: { session_token: sessionToken },
        select: ['expires_at']
      });

      return session ? session.expires_at > now : false;
    } catch (error) {
      console.error('Error checking session validity:', error);
      return false;
    }
  }
}