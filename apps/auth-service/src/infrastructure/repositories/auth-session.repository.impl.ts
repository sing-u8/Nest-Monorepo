import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { AuthSession } from '../../domain/entities/auth-session.entity';
import { AuthSessionRepository } from '../../domain/ports/auth-session.repository';
import { AuthSessionOrmEntity } from '../database/entities/auth-session.orm-entity';
import { ClientInfo } from '@auth/shared/types/auth.types';

@Injectable()
export class AuthSessionRepositoryImpl implements AuthSessionRepository {
  constructor(
    @InjectRepository(AuthSessionOrmEntity)
    private readonly authSessionOrmRepository: Repository<AuthSessionOrmEntity>,
  ) {}

  async save(authSession: AuthSession): Promise<AuthSession> {
    const authSessionOrm = this.toOrmEntity(authSession);
    const savedAuthSessionOrm = await this.authSessionOrmRepository.save(authSessionOrm);
    return this.toDomainEntity(savedAuthSessionOrm);
  }

  async findById(id: string): Promise<AuthSession | null> {
    const authSessionOrm = await this.authSessionOrmRepository.findOne({ where: { id } });
    return authSessionOrm ? this.toDomainEntity(authSessionOrm) : null;
  }

  async findBySessionToken(sessionToken: string): Promise<AuthSession | null> {
    const authSessionOrm = await this.authSessionOrmRepository.findOne({ 
      where: { sessionToken } 
    });
    return authSessionOrm ? this.toDomainEntity(authSessionOrm) : null;
  }

  async findByUserId(userId: string): Promise<AuthSession | null> {
    // Find the most recent active session for the user
    const authSessionOrm = await this.authSessionOrmRepository.findOne({ 
      where: { 
        userId,
        expiresAt: LessThan(new Date()) // Only active sessions
      },
      order: { createdAt: 'DESC' }
    });
    return authSessionOrm ? this.toDomainEntity(authSessionOrm) : null;
  }

  async findAllByUserId(userId: string): Promise<AuthSession[]> {
    const authSessionOrms = await this.authSessionOrmRepository.find({ 
      where: { userId },
      order: { createdAt: 'DESC' }
    });
    return authSessionOrms.map(authSessionOrm => this.toDomainEntity(authSessionOrm));
  }

  async revoke(sessionId: string): Promise<void> {
    const result = await this.authSessionOrmRepository.update(sessionId, { 
      expiresAt: new Date() // Set expiry to now to revoke
    });
    
    if (result.affected === 0) {
      throw new Error(`AuthSession with id ${sessionId} not found`);
    }
  }

  async revokeAllByUserId(userId: string): Promise<void> {
    await this.authSessionOrmRepository.update(
      { userId }, 
      { expiresAt: new Date() } // Set expiry to now to revoke all sessions
    );
  }

  async updateActivity(sessionId: string, clientInfo: ClientInfo): Promise<void> {
    const result = await this.authSessionOrmRepository.update(sessionId, { 
      clientInfo: clientInfo as any, // TypeORM will handle JSON serialization
      lastActivityAt: new Date()
    });
    
    if (result.affected === 0) {
      throw new Error(`AuthSession with id ${sessionId} not found`);
    }
  }

  async deleteExpired(): Promise<number> {
    const result = await this.authSessionOrmRepository.delete({
      expiresAt: LessThan(new Date())
    });
    
    return result.affected || 0;
  }

  async countActiveSessions(userId: string): Promise<number> {
    return await this.authSessionOrmRepository.count({
      where: {
        userId,
        expiresAt: LessThan(new Date()) // Only count active sessions
      }
    });
  }

  async findActiveSessions(userId: string): Promise<AuthSession[]> {
    const authSessionOrms = await this.authSessionOrmRepository.find({
      where: {
        userId,
        expiresAt: LessThan(new Date()) // Only active sessions
      },
      order: { createdAt: 'DESC' }
    });
    
    return authSessionOrms.map(authSessionOrm => this.toDomainEntity(authSessionOrm));
  }

  async deleteByUserId(userId: string): Promise<number> {
    const result = await this.authSessionOrmRepository.delete({ userId });
    return result.affected || 0;
  }

  async cleanupExpiredSessions(): Promise<number> {
    // Delete sessions that expired more than 7 days ago
    const cleanupDate = new Date();
    cleanupDate.setDate(cleanupDate.getDate() - 7);

    const result = await this.authSessionOrmRepository.delete({
      expiresAt: LessThan(cleanupDate)
    });
    
    return result.affected || 0;
  }

  private toDomainEntity(authSessionOrm: AuthSessionOrmEntity): AuthSession {
    return new AuthSession(
      authSessionOrm.id,
      authSessionOrm.userId,
      authSessionOrm.sessionToken,
      authSessionOrm.clientInfo,
      authSessionOrm.expiresAt,
      authSessionOrm.createdAt,
      authSessionOrm.lastActivityAt,
    );
  }

  private toOrmEntity(authSession: AuthSession): AuthSessionOrmEntity {
    const authSessionOrm = new AuthSessionOrmEntity();
    authSessionOrm.id = authSession.id;
    authSessionOrm.userId = authSession.userId;
    authSessionOrm.sessionToken = authSession.sessionToken;
    authSessionOrm.clientInfo = authSession.clientInfo;
    authSessionOrm.expiresAt = authSession.getExpiresAt();
    authSessionOrm.createdAt = authSession.getCreatedAt();
    authSessionOrm.lastActivityAt = authSession.getLastActivityAt();
    return authSessionOrm;
  }
}