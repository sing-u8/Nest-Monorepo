import { AuthSession } from '../entities/auth-session.entity';
import { ClientInfo } from '@auth/shared/types/auth.types';

export interface AuthSessionRepository {
  save(session: AuthSession): Promise<AuthSession>;
  findById(id: string): Promise<AuthSession | null>;
  findBySessionToken(sessionToken: string): Promise<AuthSession | null>;
  findByUserId(userId: string): Promise<AuthSession[]>;
  findActiveByUserId(userId: string): Promise<AuthSession[]>;
  update(sessionId: string, updates: Partial<AuthSession>): Promise<AuthSession>;
  revoke(sessionId: string): Promise<void>;
  revokeAllByUserId(userId: string): Promise<void>;
  deleteExpired(): Promise<number>;
  deleteInactiveSessions(maxIdleTimeMs: number): Promise<number>;
  existsBySessionToken(sessionToken: string): Promise<boolean>;
  updateActivity(sessionId: string): Promise<void>;
  findByClientInfo(clientInfo: Partial<ClientInfo>): Promise<AuthSession[]>;
}