import { AuthSession } from '@auth/domain';
import { AuthSessionEntity } from '../entities/auth-session.entity';
import { ClientInfo } from '@auth/shared';

/**
 * AuthSession Entity Mapper
 * 
 * Converts between domain AuthSession entities and TypeORM AuthSessionEntity for database operations.
 * Handles proper mapping of client information and session status.
 */
export class AuthSessionMapper {
  /**
   * Convert domain AuthSession entity to database AuthSessionEntity
   * @param domainSession - Domain auth session entity
   * @returns Database auth session entity
   */
  static toPersistence(domainSession: AuthSession): AuthSessionEntity {
    const sessionObject = domainSession.toObject();
    const clientInfo = sessionObject['clientInfo'] as ClientInfo;
    
    const entity = new AuthSessionEntity();
    entity.id = sessionObject['id'];
    entity.user_id = sessionObject['userId'];
    entity.session_token = sessionObject['sessionToken'];
    entity.status = sessionObject['status'];
    entity.device_id = clientInfo?.deviceId;
    entity.platform = clientInfo?.platform;
    entity.ip_address = clientInfo?.ipAddress;
    entity.user_agent = clientInfo?.userAgent;
    entity.expires_at = sessionObject['expiresAt'];
    entity.last_activity_at = sessionObject['lastActivityAt'];
    
    return entity;
  }

  /**
   * Convert database AuthSessionEntity to domain AuthSession entity
   * @param dbSession - Database auth session entity
   * @returns Domain auth session entity
   */
  static toDomain(dbSession: AuthSessionEntity): AuthSession {
    // Reconstruct client info
    const clientInfo: ClientInfo = {
      deviceId: dbSession.device_id,
      platform: dbSession.platform,
      ipAddress: dbSession.ip_address || '127.0.0.1',
      userAgent: dbSession.user_agent || 'Unknown',
    };

    // Calculate expiration hours from creation and expiration dates
    const expirationHours = this.calculateHoursFromExpiration(
      dbSession.expires_at, 
      dbSession.created_at
    );

    return AuthSession.create({
      id: dbSession.id,
      userId: dbSession.user_id,
      sessionToken: dbSession.session_token,
      clientInfo: clientInfo,
      expirationHours: expirationHours,
    });
  }

  /**
   * Convert array of database entities to domain entities
   * @param dbSessions - Array of database auth session entities
   * @returns Array of domain auth session entities
   */
  static toDomainArray(dbSessions: AuthSessionEntity[]): AuthSession[] {
    return dbSessions.map(dbSession => this.toDomain(dbSession));
  }

  /**
   * Update database entity with domain entity data
   * @param dbSession - Existing database entity
   * @param domainSession - Domain entity with updated data
   * @returns Updated database entity
   */
  static updatePersistence(dbSession: AuthSessionEntity, domainSession: AuthSession): AuthSessionEntity {
    const sessionObject = domainSession.toObject();
    const clientInfo = sessionObject['clientInfo'] as ClientInfo;
    
    dbSession.user_id = sessionObject['userId'];
    dbSession.session_token = sessionObject['sessionToken'];
    dbSession.status = sessionObject['status'];
    dbSession.device_id = clientInfo?.deviceId;
    dbSession.platform = clientInfo?.platform;
    dbSession.ip_address = clientInfo?.ipAddress;
    dbSession.user_agent = clientInfo?.userAgent;
    dbSession.expires_at = sessionObject['expiresAt'];
    dbSession.last_activity_at = sessionObject['lastActivityAt'];
    
    return dbSession;
  }

  /**
   * Calculate expiration hours from dates
   * @param expiresAt - Expiration date
   * @param createdAt - Creation date
   * @returns Hours until expiration
   */
  private static calculateHoursFromExpiration(expiresAt: Date, createdAt: Date): number {
    const diffMs = expiresAt.getTime() - createdAt.getTime();
    return Math.ceil(diffMs / (1000 * 60 * 60));
  }
}