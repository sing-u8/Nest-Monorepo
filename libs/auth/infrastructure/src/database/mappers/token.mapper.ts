import { Token } from '@auth/domain';
import { TokenEntity } from '../entities/token.entity';
import { TokenType } from '@auth/shared';

/**
 * Token Entity Mapper
 * 
 * Converts between domain Token entities and TypeORM TokenEntity for database operations.
 * Handles proper mapping of token types and expiration logic.
 */
export class TokenMapper {
  /**
   * Convert domain Token entity to database TokenEntity
   * @param domainToken - Domain token entity
   * @returns Database token entity
   */
  static toPersistence(domainToken: Token): TokenEntity {
    const tokenObject = domainToken.toObject();
    
    const entity = new TokenEntity();
    entity.id = tokenObject['id'];
    entity.user_id = tokenObject['userId'];
    entity.type = tokenObject['type'];
    entity.value = tokenObject['value'];
    entity.expires_at = tokenObject['expiresAt'];
    entity.revoked_at = tokenObject['revokedAt'];
    
    return entity;
  }

  /**
   * Convert database TokenEntity to domain Token entity
   * @param dbToken - Database token entity
   * @returns Domain token entity
   */
  static toDomain(dbToken: TokenEntity): Token {
    const tokenType = dbToken.type as TokenType;

    // Determine expiration based on token type
    let expirationMinutes: number | undefined;
    let expirationDays: number | undefined;

    switch (tokenType) {
      case TokenType.ACCESS:
        expirationMinutes = this.calculateMinutesFromExpiration(dbToken.expires_at, dbToken.created_at);
        return Token.createAccessToken({
          id: dbToken.id,
          userId: dbToken.user_id,
          value: dbToken.value,
          expirationMinutes: expirationMinutes || 15,
        });

      case TokenType.REFRESH:
        expirationDays = this.calculateDaysFromExpiration(dbToken.expires_at, dbToken.created_at);
        return Token.createRefreshToken({
          id: dbToken.id,
          userId: dbToken.user_id,
          value: dbToken.value,
          expirationDays: expirationDays || 7,
        });

      case TokenType.RESET_PASSWORD:
        expirationMinutes = this.calculateMinutesFromExpiration(dbToken.expires_at, dbToken.created_at);
        return Token.createResetPasswordToken({
          id: dbToken.id,
          userId: dbToken.user_id,
          value: dbToken.value,
          expirationMinutes: expirationMinutes || 60,
        });

      case TokenType.EMAIL_VERIFICATION:
        expirationMinutes = this.calculateMinutesFromExpiration(dbToken.expires_at, dbToken.created_at);
        return Token.createEmailVerificationToken({
          id: dbToken.id,
          userId: dbToken.user_id,
          value: dbToken.value,
          expirationMinutes: expirationMinutes || 1440, // 24 hours
        });

      default:
        // Fallback to access token
        expirationMinutes = this.calculateMinutesFromExpiration(dbToken.expires_at, dbToken.created_at);
        return Token.createAccessToken({
          id: dbToken.id,
          userId: dbToken.user_id,
          value: dbToken.value,
          expirationMinutes: expirationMinutes || 15,
        });
    }
  }

  /**
   * Convert array of database entities to domain entities
   * @param dbTokens - Array of database token entities
   * @returns Array of domain token entities
   */
  static toDomainArray(dbTokens: TokenEntity[]): Token[] {
    return dbTokens.map(dbToken => this.toDomain(dbToken));
  }

  /**
   * Update database entity with domain entity data
   * @param dbToken - Existing database entity
   * @param domainToken - Domain entity with updated data
   * @returns Updated database entity
   */
  static updatePersistence(dbToken: TokenEntity, domainToken: Token): TokenEntity {
    const tokenObject = domainToken.toObject();
    
    dbToken.user_id = tokenObject['userId'];
    dbToken.type = tokenObject['type'];
    dbToken.value = tokenObject['value'];
    dbToken.expires_at = tokenObject['expiresAt'];
    dbToken.revoked_at = tokenObject['revokedAt'];
    
    return dbToken;
  }

  /**
   * Calculate expiration minutes from dates
   * @param expiresAt - Expiration date
   * @param createdAt - Creation date
   * @returns Minutes until expiration
   */
  private static calculateMinutesFromExpiration(expiresAt: Date, createdAt: Date): number {
    const diffMs = expiresAt.getTime() - createdAt.getTime();
    return Math.ceil(diffMs / (1000 * 60));
  }

  /**
   * Calculate expiration days from dates
   * @param expiresAt - Expiration date
   * @param createdAt - Creation date
   * @returns Days until expiration
   */
  private static calculateDaysFromExpiration(expiresAt: Date, createdAt: Date): number {
    const diffMs = expiresAt.getTime() - createdAt.getTime();
    return Math.ceil(diffMs / (1000 * 60 * 60 * 24));
  }
}