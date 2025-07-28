import { User } from '@auth/domain';
import { UserEntity } from '../entities/user.entity';
import { AuthProvider, UserStatus } from '@auth/shared';

/**
 * User Entity Mapper
 * 
 * Converts between domain User entities and TypeORM UserEntity for database operations.
 * Handles proper mapping of complex types and domain-specific logic.
 */
export class UserMapper {
  /**
   * Convert domain User entity to database UserEntity
   * @param domainUser - Domain user entity
   * @returns Database user entity
   */
  static toPersistence(domainUser: User): UserEntity {
    const userObject = domainUser.toObject();
    
    const entity = new UserEntity();
    entity.id = userObject['id'];
    entity.email = userObject['email'];
    entity.password = userObject['password'];
    entity.name = userObject['name'];
    entity.profile_picture = userObject['profilePicture'];
    entity.provider = userObject['provider'];
    entity.provider_id = userObject['providerId'];
    entity.email_verified = userObject['emailVerified'] || false;
    entity.status = userObject['status'];
    entity.last_login_at = userObject['lastLoginAt'];
    
    return entity;
  }

  /**
   * Convert database UserEntity to domain User entity
   * @param dbUser - Database user entity
   * @returns Domain user entity
   */
  static toDomain(dbUser: UserEntity): User {
    // For social provider users
    if (dbUser.provider !== 'local' && dbUser.provider_id) {
      return User.createFromSocialProvider({
        id: dbUser.id,
        email: dbUser.email,
        name: dbUser.name,
        provider: dbUser.provider as AuthProvider,
        providerId: dbUser.provider_id,
        profilePicture: dbUser.profile_picture,
        emailVerified: dbUser.email_verified,
      });
    }

    // For local users
    return User.create({
      id: dbUser.id,
      email: dbUser.email,
      password: dbUser.password!,
      name: dbUser.name,
      profilePicture: dbUser.profile_picture,
      provider: dbUser.provider as AuthProvider,
      providerId: dbUser.provider_id,
      emailVerified: dbUser.email_verified,
      status: dbUser.status as UserStatus,
    });
  }

  /**
   * Convert array of database entities to domain entities
   * @param dbUsers - Array of database user entities
   * @returns Array of domain user entities
   */
  static toDomainArray(dbUsers: UserEntity[]): User[] {
    return dbUsers.map(dbUser => this.toDomain(dbUser));
  }

  /**
   * Update database entity with domain entity data
   * @param dbUser - Existing database entity
   * @param domainUser - Domain entity with updated data
   * @returns Updated database entity
   */
  static updatePersistence(dbUser: UserEntity, domainUser: User): UserEntity {
    const userObject = domainUser.toObject();
    
    dbUser.email = userObject['email'];
    dbUser.password = userObject['password'];
    dbUser.name = userObject['name'];
    dbUser.profile_picture = userObject['profilePicture'];
    dbUser.provider = userObject['provider'];
    dbUser.provider_id = userObject['providerId'];
    dbUser.email_verified = userObject['emailVerified'] || false;
    dbUser.status = userObject['status'];
    dbUser.last_login_at = userObject['lastLoginAt'];
    
    return dbUser;
  }
}