import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan, IsNull } from 'typeorm';
import { Token, TokenRepository } from '@auth/domain';
import { TokenType } from '@auth/shared';
import { TokenEntity } from '../database/entities/token.entity';
import { TokenMapper } from '../database/mappers/token.mapper';

/**
 * TypeORM Token Repository Implementation
 * 
 * Implements the TokenRepository port interface using TypeORM for data persistence.
 * Handles token storage, retrieval, and cleanup operations with proper indexing.
 */
@Injectable()
export class TypeOrmTokenRepository implements TokenRepository {
  constructor(
    @InjectRepository(TokenEntity)
    private readonly tokenRepository: Repository<TokenEntity>
  ) {}

  /**
   * Find a token by its unique ID
   */
  async findById(id: string): Promise<Token | null> {
    try {
      const tokenEntity = await this.tokenRepository.findOne({
        where: { id }
      });

      return tokenEntity ? TokenMapper.toDomain(tokenEntity) : null;
    } catch (error) {
      console.error('Error finding token by ID:', error);
      throw new Error(`Failed to find token by ID: ${id}`);
    }
  }

  /**
   * Find a token by its value
   */
  async findByValue(value: string): Promise<Token | null> {
    try {
      const tokenEntity = await this.tokenRepository.findOne({
        where: { value }
      });

      return tokenEntity ? TokenMapper.toDomain(tokenEntity) : null;
    } catch (error) {
      console.error('Error finding token by value:', error);
      throw new Error('Failed to find token by value');
    }
  }

  /**
   * Find all tokens for a specific user
   */
  async findByUserId(userId: string): Promise<Token[]> {
    try {
      const tokenEntities = await this.tokenRepository.find({
        where: { user_id: userId },
        order: { created_at: 'DESC' }
      });

      return TokenMapper.toDomainArray(tokenEntities);
    } catch (error) {
      console.error('Error finding tokens by user ID:', error);
      throw new Error(`Failed to find tokens for user: ${userId}`);
    }
  }

  /**
   * Find tokens by user ID and type
   */
  async findByUserIdAndType(userId: string, type: TokenType): Promise<Token[]> {
    try {
      const tokenEntities = await this.tokenRepository.find({
        where: { 
          user_id: userId,
          type: type
        },
        order: { created_at: 'DESC' }
      });

      return TokenMapper.toDomainArray(tokenEntities);
    } catch (error) {
      console.error('Error finding tokens by user ID and type:', error);
      throw new Error(`Failed to find tokens for user: ${userId}, type: ${type}`);
    }
  }

  /**
   * Save a new token or update an existing one
   */
  async save(token: Token): Promise<Token> {
    try {
      const tokenObject = token.toObject();
      const tokenId = tokenObject['id'];

      // Check if token exists
      const existingToken = await this.tokenRepository.findOne({
        where: { id: tokenId }
      });

      let savedEntity: TokenEntity;

      if (existingToken) {
        // Update existing token
        const updatedEntity = TokenMapper.updatePersistence(existingToken, token);
        savedEntity = await this.tokenRepository.save(updatedEntity);
      } else {
        // Create new token
        const newEntity = TokenMapper.toPersistence(token);
        savedEntity = await this.tokenRepository.save(newEntity);
      }

      return TokenMapper.toDomain(savedEntity);
    } catch (error) {
      console.error('Error saving token:', error);
      throw new Error('Failed to save token');
    }
  }

  /**
   * Delete a token by its ID
   */
  async delete(id: string): Promise<boolean> {
    try {
      const result = await this.tokenRepository.delete({ id });
      return result.affected !== undefined && result.affected > 0;
    } catch (error) {
      console.error('Error deleting token:', error);
      throw new Error(`Failed to delete token: ${id}`);
    }
  }

  /**
   * Delete all tokens for a specific user
   */
  async deleteByUserId(userId: string): Promise<number> {
    try {
      const result = await this.tokenRepository.delete({ user_id: userId });
      return result.affected || 0;
    } catch (error) {
      console.error('Error deleting tokens by user ID:', error);
      throw new Error(`Failed to delete tokens for user: ${userId}`);
    }
  }

  /**
   * Delete all tokens of a specific type for a user
   */
  async deleteByUserIdAndType(userId: string, type: TokenType): Promise<number> {
    try {
      const result = await this.tokenRepository.delete({ 
        user_id: userId,
        type: type
      });
      return result.affected || 0;
    } catch (error) {
      console.error('Error deleting tokens by user ID and type:', error);
      throw new Error(`Failed to delete tokens for user: ${userId}, type: ${type}`);
    }
  }

  /**
   * Find all expired tokens
   */
  async findExpired(): Promise<Token[]> {
    try {
      const now = new Date();
      const tokenEntities = await this.tokenRepository.find({
        where: {
          expires_at: LessThan(now)
        },
        order: { expires_at: 'ASC' }
      });

      return TokenMapper.toDomainArray(tokenEntities);
    } catch (error) {
      console.error('Error finding expired tokens:', error);
      throw new Error('Failed to find expired tokens');
    }
  }

  /**
   * Delete all expired tokens
   */
  async deleteExpired(): Promise<number> {
    try {
      const now = new Date();
      const result = await this.tokenRepository.delete({
        expires_at: LessThan(now)
      });
      return result.affected || 0;
    } catch (error) {
      console.error('Error deleting expired tokens:', error);
      throw new Error('Failed to delete expired tokens');
    }
  }

  /**
   * Revoke a token by its value
   */
  async revokeByValue(value: string): Promise<boolean> {
    try {
      const now = new Date();
      const result = await this.tokenRepository.update(
        { value },
        { revoked_at: now }
      );
      return result.affected !== undefined && result.affected > 0;
    } catch (error) {
      console.error('Error revoking token by value:', error);
      throw new Error('Failed to revoke token by value');
    }
  }

  /**
   * Revoke all tokens for a specific user
   */
  async revokeByUserId(userId: string): Promise<number> {
    try {
      const now = new Date();
      const result = await this.tokenRepository.update(
        { 
          user_id: userId,
          revoked_at: IsNull()
        },
        { revoked_at: now }
      );
      return result.affected || 0;
    } catch (error) {
      console.error('Error revoking tokens by user ID:', error);
      throw new Error(`Failed to revoke tokens for user: ${userId}`);
    }
  }

  /**
   * Check if a token exists and is valid
   */
  async isValidToken(value: string): Promise<boolean> {
    try {
      const now = new Date();
      const count = await this.tokenRepository.count({
        where: {
          value,
          expires_at: LessThan(now),
          revoked_at: IsNull()
        }
      });
      return count > 0;
    } catch (error) {
      console.error('Error checking token validity:', error);
      return false;
    }
  }

  /**
   * Count tokens by type
   */
  async countByType(type: TokenType): Promise<number> {
    try {
      return await this.tokenRepository.count({
        where: { type }
      });
    } catch (error) {
      console.error('Error counting tokens by type:', error);
      throw new Error(`Failed to count tokens by type: ${type}`);
    }
  }

  /**
   * Clean up old tokens (expired and revoked)
   */
  async cleanup(olderThan: Date): Promise<number> {
    try {
      // Delete tokens that are either expired or revoked and older than the threshold
      const result = await this.tokenRepository
        .createQueryBuilder()
        .delete()
        .from(TokenEntity)
        .where('expires_at < :olderThan', { olderThan })
        .orWhere('(revoked_at IS NOT NULL AND revoked_at < :olderThan)', { olderThan })
        .execute();

      return result.affected || 0;
    } catch (error) {
      console.error('Error cleaning up tokens:', error);
      throw new Error('Failed to cleanup old tokens');
    }
  }
}