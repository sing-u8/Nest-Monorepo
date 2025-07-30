import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { Token } from '../../domain/entities/token.entity';
import { TokenRepository } from '../../domain/ports/token.repository';
import { TokenOrmEntity } from '../database/entities/token.orm-entity';
import { TokenType } from '@auth/shared/types/auth.types';

@Injectable()
export class TokenRepositoryImpl implements TokenRepository {
  constructor(
    @InjectRepository(TokenOrmEntity)
    private readonly tokenOrmRepository: Repository<TokenOrmEntity>,
  ) {}

  async save(token: Token): Promise<Token> {
    const tokenOrm = this.toOrmEntity(token);
    const savedTokenOrm = await this.tokenOrmRepository.save(tokenOrm);
    return this.toDomainEntity(savedTokenOrm);
  }

  async findByValue(value: string): Promise<Token | null> {
    const tokenOrm = await this.tokenOrmRepository.findOne({ where: { value } });
    return tokenOrm ? this.toDomainEntity(tokenOrm) : null;
  }

  async findByUserId(userId: string, type?: TokenType): Promise<Token[]> {
    const whereCondition: any = { userId };
    if (type) {
      whereCondition.type = type;
    }

    const tokenOrms = await this.tokenOrmRepository.find({ 
      where: whereCondition,
      order: { createdAt: 'DESC' }
    });
    
    return tokenOrms.map(tokenOrm => this.toDomainEntity(tokenOrm));
  }

  async revoke(tokenId: string): Promise<void> {
    const result = await this.tokenOrmRepository.update(tokenId, { 
      isRevoked: true 
    });
    
    if (result.affected === 0) {
      throw new Error(`Token with id ${tokenId} not found`);
    }
  }

  async revokeAllByUserId(userId: string, type?: TokenType): Promise<void> {
    const whereCondition: any = { userId };
    if (type) {
      whereCondition.type = type;
    }

    await this.tokenOrmRepository.update(whereCondition, { 
      isRevoked: true 
    });
  }

  async deleteExpired(): Promise<number> {
    const result = await this.tokenOrmRepository.delete({
      expiresAt: LessThan(new Date())
    });
    
    return result.affected || 0;
  }

  async countActiveTokensByUserId(userId: string, type?: TokenType): Promise<number> {
    const whereCondition: any = { 
      userId,
      isRevoked: false
    };
    
    if (type) {
      whereCondition.type = type;
    }

    return await this.tokenOrmRepository.count({ where: whereCondition });
  }

  async findActiveTokensByUserId(userId: string, type?: TokenType): Promise<Token[]> {
    const whereCondition: any = { 
      userId,
      isRevoked: false
    };
    
    if (type) {
      whereCondition.type = type;
    }

    const tokenOrms = await this.tokenOrmRepository.find({ 
      where: whereCondition,
      order: { createdAt: 'DESC' }
    });
    
    return tokenOrms.map(tokenOrm => this.toDomainEntity(tokenOrm));
  }

  async deleteByUserId(userId: string, type?: TokenType): Promise<number> {
    const whereCondition: any = { userId };
    if (type) {
      whereCondition.type = type;
    }

    const result = await this.tokenOrmRepository.delete(whereCondition);
    return result.affected || 0;
  }

  async findById(id: string): Promise<Token | null> {
    const tokenOrm = await this.tokenOrmRepository.findOne({ where: { id } });
    return tokenOrm ? this.toDomainEntity(tokenOrm) : null;
  }

  async cleanupExpiredTokens(): Promise<number> {
    // Delete tokens that are expired and revoked (for cleanup purposes)
    const result = await this.tokenOrmRepository.delete({
      expiresAt: LessThan(new Date()),
      isRevoked: true
    });
    
    return result.affected || 0;
  }

  private toDomainEntity(tokenOrm: TokenOrmEntity): Token {
    const token = new Token(
      tokenOrm.id,
      tokenOrm.userId,
      tokenOrm.type,
      tokenOrm.value,
      tokenOrm.expiresAt,
      tokenOrm.isRevoked,
      tokenOrm.createdAt,
    );

    return token;
  }

  private toOrmEntity(token: Token): TokenOrmEntity {
    const tokenOrm = new TokenOrmEntity();
    tokenOrm.id = token.id;
    tokenOrm.userId = token.userId;
    tokenOrm.type = token.type;
    tokenOrm.value = token.getValue();
    tokenOrm.expiresAt = token.getExpiresAt();
    tokenOrm.isRevoked = !token.isValid() || token.isExpired();
    tokenOrm.createdAt = token.getCreatedAt();
    return tokenOrm;
  }
}