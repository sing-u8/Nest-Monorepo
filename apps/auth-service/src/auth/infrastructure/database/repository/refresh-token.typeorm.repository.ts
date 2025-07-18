import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { LessThan, MoreThan, Repository } from 'typeorm';
import { RefreshToken } from '@/auth/domain';
import { IRefreshTokenRepository } from '@/auth/domain';
import { UserId } from '@/auth/domain';
import { RefreshTokenTypeOrmEntity } from '../entity/refresh-token.typeorm.entity';

@Injectable()
export class RefreshTokenTypeormRepository implements IRefreshTokenRepository {

	constructor(
		@InjectRepository(RefreshTokenTypeOrmEntity)
		private readonly refreshTokenRepository: Repository<RefreshTokenTypeOrmEntity>
	) {}

  async save(refreshToken: RefreshToken): Promise<RefreshToken> {
    const entity = this.toTypeormEntity(refreshToken);

    if (refreshToken.getId()) {
      // 기존 토큰 업데이트
      await this.refreshTokenRepository.update(refreshToken.getId(), entity);
      const updatedEntity = await this.refreshTokenRepository.findOne({
        where: { id: refreshToken.getId() },
      });
      if (!updatedEntity) {
        throw new Error('토큰 업데이트 후 조회 실패');
      }
      return this.toDomainEntity(updatedEntity);
    } else {
      // 새 토큰 생성
      const savedEntity = await this.refreshTokenRepository.save(entity);
      return this.toDomainEntity(savedEntity);
    }
  }

  async findById(id: string): Promise<RefreshToken | null> {
    const entity = await this.refreshTokenRepository.findOne({
      where: { id },
    });

    return entity ? this.toDomainEntity(entity) : null;
  }

  async findByToken(token: string): Promise<RefreshToken | null> {
    const entity = await this.refreshTokenRepository.findOne({
      where: { token },
    });

    return entity ? this.toDomainEntity(entity) : null;
  }

  async findByUserId(userId: UserId): Promise<RefreshToken[]> {
    const entities = await this.refreshTokenRepository.find({
      where: { userId: userId.getValue() },
      order: { createdAt: 'DESC' },
    });

    return entities.map(entity => this.toDomainEntity(entity));
  }

  async findActiveTokensByUserId(userId: UserId): Promise<RefreshToken[]> {
    const entities = await this.refreshTokenRepository.find({
      where: {
        userId: userId.getValue(),
        isActive: true,
        expiresAt: MoreThan(new Date()),
      },
      order: { createdAt: 'DESC' },
    });

    return entities.map(entity => this.toDomainEntity(entity));
  }

  async findByUserIdAndDeviceInfo(userId: UserId, deviceInfo: string): Promise<RefreshToken | null> {
    const entity = await this.refreshTokenRepository.findOne({
      where: {
        userId: userId.getValue(),
        deviceInfo,
        isActive: true,
      },
    });

    return entity ? this.toDomainEntity(entity) : null;
  }

  async existsByToken(token: string): Promise<boolean> {
    const count = await this.refreshTokenRepository.count({
      where: { token },
    });
    return count > 0;
  }

  async deleteAllByUserId(userId: UserId): Promise<void> {
    await this.refreshTokenRepository.delete({ userId: userId.getValue() });
  }

  async deleteByUserIdAndDeviceInfo(userId: UserId, deviceInfo: string): Promise<void> {
    await this.refreshTokenRepository.delete({
      userId: userId.getValue(),
      deviceInfo,
    });
  }

  async deleteByToken(token: string): Promise<void> {
    await this.refreshTokenRepository.delete({ token });
  }

  async deleteExpiredTokens(): Promise<number> {
    const result = await this.refreshTokenRepository.delete({
      expiresAt: LessThan(new Date()),
    });

    return result.affected || 0;
  }

  async deactivateByUserId(userId: UserId): Promise<void> {
    await this.refreshTokenRepository.update(
      { userId: userId.getValue() },
      { isActive: false }
    );
  }

  async deactivateByToken(token: string): Promise<void> {
    await this.refreshTokenRepository.update(
      { token },
      { isActive: false }
    );
  }

  async countActiveTokensByUserId(userId: UserId): Promise<number> {
    return await this.refreshTokenRepository.count({
      where: {
        userId: userId.getValue(),
        isActive: true,
        expiresAt: MoreThan(new Date()),
      },
    });
  }

  async delete(id: string): Promise<void> {
    await this.refreshTokenRepository.delete(id);
  }

  async updateLastUsedAt(id: string, lastUsedAt: Date): Promise<void> {
    await this.refreshTokenRepository.update(id, { lastUsedAt });
  }

  async deactivateToken(id: string): Promise<void> {
    await this.refreshTokenRepository.update(id, { isActive: false });
  }

  async deleteOldTokensByUserId(userId: UserId, keepCount: number): Promise<number> {
    const tokens = await this.refreshTokenRepository.find({
      where: { userId: userId.getValue() },
      order: { createdAt: 'DESC' },
    });

    if (tokens.length <= keepCount) {
      return 0;
    }

    const tokensToDelete = tokens.slice(keepCount);
    const idsToDelete = tokensToDelete.map(token => token.id);

    const result = await this.refreshTokenRepository.delete(idsToDelete);
    return result.affected || 0;
  }

  private toDomainEntity(entity: RefreshTokenTypeOrmEntity): RefreshToken {
    return RefreshToken.fromPersistence({
      id: entity.id,
      userId: UserId.create(entity.userId),
      token: entity.token,
      expiresAt: entity.expiresAt,
      deviceInfo: entity.deviceInfo || undefined,
      ipAddress: entity.ipAddress || undefined,
      isActive: entity.isActive,
      lastUsedAt: entity.lastUsedAt || undefined,
      createdAt: entity.createdAt,
    });
  }

  private toTypeormEntity(refreshToken: RefreshToken): Partial<RefreshTokenTypeOrmEntity> {
    const data: Partial<RefreshTokenTypeOrmEntity> = {
      userId: refreshToken.getUserId().getValue(),
      token: refreshToken.getToken(),
      expiresAt: refreshToken.getExpiresAt(),
      isActive: refreshToken.getIsActive(),
    };

    if (refreshToken.getId()) {
      data.id = refreshToken.getId();
    }

    if (refreshToken.getDeviceInfo()) {
      data.deviceInfo = refreshToken.getDeviceInfo();
    }

    if (refreshToken.getIpAddress()) {
      data.ipAddress = refreshToken.getIpAddress();
    }

    if (refreshToken.getLastUsedAt()) {
      data.lastUsedAt = refreshToken.getLastUsedAt();
    }

    if (refreshToken.getCreatedAt()) {
      data.createdAt = refreshToken.getCreatedAt();
    }

    return data;
  }
}
