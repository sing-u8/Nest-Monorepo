import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserStatus } from '@shared/enum/user-status.enum';
import { GetUsersOptions, PaginatedResult } from '@shared/type/common.type';
import { User } from '@/auth/domain';
import { IUserRepository } from '@/auth/domain';
import { AuthProvider, Email, UserId } from '@/auth/domain';
import { UserTypeOrmEntity } from '../entity/user.typeorm.entity';

@Injectable()
export class UserTypeormRepository implements IUserRepository {

	constructor(
		@InjectRepository(UserTypeOrmEntity)
		private readonly userRepository: Repository<UserTypeOrmEntity>
	) {}

  async save(user: User): Promise<User> {
    const userEntity = this.toTypeormEntity(user);

    if (user.getId()) {
      // 기존 사용자 업데이트
      await this.userRepository.update(user.getId(), userEntity);
      const updatedEntity = await this.userRepository.findOne({
        where: { id: user.getId() },
      });
      if (!updatedEntity) {
        throw new Error('사용자 업데이트 후 조회 실패');
      }
      return this.toDomainEntity(updatedEntity);
    } else {
      // 새 사용자 생성
      const savedEntity = await this.userRepository.save(userEntity);
      return this.toDomainEntity(savedEntity);
    }
  }

  async findById(id: UserId): Promise<User | null> {
    const entity = await this.userRepository.findOne({
      where: { id: id.getValue() },
    });

    return entity ? this.toDomainEntity(entity) : null;
  }

  async findByEmail(email: Email): Promise<User | null> {
    const entity = await this.userRepository.findOne({
      where: { email: email.getValue() },
    });

    return entity ? this.toDomainEntity(entity) : null;
  }

  async findByProviderAndProviderId(provider: AuthProvider, providerId: string): Promise<User | null> {
    const entity = await this.userRepository.findOne({
      where: {
        provider: provider.getValue(),
        providerId: providerId,
      },
    });

    return entity ? this.toDomainEntity(entity) : null;
  }

  async existsByEmail(email: Email): Promise<boolean> {
    const count = await this.userRepository.count({
      where: { email: email.getValue() },
    });

    return count > 0;
  }

  async existsByProviderAndProviderId(provider: AuthProvider, providerId: string): Promise<boolean> {
    const count = await this.userRepository.count({
      where: {
        provider: provider.getValue(),
        providerId: providerId,
      },
    });

    return count > 0;
  }

  async delete(id: UserId): Promise<void> {
    await this.userRepository.delete(id.getValue());
  }

  async softDelete(id: UserId): Promise<void> {
    await this.userRepository.update(id.getValue(), {
      isActive: false,
      updatedAt: new Date(),
    });
  }

  async findMany(options: GetUsersOptions): Promise<PaginatedResult<User>> {
    const queryBuilder = this.userRepository.createQueryBuilder('user');

    // 필터링
    if (options.isActive !== undefined) {
      queryBuilder.andWhere('user.isActive = :isActive', { isActive: options.isActive });
    }

    if (options.provider) {
      queryBuilder.andWhere('user.provider = :provider', { provider: options.provider });
    }

    if (options.isEmailVerified !== undefined) {
      queryBuilder.andWhere('user.isEmailVerified = :isEmailVerified', {
        isEmailVerified: options.isEmailVerified,
      });
    }

    if (options.search) {
      queryBuilder.andWhere('user.email ILIKE :search', {
        search: `%${options.search}%`,
      });
    }

    // 정렬
    const sortField = options.sortBy || 'createdAt';
    const sortOrder = options.sortOrder || 'DESC';
    queryBuilder.orderBy(`user.${sortField}`, sortOrder);

    // 페이지네이션
    const page = options.page || 1;
    const limit = options.limit || 10;
    const offset = (page - 1) * limit;

    queryBuilder.skip(offset).take(limit);

    const [entities, total] = await queryBuilder.getManyAndCount();

    const users = entities.map(entity => this.toDomainEntity(entity));
    const totalPages = Math.ceil(total / limit);

    return {
      items: users,
      total,
      page,
      limit,
      totalPages,
      hasNext: page < totalPages,
      hasPrevious: page > 1,
    };
  }

  async updateStatus(id: UserId, status: UserStatus): Promise<void> {
    const isActive = status === UserStatus.ACTIVE;
    await this.userRepository.update(id.getValue(), {
      isActive: isActive,
      updatedAt: new Date(),
    });
  }

  async updateLastLoginAt(id: UserId): Promise<void> {
    await this.userRepository.update(id.getValue(), {
      lastLoginAt: new Date(),
      updatedAt: new Date(),
    });
  }

  async updateEmailVerificationStatus(id: UserId, isVerified: boolean): Promise<void> {
    await this.userRepository.update(id.getValue(), {
      isEmailVerified: isVerified,
      updatedAt: new Date(),
    });
  }

  async countByProvider(provider: AuthProvider): Promise<number> {
    return await this.userRepository.count({
      where: { provider: provider.getValue() },
    });
  }

  async countActiveUsers(): Promise<number> {
    return await this.userRepository.count({
      where: { isActive: true },
    });
  }

  private toDomainEntity(entity: UserTypeOrmEntity): User {
    return User.fromPersistence({
      id: UserId.create(entity.id),
      email: Email.create(entity.email),
      passwordHash: entity.passwordHash || undefined,
      provider: AuthProvider.create(entity.provider as any),
      providerId: entity.providerId || undefined,
      status: entity.isActive ? UserStatus.ACTIVE : UserStatus.INACTIVE,
      isEmailVerified: entity.isEmailVerified,
      lastLoginAt: entity.lastLoginAt || undefined,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
    });
  }

  private toTypeormEntity(user: User): Partial<UserTypeOrmEntity> {
    const data: Partial<UserTypeOrmEntity> = {
      email: user.getEmail().getValue(),
      provider: user.getProvider()?.getValue() || 'local',
      isActive: user.isActive(),
      isEmailVerified: user.isEmailVerified(),
      updatedAt: new Date(),
    };

    if (user.getId()) {
      data.id = user.getId();
    }

    if (user.getPasswordHash()) {
      data.passwordHash = user.getPasswordHash();
    }

    if (user.getProviderId()) {
      data.providerId = user.getProviderId();
    }

    if (user.getLastLoginAt()) {
      data.lastLoginAt = user.getLastLoginAt();
    }

    if (user.getCreatedAt()) {
      data.createdAt = user.getCreatedAt();
    }

    return data;
  }
}
