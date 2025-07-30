import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../domain/entities/user.entity';
import { UserRepository } from '../../domain/ports/user.repository';
import { UserOrmEntity } from '../database/entities/user.orm-entity';
import { AuthProvider } from '@auth/shared/types/auth.types';

@Injectable()
export class UserRepositoryImpl implements UserRepository {
  constructor(
    @InjectRepository(UserOrmEntity)
    private readonly userOrmRepository: Repository<UserOrmEntity>,
  ) {}

  async save(user: User): Promise<User> {
    const userOrm = this.toOrmEntity(user);
    const savedUserOrm = await this.userOrmRepository.save(userOrm);
    return this.toDomainEntity(savedUserOrm);
  }

  async findById(id: string): Promise<User | null> {
    const userOrm = await this.userOrmRepository.findOne({ where: { id } });
    return userOrm ? this.toDomainEntity(userOrm) : null;
  }

  async findByEmail(email: string): Promise<User | null> {
    const userOrm = await this.userOrmRepository.findOne({ where: { email } });
    return userOrm ? this.toDomainEntity(userOrm) : null;
  }

  async existsByEmail(email: string): Promise<boolean> {
    const count = await this.userOrmRepository.count({ where: { email } });
    return count > 0;
  }

  async update(id: string, updates: Partial<User>): Promise<User> {
    const existingUserOrm = await this.userOrmRepository.findOne({ where: { id } });
    if (!existingUserOrm) {
      throw new Error(`User with id ${id} not found`);
    }

    // Convert domain updates to ORM format
    const ormUpdates: Partial<UserOrmEntity> = {};
    
    if (updates.name !== undefined) {
      ormUpdates.name = updates.name;
    }
    
    if (updates.profilePicture !== undefined) {
      ormUpdates.profilePicture = updates.profilePicture;
    }

    // Update the entity
    await this.userOrmRepository.update(id, {
      ...ormUpdates,
      updatedAt: new Date(),
    });

    // Fetch and return updated entity
    const updatedUserOrm = await this.userOrmRepository.findOne({ where: { id } });
    if (!updatedUserOrm) {
      throw new Error(`Failed to retrieve updated user with id ${id}`);
    }

    return this.toDomainEntity(updatedUserOrm);
  }

  async delete(id: string): Promise<void> {
    const result = await this.userOrmRepository.delete(id);
    if (result.affected === 0) {
      throw new Error(`User with id ${id} not found`);
    }
  }

  async activate(id: string): Promise<void> {
    const result = await this.userOrmRepository.update(id, { 
      isActive: true,
      updatedAt: new Date(),
    });
    
    if (result.affected === 0) {
      throw new Error(`User with id ${id} not found`);
    }
  }

  async deactivate(id: string): Promise<void> {
    const result = await this.userOrmRepository.update(id, { 
      isActive: false,
      updatedAt: new Date(),
    });
    
    if (result.affected === 0) {
      throw new Error(`User with id ${id} not found`);
    }
  }

  async findByProvider(provider: string, providerId: string): Promise<User | null> {
    const userOrm = await this.userOrmRepository.findOne({ 
      where: { 
        provider: provider as AuthProvider, 
        providerId 
      } 
    });
    return userOrm ? this.toDomainEntity(userOrm) : null;
  }

  private toDomainEntity(userOrm: UserOrmEntity): User {
    return new User(
      userOrm.id,
      userOrm.email,
      userOrm.passwordHash || '',
      userOrm.name,
      userOrm.profilePicture,
      userOrm.provider,
      userOrm.providerId,
      userOrm.isActive,
      userOrm.createdAt,
      userOrm.updatedAt,
    );
  }

  private toOrmEntity(user: User): UserOrmEntity {
    const userOrm = new UserOrmEntity();
    userOrm.id = user.id;
    userOrm.email = user.email;
    userOrm.passwordHash = user.getPassword();
    userOrm.name = user.name;
    userOrm.profilePicture = user.profilePicture;
    userOrm.provider = user.provider;
    userOrm.providerId = user.providerId;
    userOrm.isActive = user.isAccountActive();
    userOrm.createdAt = user.getCreatedAt();
    userOrm.updatedAt = user.getUpdatedAt();
    return userOrm;
  }
}