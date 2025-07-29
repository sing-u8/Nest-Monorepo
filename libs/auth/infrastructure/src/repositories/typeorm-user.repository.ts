import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRepository } from '@auth/domain';
import { UserEntity } from '../database/entities/user.entity';
import { UserMapper } from '../database/mappers/user.mapper';
import { MetricsService } from '../services/metrics.service';
import { TrackDatabaseOperation, InjectMetrics } from '../decorators/metrics.decorator';

/**
 * TypeORM User Repository Implementation
 * 
 * Implements the UserRepository port interface using TypeORM for data persistence.
 * Handles conversion between domain entities and database entities.
 */
@Injectable()
export class TypeOrmUserRepository implements UserRepository {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    @InjectMetrics()
    private readonly metricsService: MetricsService,
  ) {}

  /**
   * Find a user by their unique ID
   */
  @TrackDatabaseOperation('select', 'users')
  async findById(id: string): Promise<User | null> {
    try {
      const userEntity = await this.userRepository.findOne({
        where: { id }
      });

      return userEntity ? UserMapper.toDomain(userEntity) : null;
    } catch (error) {
      console.error('Error finding user by ID:', error);
      throw new Error(`Failed to find user by ID: ${id}`);
    }
  }

  /**
   * Find a user by their email address
   */
  @TrackDatabaseOperation('select', 'users')
  async findByEmail(email: string): Promise<User | null> {
    try {
      const userEntity = await this.userRepository.findOne({
        where: { email }
      });

      return userEntity ? UserMapper.toDomain(userEntity) : null;
    } catch (error) {
      console.error('Error finding user by email:', error);
      throw new Error(`Failed to find user by email: ${email}`);
    }
  }

  /**
   * Find a user by their social provider ID
   */
  async findByProviderId(provider: string, providerId: string): Promise<User | null> {
    try {
      const userEntity = await this.userRepository.findOne({
        where: { 
          provider,
          provider_id: providerId
        }
      });

      return userEntity ? UserMapper.toDomain(userEntity) : null;
    } catch (error) {
      console.error('Error finding user by provider ID:', error);
      throw new Error(`Failed to find user by provider ID: ${provider}:${providerId}`);
    }
  }

  /**
   * Save a new user or update an existing one
   */
  async save(user: User): Promise<User> {
    try {
      const userObject = user.toObject();
      const userId = userObject['id'];

      // Check if user exists
      const existingUser = await this.userRepository.findOne({
        where: { id: userId }
      });

      let savedEntity: UserEntity;

      if (existingUser) {
        // Update existing user
        const updatedEntity = UserMapper.updatePersistence(existingUser, user);
        savedEntity = await this.userRepository.save(updatedEntity);
      } else {
        // Create new user
        const newEntity = UserMapper.toPersistence(user);
        savedEntity = await this.userRepository.save(newEntity);
      }

      return UserMapper.toDomain(savedEntity);
    } catch (error) {
      console.error('Error saving user:', error);
      throw new Error('Failed to save user');
    }
  }

  /**
   * Delete a user by their ID
   */
  async delete(id: string): Promise<boolean> {
    try {
      const result = await this.userRepository.delete({ id });
      return result.affected !== undefined && result.affected > 0;
    } catch (error) {
      console.error('Error deleting user:', error);
      throw new Error(`Failed to delete user: ${id}`);
    }
  }

  /**
   * Check if an email already exists in the system
   */
  async existsByEmail(email: string): Promise<boolean> {
    try {
      const count = await this.userRepository.count({
        where: { email }
      });
      return count > 0;
    } catch (error) {
      console.error('Error checking email existence:', error);
      throw new Error(`Failed to check email existence: ${email}`);
    }
  }

  /**
   * Find all users (with optional pagination)
   */
  async findAll(options?: {
    skip?: number;
    take?: number;
    orderBy?: {
      field: string;
      direction: 'asc' | 'desc';
    };
  }): Promise<User[]> {
    try {
      const queryBuilder = this.userRepository.createQueryBuilder('user');

      // Apply pagination
      if (options?.skip !== undefined) {
        queryBuilder.skip(options.skip);
      }
      if (options?.take !== undefined) {
        queryBuilder.take(options.take);
      }

      // Apply ordering
      if (options?.orderBy) {
        const orderField = this.mapOrderField(options.orderBy.field);
        queryBuilder.orderBy(`user.${orderField}`, options.orderBy.direction.toUpperCase() as 'ASC' | 'DESC');
      } else {
        // Default ordering
        queryBuilder.orderBy('user.created_at', 'DESC');
      }

      const userEntities = await queryBuilder.getMany();
      return UserMapper.toDomainArray(userEntities);
    } catch (error) {
      console.error('Error finding all users:', error);
      throw new Error('Failed to find all users');
    }
  }

  /**
   * Count total number of users
   */
  async count(): Promise<number> {
    try {
      return await this.userRepository.count();
    } catch (error) {
      console.error('Error counting users:', error);
      throw new Error('Failed to count users');
    }
  }

  /**
   * Find users by their status
   */
  async findByStatus(status: string): Promise<User[]> {
    try {
      const userEntities = await this.userRepository.find({
        where: { status },
        order: { created_at: 'DESC' }
      });

      return UserMapper.toDomainArray(userEntities);
    } catch (error) {
      console.error('Error finding users by status:', error);
      throw new Error(`Failed to find users by status: ${status}`);
    }
  }

  /**
   * Update user's last login timestamp
   */
  async updateLastLogin(userId: string, timestamp: Date): Promise<void> {
    try {
      await this.userRepository.update(
        { id: userId },
        { last_login_at: timestamp }
      );
    } catch (error) {
      console.error('Error updating last login:', error);
      throw new Error(`Failed to update last login for user: ${userId}`);
    }
  }

  /**
   * Map domain field names to database field names
   */
  private mapOrderField(field: string): string {
    const fieldMap: { [key: string]: string } = {
      'id': 'id',
      'email': 'email',
      'name': 'name',
      'status': 'status',
      'createdAt': 'created_at',
      'updatedAt': 'updated_at',
      'lastLoginAt': 'last_login_at',
    };

    return fieldMap[field] || 'created_at';
  }
}