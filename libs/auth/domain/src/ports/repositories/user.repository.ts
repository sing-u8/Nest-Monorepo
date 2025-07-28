import { User } from '../../entities/user.entity';

/**
 * UserRepository Port Interface
 * 
 * This interface defines the contract for user data persistence.
 * Infrastructure layer must implement this interface.
 * Following Dependency Inversion Principle - domain doesn't depend on infrastructure.
 */
export interface UserRepository {
  /**
   * Find a user by their unique ID
   * @param id - User's unique identifier
   * @returns User entity if found, null otherwise
   */
  findById(id: string): Promise<User | null>;

  /**
   * Find a user by their email address
   * @param email - User's email address
   * @returns User entity if found, null otherwise
   */
  findByEmail(email: string): Promise<User | null>;

  /**
   * Find a user by their social provider ID
   * @param provider - Authentication provider (e.g., 'google', 'apple')
   * @param providerId - User's ID from the provider
   * @returns User entity if found, null otherwise
   */
  findByProviderId(provider: string, providerId: string): Promise<User | null>;

  /**
   * Save a new user or update an existing one
   * @param user - User entity to save
   * @returns Saved user entity
   */
  save(user: User): Promise<User>;

  /**
   * Delete a user by their ID
   * @param id - User's unique identifier
   * @returns True if deleted, false if not found
   */
  delete(id: string): Promise<boolean>;

  /**
   * Check if an email already exists in the system
   * @param email - Email address to check
   * @returns True if email exists, false otherwise
   */
  existsByEmail(email: string): Promise<boolean>;

  /**
   * Find all users (with optional pagination)
   * @param options - Pagination options
   * @returns Array of users
   */
  findAll(options?: {
    skip?: number;
    take?: number;
    orderBy?: {
      field: string;
      direction: 'asc' | 'desc';
    };
  }): Promise<User[]>;

  /**
   * Count total number of users
   * @returns Total count of users
   */
  count(): Promise<number>;

  /**
   * Find users by their status
   * @param status - User status to filter by
   * @returns Array of users with the specified status
   */
  findByStatus(status: string): Promise<User[]>;

  /**
   * Update user's last login timestamp
   * @param userId - User's unique identifier
   * @param timestamp - Login timestamp
   */
  updateLastLogin(userId: string, timestamp: Date): Promise<void>;
}