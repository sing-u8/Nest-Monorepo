import { AuthSession } from '../../entities/auth-session.entity';
import { ClientInfo } from '@auth/shared';

/**
 * AuthSessionRepository Port Interface
 * 
 * This interface defines the contract for authentication session data persistence.
 * Infrastructure layer must implement this interface.
 */
export interface AuthSessionRepository {
  /**
   * Find a session by its unique ID
   * @param id - Session's unique identifier
   * @returns AuthSession entity if found, null otherwise
   */
  findById(id: string): Promise<AuthSession | null>;

  /**
   * Find a session by its token
   * @param sessionToken - Session token
   * @returns AuthSession entity if found, null otherwise
   */
  findByToken(sessionToken: string): Promise<AuthSession | null>;

  /**
   * Find all sessions for a specific user
   * @param userId - User's unique identifier
   * @returns Array of sessions belonging to the user
   */
  findByUserId(userId: string): Promise<AuthSession[]>;

  /**
   * Find active sessions for a specific user
   * @param userId - User's unique identifier
   * @returns Array of active sessions
   */
  findActiveByUserId(userId: string): Promise<AuthSession[]>;

  /**
   * Save a new session or update an existing one
   * @param session - AuthSession entity to save
   * @returns Saved session entity
   */
  save(session: AuthSession): Promise<AuthSession>;

  /**
   * Delete a session by its ID
   * @param id - Session's unique identifier
   * @returns True if deleted, false if not found
   */
  delete(id: string): Promise<boolean>;

  /**
   * Delete all sessions for a specific user
   * @param userId - User's unique identifier
   * @returns Number of sessions deleted
   */
  deleteByUserId(userId: string): Promise<number>;

  /**
   * Invalidate a session by its token
   * @param sessionToken - Session token to invalidate
   * @returns True if invalidated, false if not found
   */
  invalidateByToken(sessionToken: string): Promise<boolean>;

  /**
   * Invalidate all sessions for a specific user
   * @param userId - User's unique identifier
   * @returns Number of sessions invalidated
   */
  invalidateByUserId(userId: string): Promise<number>;

  /**
   * Find expired sessions
   * @returns Array of expired sessions
   */
  findExpired(): Promise<AuthSession[]>;

  /**
   * Delete expired sessions
   * @returns Number of sessions deleted
   */
  deleteExpired(): Promise<number>;

  /**
   * Find idle sessions that haven't been used for a specified time
   * @param idleMinutes - Number of minutes to consider a session idle
   * @returns Array of idle sessions
   */
  findIdle(idleMinutes: number): Promise<AuthSession[]>;

  /**
   * Update last activity timestamp for a session
   * @param sessionToken - Session token
   * @param timestamp - Activity timestamp
   * @returns True if updated, false if not found
   */
  updateActivity(sessionToken: string, timestamp: Date): Promise<boolean>;

  /**
   * Find sessions by device ID
   * @param deviceId - Device identifier
   * @returns Array of sessions from the device
   */
  findByDeviceId(deviceId: string): Promise<AuthSession[]>;

  /**
   * Find sessions by IP address
   * @param ipAddress - IP address
   * @returns Array of sessions from the IP
   */
  findByIpAddress(ipAddress: string): Promise<AuthSession[]>;

  /**
   * Count active sessions for a user
   * @param userId - User's unique identifier
   * @returns Number of active sessions
   */
  countActiveByUserId(userId: string): Promise<number>;

  /**
   * Clean up old sessions (expired and inactive)
   * @param olderThan - Date threshold
   * @returns Number of sessions cleaned up
   */
  cleanup(olderThan: Date): Promise<number>;

  /**
   * Check if a session token is valid and active
   * @param sessionToken - Session token
   * @returns True if valid and active, false otherwise
   */
  isValidSession(sessionToken: string): Promise<boolean>;
}