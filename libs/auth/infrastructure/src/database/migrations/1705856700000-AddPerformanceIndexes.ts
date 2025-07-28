import { MigrationInterface, QueryRunner, Index } from 'typeorm';

/**
 * Performance Indexes Migration
 * 
 * Adds additional performance-optimized indexes for common query patterns
 * based on expected usage patterns and query optimization.
 */
export class AddPerformanceIndexes1705856700000 implements MigrationInterface {
  name = 'AddPerformanceIndexes1705856700000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Users table performance indexes
    
    // Composite index for active users with recent login (admin dashboard queries)
    await queryRunner.createIndex(
      'users',
      new Index('IDX_users_status_last_login_at', ['status', 'last_login_at'])
    );

    // Index for email verification status queries
    await queryRunner.createIndex(
      'users',
      new Index('IDX_users_email_verified_status', ['email_verified', 'status'])
    );

    // Index for provider-based user searches
    await queryRunner.createIndex(
      'users',
      new Index('IDX_users_provider_status', ['provider', 'status'])
    );

    // Tokens table performance indexes
    
    // Composite index for active tokens cleanup queries
    await queryRunner.createIndex(
      'tokens',
      new Index('IDX_tokens_type_expires_at_revoked_at', ['type', 'expires_at', 'revoked_at'])
    );

    // Index for user token management (get all active tokens for a user)
    await queryRunner.createIndex(
      'tokens',
      new Index('IDX_tokens_user_id_type_expires_at', ['user_id', 'type', 'expires_at'])
    );

    // Index for token cleanup by creation date (for old token removal)
    await queryRunner.createIndex(
      'tokens',
      new Index('IDX_tokens_created_at_type', ['created_at', 'type'])
    );

    // AuthSessions table performance indexes
    
    // Composite index for session cleanup queries (expired and revoked sessions)
    await queryRunner.createIndex(
      'auth_sessions',
      new Index('IDX_auth_sessions_status_expires_at_last_activity', ['status', 'expires_at', 'last_activity_at'])
    );

    // Index for device-based session management
    await queryRunner.createIndex(
      'auth_sessions',
      new Index('IDX_auth_sessions_device_id_user_id_status', ['device_id', 'user_id', 'status'])
    );

    // Index for IP-based security monitoring
    await queryRunner.createIndex(
      'auth_sessions',
      new Index('IDX_auth_sessions_ip_address_created_at', ['ip_address', 'created_at'])
    );

    // Index for platform-based analytics
    await queryRunner.createIndex(
      'auth_sessions',
      new Index('IDX_auth_sessions_platform_created_at', ['platform', 'created_at'])
    );

    // Index for active session count per user
    await queryRunner.createIndex(
      'auth_sessions',
      new Index('IDX_auth_sessions_user_id_status_expires_at', ['user_id', 'status', 'expires_at'])
    );

    // Partial indexes for better performance (PostgreSQL specific)
    
    // Index only active users (reduces index size)
    await queryRunner.query(`
      CREATE INDEX CONCURRENTLY IF NOT EXISTS IDX_users_active_email 
      ON users (email) 
      WHERE status = 'active'
    `);

    // Index only non-revoked tokens
    await queryRunner.query(`
      CREATE INDEX CONCURRENTLY IF NOT EXISTS IDX_tokens_active_value 
      ON tokens (value) 
      WHERE revoked_at IS NULL
    `);

    // Index only active sessions
    await queryRunner.query(`
      CREATE INDEX CONCURRENTLY IF NOT EXISTS IDX_auth_sessions_active_expires_at 
      ON auth_sessions (expires_at) 
      WHERE status = 'active'
    `);

    // Add database-level optimizations
    
    // Set statistics targets for better query planning
    await queryRunner.query('ALTER TABLE users ALTER COLUMN email SET STATISTICS 1000');
    await queryRunner.query('ALTER TABLE users ALTER COLUMN status SET STATISTICS 1000');
    await queryRunner.query('ALTER TABLE tokens ALTER COLUMN type SET STATISTICS 1000');
    await queryRunner.query('ALTER TABLE tokens ALTER COLUMN expires_at SET STATISTICS 1000');
    await queryRunner.query('ALTER TABLE auth_sessions ALTER COLUMN status SET STATISTICS 1000');
    await queryRunner.query('ALTER TABLE auth_sessions ALTER COLUMN expires_at SET STATISTICS 1000');
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Remove statistics targets
    await queryRunner.query('ALTER TABLE users ALTER COLUMN email SET STATISTICS -1');
    await queryRunner.query('ALTER TABLE users ALTER COLUMN status SET STATISTICS -1');
    await queryRunner.query('ALTER TABLE tokens ALTER COLUMN type SET STATISTICS -1');
    await queryRunner.query('ALTER TABLE tokens ALTER COLUMN expires_at SET STATISTICS -1');
    await queryRunner.query('ALTER TABLE auth_sessions ALTER COLUMN status SET STATISTICS -1');
    await queryRunner.query('ALTER TABLE auth_sessions ALTER COLUMN expires_at SET STATISTICS -1');

    // Drop partial indexes
    await queryRunner.query('DROP INDEX CONCURRENTLY IF EXISTS IDX_auth_sessions_active_expires_at');
    await queryRunner.query('DROP INDEX CONCURRENTLY IF EXISTS IDX_tokens_active_value');
    await queryRunner.query('DROP INDEX CONCURRENTLY IF EXISTS IDX_users_active_email');

    // Drop composite indexes for auth_sessions
    await queryRunner.dropIndex('auth_sessions', 'IDX_auth_sessions_user_id_status_expires_at');
    await queryRunner.dropIndex('auth_sessions', 'IDX_auth_sessions_platform_created_at');
    await queryRunner.dropIndex('auth_sessions', 'IDX_auth_sessions_ip_address_created_at');
    await queryRunner.dropIndex('auth_sessions', 'IDX_auth_sessions_device_id_user_id_status');
    await queryRunner.dropIndex('auth_sessions', 'IDX_auth_sessions_status_expires_at_last_activity');

    // Drop composite indexes for tokens
    await queryRunner.dropIndex('tokens', 'IDX_tokens_created_at_type');
    await queryRunner.dropIndex('tokens', 'IDX_tokens_user_id_type_expires_at');
    await queryRunner.dropIndex('tokens', 'IDX_tokens_type_expires_at_revoked_at');

    // Drop composite indexes for users
    await queryRunner.dropIndex('users', 'IDX_users_provider_status');
    await queryRunner.dropIndex('users', 'IDX_users_email_verified_status');
    await queryRunner.dropIndex('users', 'IDX_users_status_last_login_at');
  }
}