import { MigrationInterface, QueryRunner, Table, Index, ForeignKey } from 'typeorm';

/**
 * AuthSessions Table Migration
 * 
 * Creates the auth_sessions table for managing user authentication sessions
 * with device tracking and session management capabilities.
 */
export class CreateAuthSessionsTable1705856600000 implements MigrationInterface {
  name = 'CreateAuthSessionsTable1705856600000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create auth_sessions table
    await queryRunner.createTable(
      new Table({
        name: 'auth_sessions',
        columns: [
          {
            name: 'id',
            type: 'varchar',
            length: '255',
            isPrimary: true,
            comment: 'Unique session identifier (UUID)',
          },
          {
            name: 'user_id',
            type: 'varchar',
            length: '255',
            isNullable: false,
            comment: 'Reference to user who owns this session',
          },
          {
            name: 'session_token',
            type: 'text',
            isNullable: false,
            comment: 'Unique session token (hashed)',
          },
          {
            name: 'status',
            type: 'varchar',
            length: '20',
            default: "'active'",
            isNullable: false,
            comment: 'Session status (active, expired, revoked)',
          },
          {
            name: 'device_id',
            type: 'varchar',
            length: '255',
            isNullable: true,
            comment: 'Device identifier for tracking',
          },
          {
            name: 'platform',
            type: 'varchar',
            length: '100',
            isNullable: true,
            comment: 'Platform/OS information (iOS, Android, Web, etc.)',
          },
          {
            name: 'ip_address',
            type: 'varchar',
            length: '45',
            isNullable: true,
            comment: 'Client IP address (supports IPv6)',
          },
          {
            name: 'user_agent',
            type: 'text',
            isNullable: true,
            comment: 'Client user agent string',
          },
          {
            name: 'expires_at',
            type: 'timestamp',
            isNullable: false,
            comment: 'Session expiration timestamp',
          },
          {
            name: 'last_activity_at',
            type: 'timestamp',
            isNullable: false,
            comment: 'Last activity timestamp for session tracking',
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
            isNullable: false,
            comment: 'Session creation timestamp',
          },
          {
            name: 'updated_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
            onUpdate: 'CURRENT_TIMESTAMP',
            isNullable: false,
            comment: 'Last update timestamp',
          },
        ],
        indices: [
          new Index('IDX_auth_sessions_user_id', ['user_id']),
          new Index('IDX_auth_sessions_session_token', ['session_token'], { isUnique: true }),
          new Index('IDX_auth_sessions_status', ['status']),
          new Index('IDX_auth_sessions_expires_at', ['expires_at']),
          new Index('IDX_auth_sessions_last_activity_at', ['last_activity_at']),
          new Index('IDX_auth_sessions_ip_address', ['ip_address']),
          new Index('IDX_auth_sessions_device_id', ['device_id']),
          new Index('IDX_auth_sessions_user_id_status', ['user_id', 'status']),
          new Index('IDX_auth_sessions_expires_at_status', ['expires_at', 'status']),
        ],
        foreignKeys: [
          new ForeignKey({
            name: 'FK_auth_sessions_user_id',
            columnNames: ['user_id'],
            referencedTableName: 'users',
            referencedColumnNames: ['id'],
            onDelete: 'CASCADE',
            onUpdate: 'CASCADE',
          }),
        ],
      }),
      true,
    );

    // Add check constraints for valid session statuses
    await queryRunner.query(`
      ALTER TABLE auth_sessions 
      ADD CONSTRAINT CHK_auth_sessions_status 
      CHECK (status IN ('active', 'expired', 'revoked'))
    `);

    // Add constraint to ensure expires_at is in the future when creating
    await queryRunner.query(`
      ALTER TABLE auth_sessions 
      ADD CONSTRAINT CHK_auth_sessions_expires_at 
      CHECK (expires_at > created_at)
    `);

    // Add constraint to ensure last_activity_at is not before created_at
    await queryRunner.query(`
      ALTER TABLE auth_sessions 
      ADD CONSTRAINT CHK_auth_sessions_last_activity_at 
      CHECK (last_activity_at >= created_at)
    `);

    // Add constraint for IP address format (basic validation)
    await queryRunner.query(`
      ALTER TABLE auth_sessions 
      ADD CONSTRAINT CHK_auth_sessions_ip_address 
      CHECK (
        ip_address IS NULL OR 
        ip_address ~ '^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop constraints first
    await queryRunner.query('ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS CHK_auth_sessions_ip_address');
    await queryRunner.query('ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS CHK_auth_sessions_last_activity_at');
    await queryRunner.query('ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS CHK_auth_sessions_expires_at');
    await queryRunner.query('ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS CHK_auth_sessions_status');

    // Drop foreign key
    await queryRunner.dropForeignKey('auth_sessions', 'FK_auth_sessions_user_id');

    // Drop the table
    await queryRunner.dropTable('auth_sessions');
  }
}