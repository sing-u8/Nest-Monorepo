import { MigrationInterface, QueryRunner, Table, Index } from 'typeorm';

/**
 * Initial database migration
 * 
 * Creates the core authentication tables:
 * - users: User account information
 * - tokens: JWT tokens for authentication
 * - auth_sessions: User session management
 */
export class CreateInitialTables1640995200000 implements MigrationInterface {
  name = 'CreateInitialTables1640995200000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create users table
    await queryRunner.createTable(
      new Table({
        name: 'users',
        columns: [
          {
            name: 'id',
            type: 'varchar',
            length: '255',
            isPrimary: true,
          },
          {
            name: 'email',
            type: 'varchar',
            length: '255',
            isUnique: true,
          },
          {
            name: 'password_hash',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'name',
            type: 'varchar',
            length: '100',
          },
          {
            name: 'profile_picture',
            type: 'varchar',
            length: '500',
            isNullable: true,
          },
          {
            name: 'is_active',
            type: 'boolean',
            default: true,
          },
          {
            name: 'email_verified',
            type: 'boolean',
            default: false,
          },
          {
            name: 'auth_provider',
            type: 'varchar',
            length: '50',
            default: "'LOCAL'",
          },
          {
            name: 'provider_id',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'last_login_at',
            type: 'timestamp with time zone',
            isNullable: true,
          },
          {
            name: 'created_at',
            type: 'timestamp with time zone',
            default: 'now()',
          },
          {
            name: 'updated_at',
            type: 'timestamp with time zone',
            default: 'now()',
          },
        ],
      }),
      true,
    );

    // Create tokens table
    await queryRunner.createTable(
      new Table({
        name: 'tokens',
        columns: [
          {
            name: 'id',
            type: 'varchar',
            length: '255',
            isPrimary: true,
          },
          {
            name: 'user_id',
            type: 'varchar',
            length: '255',
          },
          {
            name: 'type',
            type: 'varchar',
            length: '50',
          },
          {
            name: 'value',
            type: 'text',
            isUnique: true,
          },
          {
            name: 'expires_at',
            type: 'timestamp with time zone',
          },
          {
            name: 'is_revoked',
            type: 'boolean',
            default: false,
          },
          {
            name: 'revoked_at',
            type: 'timestamp with time zone',
            isNullable: true,
          },
          {
            name: 'created_at',
            type: 'timestamp with time zone',
            default: 'now()',
          },
          {
            name: 'updated_at',
            type: 'timestamp with time zone',
            default: 'now()',
          },
        ],
        foreignKeys: [
          {
            name: 'FK_tokens_user_id',
            columnNames: ['user_id'],
            referencedTableName: 'users',
            referencedColumnNames: ['id'],
            onDelete: 'CASCADE',
          },
        ],
      }),
      true,
    );

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
          },
          {
            name: 'user_id',
            type: 'varchar',
            length: '255',
          },
          {
            name: 'session_token',
            type: 'varchar',
            length: '500',
            isUnique: true,
          },
          {
            name: 'client_info',
            type: 'jsonb',
          },
          {
            name: 'expires_at',
            type: 'timestamp with time zone',
          },
          {
            name: 'last_activity_at',
            type: 'timestamp with time zone',
            default: 'now()',
          },
          {
            name: 'is_revoked',
            type: 'boolean',
            default: false,
          },
          {
            name: 'revoked_at',
            type: 'timestamp with time zone',
            isNullable: true,
          },
          {
            name: 'created_at',
            type: 'timestamp with time zone',
            default: 'now()',
          },
          {
            name: 'updated_at',
            type: 'timestamp with time zone',
            default: 'now()',
          },
        ],
        foreignKeys: [
          {
            name: 'FK_auth_sessions_user_id',
            columnNames: ['user_id'],
            referencedTableName: 'users',
            referencedColumnNames: ['id'],
            onDelete: 'CASCADE',
          },
        ],
      }),
      true,
    );

    // Create indexes for performance optimization
    
    // Users table indexes
    await queryRunner.createIndex(
      'users',
      new Index('IDX_users_email', ['email']),
    );
    
    await queryRunner.createIndex(
      'users',
      new Index('IDX_users_provider_provider_id', ['auth_provider', 'provider_id']),
    );
    
    await queryRunner.createIndex(
      'users',
      new Index('IDX_users_is_active', ['is_active']),
    );
    
    await queryRunner.createIndex(
      'users',
      new Index('IDX_users_created_at', ['created_at']),
    );

    // Tokens table indexes
    await queryRunner.createIndex(
      'tokens',
      new Index('IDX_tokens_user_id', ['user_id']),
    );
    
    await queryRunner.createIndex(
      'tokens',
      new Index('IDX_tokens_type', ['type']),
    );
    
    await queryRunner.createIndex(
      'tokens',
      new Index('IDX_tokens_expires_at', ['expires_at']),
    );
    
    await queryRunner.createIndex(
      'tokens',
      new Index('IDX_tokens_is_revoked', ['is_revoked']),
    );
    
    await queryRunner.createIndex(
      'tokens',
      new Index('IDX_tokens_user_type_active', ['user_id', 'type', 'is_revoked']),
    );

    // Auth sessions table indexes
    await queryRunner.createIndex(
      'auth_sessions',
      new Index('IDX_auth_sessions_user_id', ['user_id']),
    );
    
    await queryRunner.createIndex(
      'auth_sessions',
      new Index('IDX_auth_sessions_session_token', ['session_token']),
    );
    
    await queryRunner.createIndex(
      'auth_sessions',
      new Index('IDX_auth_sessions_expires_at', ['expires_at']),
    );
    
    await queryRunner.createIndex(
      'auth_sessions',
      new Index('IDX_auth_sessions_is_revoked', ['is_revoked']),
    );
    
    await queryRunner.createIndex(
      'auth_sessions',
      new Index('IDX_auth_sessions_last_activity', ['last_activity_at']),
    );
    
    await queryRunner.createIndex(
      'auth_sessions',
      new Index('IDX_auth_sessions_user_active', ['user_id', 'is_revoked']),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop tables in reverse order due to foreign key constraints
    await queryRunner.dropTable('auth_sessions');
    await queryRunner.dropTable('tokens');
    await queryRunner.dropTable('users');
  }
}