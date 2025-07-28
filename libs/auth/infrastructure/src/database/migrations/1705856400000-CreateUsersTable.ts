import { MigrationInterface, QueryRunner, Table, Index } from 'typeorm';

/**
 * Initial Users Table Migration
 * 
 * Creates the users table with all necessary columns, indexes, and constraints
 * for user authentication and profile management.
 */
export class CreateUsersTable1705856400000 implements MigrationInterface {
  name = 'CreateUsersTable1705856400000';

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
            comment: 'Unique user identifier (UUID)',
          },
          {
            name: 'email',
            type: 'varchar',
            length: '255',
            isUnique: true,
            isNullable: false,
            comment: 'User email address (unique)',
          },
          {
            name: 'password',
            type: 'varchar',
            length: '255',
            isNullable: true,
            comment: 'Hashed password (null for social login users)',
          },
          {
            name: 'name',
            type: 'varchar',
            length: '100',
            isNullable: false,
            comment: 'User full name or display name',
          },
          {
            name: 'profile_picture',
            type: 'text',
            isNullable: true,
            comment: 'URL to user profile picture',
          },
          {
            name: 'provider',
            type: 'varchar',
            length: '50',
            default: "'local'",
            isNullable: false,
            comment: 'Authentication provider (local, google, apple)',
          },
          {
            name: 'provider_id',
            type: 'varchar',
            length: '255',
            isNullable: true,
            comment: 'Provider-specific user ID',
          },
          {
            name: 'email_verified',
            type: 'boolean',
            default: false,
            isNullable: false,
            comment: 'Whether user email has been verified',
          },
          {
            name: 'status',
            type: 'varchar',
            length: '20',
            default: "'active'",
            isNullable: false,
            comment: 'User account status (active, inactive, suspended, deleted)',
          },
          {
            name: 'last_login_at',
            type: 'timestamp',
            isNullable: true,
            comment: 'Timestamp of last successful login',
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
            isNullable: false,
            comment: 'Account creation timestamp',
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
          new Index('IDX_users_email', ['email'], { isUnique: true }),
          new Index('IDX_users_provider_provider_id', ['provider', 'provider_id'], { isUnique: true }),
          new Index('IDX_users_status', ['status']),
          new Index('IDX_users_created_at', ['created_at']),
          new Index('IDX_users_last_login_at', ['last_login_at']),
        ],
      }),
      true,
    );

    // Add check constraints for valid values
    await queryRunner.query(`
      ALTER TABLE users 
      ADD CONSTRAINT CHK_users_provider 
      CHECK (provider IN ('local', 'google', 'apple'))
    `);

    await queryRunner.query(`
      ALTER TABLE users 
      ADD CONSTRAINT CHK_users_status 
      CHECK (status IN ('active', 'inactive', 'suspended', 'deleted'))
    `);

    // Add constraint to ensure provider_id is not null for non-local providers
    await queryRunner.query(`
      ALTER TABLE users 
      ADD CONSTRAINT CHK_users_provider_id 
      CHECK (
        (provider = 'local' AND provider_id IS NULL) OR 
        (provider != 'local' AND provider_id IS NOT NULL)
      )
    `);

    // Add constraint to ensure password is not null for local provider
    await queryRunner.query(`
      ALTER TABLE users 
      ADD CONSTRAINT CHK_users_password 
      CHECK (
        (provider = 'local' AND password IS NOT NULL) OR 
        (provider != 'local')
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop constraints first
    await queryRunner.query('ALTER TABLE users DROP CONSTRAINT IF EXISTS CHK_users_password');
    await queryRunner.query('ALTER TABLE users DROP CONSTRAINT IF EXISTS CHK_users_provider_id');
    await queryRunner.query('ALTER TABLE users DROP CONSTRAINT IF EXISTS CHK_users_status');
    await queryRunner.query('ALTER TABLE users DROP CONSTRAINT IF EXISTS CHK_users_provider');

    // Drop the table
    await queryRunner.dropTable('users');
  }
}