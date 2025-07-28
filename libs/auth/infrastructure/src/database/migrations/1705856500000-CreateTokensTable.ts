import { MigrationInterface, QueryRunner, Table, Index, ForeignKey } from 'typeorm';

/**
 * Tokens Table Migration
 * 
 * Creates the tokens table for managing authentication tokens (refresh tokens, etc.)
 * with proper relationships to users and efficient indexing.
 */
export class CreateTokensTable1705856500000 implements MigrationInterface {
  name = 'CreateTokensTable1705856500000';

  public async up(queryRunner: QueryRunner): Promise<void> {
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
            comment: 'Unique token identifier (UUID)',
          },
          {
            name: 'user_id',
            type: 'varchar',
            length: '255',
            isNullable: false,
            comment: 'Reference to user who owns this token',
          },
          {
            name: 'type',
            type: 'varchar',
            length: '50',
            isNullable: false,
            comment: 'Token type (refresh_token, access_token, email_verification, etc.)',
          },
          {
            name: 'value',
            type: 'text',
            isNullable: false,
            comment: 'Token value (hashed or encrypted)',
          },
          {
            name: 'expires_at',
            type: 'timestamp',
            isNullable: false,
            comment: 'Token expiration timestamp',
          },
          {
            name: 'revoked_at',
            type: 'timestamp',
            isNullable: true,
            comment: 'Token revocation timestamp (null if not revoked)',
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
            isNullable: false,
            comment: 'Token creation timestamp',
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
          new Index('IDX_tokens_user_id', ['user_id']),
          new Index('IDX_tokens_type', ['type']),
          new Index('IDX_tokens_value', ['value'], { isUnique: true }),
          new Index('IDX_tokens_expires_at', ['expires_at']),
          new Index('IDX_tokens_revoked_at', ['revoked_at']),
          new Index('IDX_tokens_user_id_type', ['user_id', 'type']),
          new Index('IDX_tokens_expires_at_revoked_at', ['expires_at', 'revoked_at']),
        ],
        foreignKeys: [
          new ForeignKey({
            name: 'FK_tokens_user_id',
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

    // Add check constraints for valid token types
    await queryRunner.query(`
      ALTER TABLE tokens 
      ADD CONSTRAINT CHK_tokens_type 
      CHECK (type IN (
        'refresh_token', 
        'access_token', 
        'email_verification', 
        'password_reset',
        'two_factor'
      ))
    `);

    // Add constraint to ensure expires_at is in the future when creating
    await queryRunner.query(`
      ALTER TABLE tokens 
      ADD CONSTRAINT CHK_tokens_expires_at 
      CHECK (expires_at > created_at)
    `);

    // Add constraint to ensure revoked_at is after created_at if set
    await queryRunner.query(`
      ALTER TABLE tokens 
      ADD CONSTRAINT CHK_tokens_revoked_at 
      CHECK (revoked_at IS NULL OR revoked_at >= created_at)
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop constraints first
    await queryRunner.query('ALTER TABLE tokens DROP CONSTRAINT IF EXISTS CHK_tokens_revoked_at');
    await queryRunner.query('ALTER TABLE tokens DROP CONSTRAINT IF EXISTS CHK_tokens_expires_at');
    await queryRunner.query('ALTER TABLE tokens DROP CONSTRAINT IF EXISTS CHK_tokens_type');

    // Drop foreign key
    await queryRunner.dropForeignKey('tokens', 'FK_tokens_user_id');

    // Drop the table
    await queryRunner.dropTable('tokens');
  }
}