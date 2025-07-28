import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

/**
 * Token TypeORM Database Entity
 * 
 * Represents authentication tokens in the database with proper indexes for performance.
 * Maps to the domain Token entity for persistence operations.
 */
@Entity('tokens')
@Index(['user_id'])
@Index(['type'])
@Index(['value'], { unique: true })
@Index(['expires_at'])
@Index(['revoked_at'])
@Index(['user_id', 'type'])
@Index(['expires_at', 'revoked_at']) // For cleanup queries
export class TokenEntity {
  @PrimaryColumn('varchar', { length: 255 })
  id: string;

  @Column('varchar', { length: 255 })
  user_id: string;

  @Column('varchar', { length: 50 })
  type: string;

  @Column('text')
  value: string;

  @Column('timestamp')
  expires_at: Date;

  @Column('timestamp', { nullable: true })
  revoked_at?: Date;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;
}