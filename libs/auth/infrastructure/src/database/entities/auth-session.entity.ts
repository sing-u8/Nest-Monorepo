import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

/**
 * AuthSession TypeORM Database Entity
 * 
 * Represents user authentication sessions in the database with indexes for efficient queries.
 * Maps to the domain AuthSession entity for persistence operations.
 */
@Entity('auth_sessions')
@Index(['user_id'])
@Index(['session_token'], { unique: true })
@Index(['status'])
@Index(['expires_at'])
@Index(['last_activity_at'])
@Index(['ip_address'])
@Index(['device_id'])
@Index(['user_id', 'status'])
@Index(['expires_at', 'status']) // For cleanup and active session queries
export class AuthSessionEntity {
  @PrimaryColumn('varchar', { length: 255 })
  id: string;

  @Column('varchar', { length: 255 })
  user_id: string;

  @Column('text')
  session_token: string;

  @Column('varchar', { length: 20, default: 'active' })
  status: string;

  @Column('varchar', { length: 255, nullable: true })
  device_id?: string;

  @Column('varchar', { length: 100, nullable: true })
  platform?: string;

  @Column('varchar', { length: 45, nullable: true })
  ip_address?: string;

  @Column('text', { nullable: true })
  user_agent?: string;

  @Column('timestamp')
  expires_at: Date;

  @Column('timestamp')
  last_activity_at: Date;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;
}