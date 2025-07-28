import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

/**
 * User TypeORM Database Entity
 * 
 * Represents user data in the database with proper indexes and constraints.
 * Maps to the domain User entity for persistence operations.
 */
@Entity('users')
@Index(['email'], { unique: true })
@Index(['provider', 'provider_id'], { unique: true })
@Index(['status'])
@Index(['created_at'])
export class UserEntity {
  @PrimaryColumn('varchar', { length: 255 })
  id: string;

  @Column('varchar', { length: 255, unique: true })
  email: string;

  @Column('varchar', { length: 255, nullable: true })
  password?: string;

  @Column('varchar', { length: 100 })
  name: string;

  @Column('text', { nullable: true })
  profile_picture?: string;

  @Column('varchar', { length: 50, default: 'local' })
  provider: string;

  @Column('varchar', { length: 255, nullable: true })
  provider_id?: string;

  @Column('boolean', { default: false })
  email_verified: boolean;

  @Column('varchar', { length: 20, default: 'active' })
  status: string;

  @Column('timestamp', { nullable: true })
  last_login_at?: Date;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;
}