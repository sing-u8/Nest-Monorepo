import { Entity, PrimaryColumn, Column, CreateDateColumn, Index, ManyToOne, JoinColumn } from 'typeorm';
import { UserOrmEntity } from './user.orm-entity';
import { ClientInfo } from '@auth/shared/types/auth.types';

@Entity('auth_sessions')
@Index(['userId'])
@Index(['sessionToken'], { unique: true })
@Index(['expiresAt'])
export class AuthSessionOrmEntity {
  @PrimaryColumn('varchar', { length: 255 })
  id: string;

  @Column('varchar', { length: 255, name: 'user_id' })
  userId: string;

  @Column('varchar', { length: 255, unique: true, name: 'session_token' })
  sessionToken: string;

  @Column('jsonb', { nullable: true, name: 'client_info' })
  clientInfo: ClientInfo | null;

  @Column('timestamp', { name: 'expires_at' })
  expiresAt: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @Column('timestamp', { 
    nullable: true, 
    name: 'last_activity_at',
    default: () => 'CURRENT_TIMESTAMP'
  })
  lastActivityAt: Date | null;

  @ManyToOne(() => UserOrmEntity, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: UserOrmEntity;
}