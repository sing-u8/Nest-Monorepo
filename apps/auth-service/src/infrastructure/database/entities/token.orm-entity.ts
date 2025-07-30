import { Entity, PrimaryColumn, Column, CreateDateColumn, Index, ManyToOne, JoinColumn } from 'typeorm';
import { TokenType } from '@auth/shared/types/auth.types';
import { UserOrmEntity } from './user.orm-entity';

@Entity('tokens')
@Index(['userId'])
@Index(['type'])
@Index(['value'], { unique: true })
@Index(['expiresAt'])
@Index(['isRevoked'])
export class TokenOrmEntity {
  @PrimaryColumn('varchar', { length: 255 })
  id: string;

  @Column('varchar', { length: 255, name: 'user_id' })
  userId: string;

  @Column('varchar', { length: 50 })
  type: TokenType;

  @Column('text')
  value: string;

  @Column('timestamp', { name: 'expires_at' })
  expiresAt: Date;

  @Column('boolean', { default: false, name: 'is_revoked' })
  isRevoked: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @ManyToOne(() => UserOrmEntity, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: UserOrmEntity;
}