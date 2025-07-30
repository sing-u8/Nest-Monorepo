import { Entity, PrimaryColumn, Column, CreateDateColumn, UpdateDateColumn, Index } from 'typeorm';
import { AuthProvider } from '@auth/shared/types/auth.types';

@Entity('users')
@Index(['email'], { unique: true })
@Index(['provider', 'providerId'], { unique: true })
export class UserOrmEntity {
  @PrimaryColumn('varchar', { length: 255 })
  id: string;

  @Column('varchar', { length: 255, unique: true })
  email: string;

  @Column('varchar', { length: 255, nullable: true, name: 'password_hash' })
  passwordHash: string | null;

  @Column('varchar', { length: 255 })
  name: string;

  @Column('text', { nullable: true, name: 'profile_picture' })
  profilePicture: string | null;

  @Column('varchar', { length: 50, default: AuthProvider.LOCAL })
  provider: AuthProvider;

  @Column('varchar', { length: 255, nullable: true, name: 'provider_id' })
  providerId: string | null;

  @Column('boolean', { default: true, name: 'is_active' })
  isActive: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}