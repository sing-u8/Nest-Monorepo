import { Token } from '../entities/token.entity';
import { TokenType } from '@auth/shared/types/auth.types';

export interface TokenRepository {
  save(token: Token): Promise<Token>;
  findByValue(value: string): Promise<Token | null>;
  findByUserId(userId: string, type?: TokenType): Promise<Token[]>;
  findByUserIdAndType(userId: string, type: TokenType): Promise<Token | null>;
  revoke(tokenValue: string): Promise<void>;
  revokeAllByUserId(userId: string, type?: TokenType): Promise<void>;
  deleteExpired(): Promise<number>;
  existsByValue(value: string): Promise<boolean>;
  countActiveByUserId(userId: string, type: TokenType): Promise<number>;
}