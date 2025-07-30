import { TokenType } from '@auth/shared/types/auth.types';

export class Token {
  constructor(
    public readonly id: string,
    public readonly userId: string,
    public readonly type: TokenType,
    public readonly value: string,
    public readonly expiresAt: Date,
    private isRevoked: boolean = false,
    private readonly createdAt: Date = new Date()
  ) {
    this.validateToken();
  }

  private validateToken(): void {
    if (!this.id || this.id.trim().length === 0) {
      throw new Error('Token ID is required');
    }
    
    if (!this.userId || this.userId.trim().length === 0) {
      throw new Error('User ID is required');
    }
    
    if (!this.value || this.value.trim().length === 0) {
      throw new Error('Token value is required');
    }
    
    if (!Object.values(TokenType).includes(this.type)) {
      throw new Error('Invalid token type');
    }
    
    if (!(this.expiresAt instanceof Date) || isNaN(this.expiresAt.getTime())) {
      throw new Error('Invalid expiration date');
    }
    
    if (this.expiresAt <= new Date()) {
      throw new Error('Token expiration date must be in the future');
    }
  }

  public isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  public revoke(): void {
    if (this.isRevoked) {
      throw new Error('Token is already revoked');
    }
    this.isRevoked = true;
  }

  public isValid(): boolean {
    return !this.isRevoked && !this.isExpired();
  }

  public getIsRevoked(): boolean {
    return this.isRevoked;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getRemainingTime(): number {
    if (!this.isValid()) {
      return 0;
    }
    return this.expiresAt.getTime() - new Date().getTime();
  }

  public toJSON(): Record<string, any> {
    return {
      id: this.id,
      userId: this.userId,
      type: this.type,
      value: this.value,
      expiresAt: this.expiresAt,
      isRevoked: this.isRevoked,
      createdAt: this.createdAt,
      isValid: this.isValid(),
      remainingTime: this.getRemainingTime(),
    };
  }
}