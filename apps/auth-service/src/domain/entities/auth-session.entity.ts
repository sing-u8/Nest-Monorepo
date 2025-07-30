import { ClientInfo } from '@auth/shared/types/auth.types';

export class AuthSession {
  constructor(
    public readonly id: string,
    public readonly userId: string,
    public readonly sessionToken: string,
    public readonly expiresAt: Date,
    public readonly clientInfo?: ClientInfo,
    private isRevoked: boolean = false,
    private readonly createdAt: Date = new Date(),
    private lastActivityAt: Date = new Date()
  ) {
    this.validateSession();
  }

  private validateSession(): void {
    if (!this.id || this.id.trim().length === 0) {
      throw new Error('Session ID is required');
    }
    
    if (!this.userId || this.userId.trim().length === 0) {
      throw new Error('User ID is required');
    }
    
    if (!this.sessionToken || this.sessionToken.trim().length === 0) {
      throw new Error('Session token is required');
    }
    
    if (!(this.expiresAt instanceof Date) || isNaN(this.expiresAt.getTime())) {
      throw new Error('Invalid expiration date');
    }
    
    if (this.expiresAt <= new Date()) {
      throw new Error('Session expiration date must be in the future');
    }
  }

  public isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  public revoke(): void {
    if (this.isRevoked) {
      throw new Error('Session is already revoked');
    }
    this.isRevoked = true;
  }

  public isValid(): boolean {
    return !this.isRevoked && !this.isExpired();
  }

  public updateActivity(): void {
    if (!this.isValid()) {
      throw new Error('Cannot update activity on invalid session');
    }
    this.lastActivityAt = new Date();
  }

  public getIsRevoked(): boolean {
    return this.isRevoked;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getLastActivityAt(): Date {
    return this.lastActivityAt;
  }

  public getRemainingTime(): number {
    if (!this.isValid()) {
      return 0;
    }
    return this.expiresAt.getTime() - new Date().getTime();
  }

  public getIdleTime(): number {
    return new Date().getTime() - this.lastActivityAt.getTime();
  }

  public shouldExpireForInactivity(maxIdleTimeMs: number): boolean {
    return this.getIdleTime() > maxIdleTimeMs;
  }

  public toJSON(): Record<string, any> {
    return {
      id: this.id,
      userId: this.userId,
      sessionToken: this.sessionToken,
      clientInfo: this.clientInfo,
      expiresAt: this.expiresAt,
      isRevoked: this.isRevoked,
      createdAt: this.createdAt,
      lastActivityAt: this.lastActivityAt,
      isValid: this.isValid(),
      remainingTime: this.getRemainingTime(),
      idleTime: this.getIdleTime(),
    };
  }
}