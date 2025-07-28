import { ClientInfo } from '@auth/shared';

/**
 * AuthSession Entity - Core business entity
 * 
 * This entity represents an authentication session with its business logic.
 * It handles session validation, expiration, and client information tracking.
 */
export class AuthSession {
  private isActive: boolean;
  private readonly createdAt: Date;
  private lastActivityAt: Date;

  constructor(
    public readonly id: string,
    public readonly userId: string,
    public readonly sessionToken: string,
    public readonly clientInfo: ClientInfo,
    public readonly expiresAt: Date,
    isActive: boolean = true,
    createdAt?: Date,
    lastActivityAt?: Date
  ) {
    this.isActive = isActive;
    this.createdAt = createdAt || new Date();
    this.lastActivityAt = lastActivityAt || new Date();
    
    this.validateExpiration();
  }

  /**
   * Factory method to create a new session
   */
  static create(params: {
    id: string;
    userId: string;
    sessionToken: string;
    clientInfo: ClientInfo;
    expirationHours?: number;
  }): AuthSession {
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + (params.expirationHours || 24));
    
    return new AuthSession(
      params.id,
      params.userId,
      params.sessionToken,
      params.clientInfo,
      expiresAt
    );
  }

  /**
   * Check if session is expired
   */
  public isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  /**
   * Check if session is valid (active and not expired)
   */
  public isValid(): boolean {
    return this.isActive && !this.isExpired();
  }

  /**
   * Invalidate the session
   */
  public invalidate(): void {
    if (!this.isActive) {
      throw new Error('Session is already inactive');
    }
    this.isActive = false;
  }

  /**
   * Update last activity timestamp
   */
  public updateActivity(): void {
    if (!this.isActive) {
      throw new Error('Cannot update activity on inactive session');
    }
    
    if (this.isExpired()) {
      throw new Error('Cannot update activity on expired session');
    }
    
    this.lastActivityAt = new Date();
  }

  /**
   * Extend session expiration (sliding session)
   */
  public extendSession(additionalHours: number): void {
    if (!this.isActive) {
      throw new Error('Cannot extend inactive session');
    }
    
    if (this.isExpired()) {
      throw new Error('Cannot extend expired session');
    }
    
    const newExpiresAt = new Date(this.expiresAt);
    newExpiresAt.setHours(newExpiresAt.getHours() + additionalHours);
    
    // Type assertion to make expiresAt mutable for this update
    (this as any).expiresAt = newExpiresAt;
    this.updateActivity();
  }

  /**
   * Check if session has been idle for too long
   */
  public isIdle(maxIdleMinutes: number = 30): boolean {
    const now = new Date();
    const idleTime = now.getTime() - this.lastActivityAt.getTime();
    const maxIdleTime = maxIdleMinutes * 60 * 1000; // Convert to milliseconds
    
    return idleTime > maxIdleTime;
  }

  /**
   * Get session status
   */
  public getStatus(): string {
    if (!this.isActive) {
      return 'inactive';
    }
    
    if (this.isExpired()) {
      return 'expired';
    }
    
    if (this.isIdle()) {
      return 'idle';
    }
    
    return 'active';
  }

  /**
   * Get time until expiration in milliseconds
   */
  public getTimeUntilExpiration(): number {
    const now = new Date();
    return this.expiresAt.getTime() - now.getTime();
  }

  /**
   * Get time since last activity in milliseconds
   */
  public getTimeSinceLastActivity(): number {
    const now = new Date();
    return now.getTime() - this.lastActivityAt.getTime();
  }

  /**
   * Check if session belongs to a specific device
   */
  public isFromDevice(deviceId: string): boolean {
    return this.clientInfo.deviceId === deviceId;
  }

  /**
   * Check if session is from a specific IP address
   */
  public isFromIpAddress(ipAddress: string): boolean {
    return this.clientInfo.ipAddress === ipAddress;
  }

  /**
   * Get creation date
   */
  public getCreatedAt(): Date {
    return this.createdAt;
  }

  /**
   * Get last activity date
   */
  public getLastActivityAt(): Date {
    return this.lastActivityAt;
  }

  /**
   * Get active status
   */
  public getActiveStatus(): boolean {
    return this.isActive;
  }

  /**
   * Validate that expiration date is in the future
   */
  private validateExpiration(): void {
    if (this.expiresAt <= new Date()) {
      throw new Error('Session expiration date must be in the future');
    }
  }

  /**
   * Convert to plain object (for serialization)
   */
  public toObject(): Record<string, any> {
    return {
      id: this.id,
      userId: this.userId,
      sessionToken: this.sessionToken,
      clientInfo: this.clientInfo,
      expiresAt: this.expiresAt,
      isActive: this.isActive,
      createdAt: this.createdAt,
      lastActivityAt: this.lastActivityAt,
      status: this.getStatus(),
      isValid: this.isValid(),
    };
  }

  /**
   * Convert to safe object (without sensitive data)
   */
  public toSafeObject(): Record<string, any> {
    return {
      id: this.id,
      clientInfo: {
        platform: this.clientInfo.platform,
        deviceId: this.clientInfo.deviceId,
      },
      expiresAt: this.expiresAt,
      createdAt: this.createdAt,
      lastActivityAt: this.lastActivityAt,
      status: this.getStatus(),
    };
  }
}