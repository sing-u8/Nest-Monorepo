import { TokenType } from '@auth/shared';

/**
 * Token Entity - Core business entity
 * 
 * This entity represents authentication tokens with their business logic.
 * It handles token validation, expiration, and revocation.
 */
export class Token {
  private isRevoked: boolean;
  private readonly createdAt: Date;

  constructor(
    public readonly id: string,
    public readonly userId: string,
    public readonly type: TokenType,
    public readonly value: string,
    public readonly expiresAt: Date,
    isRevoked: boolean = false,
    createdAt?: Date
  ) {
    this.isRevoked = isRevoked;
    this.createdAt = createdAt || new Date();
    
    this.validateExpiration();
  }

  /**
   * Factory method to create a new token
   */
  static create(params: {
    id: string;
    userId: string;
    type: TokenType;
    value: string;
    expiresAt: Date;
  }): Token {
    return new Token(
      params.id,
      params.userId,
      params.type,
      params.value,
      params.expiresAt
    );
  }

  /**
   * Factory method to create an access token
   */
  static createAccessToken(params: {
    id: string;
    userId: string;
    value: string;
    expirationMinutes?: number;
  }): Token {
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + (params.expirationMinutes || 15));
    
    return new Token(
      params.id,
      params.userId,
      TokenType.ACCESS,
      params.value,
      expiresAt
    );
  }

  /**
   * Factory method to create a refresh token
   */
  static createRefreshToken(params: {
    id: string;
    userId: string;
    value: string;
    expirationDays?: number;
  }): Token {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + (params.expirationDays || 7));
    
    return new Token(
      params.id,
      params.userId,
      TokenType.REFRESH,
      params.value,
      expiresAt
    );
  }

  /**
   * Check if token is expired
   */
  public isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  /**
   * Revoke the token
   */
  public revoke(): void {
    if (this.isRevoked) {
      throw new Error('Token is already revoked');
    }
    this.isRevoked = true;
  }

  /**
   * Check if token is valid (not expired and not revoked)
   */
  public isValid(): boolean {
    return !this.isExpired() && !this.isRevoked;
  }

  /**
   * Get revocation status
   */
  public getRevocationStatus(): boolean {
    return this.isRevoked;
  }

  /**
   * Get creation date
   */
  public getCreatedAt(): Date {
    return this.createdAt;
  }

  /**
   * Get time until expiration in milliseconds
   */
  public getTimeUntilExpiration(): number {
    const now = new Date();
    return this.expiresAt.getTime() - now.getTime();
  }

  /**
   * Get time until expiration in seconds
   */
  public getTimeUntilExpirationInSeconds(): number {
    return Math.floor(this.getTimeUntilExpiration() / 1000);
  }

  /**
   * Check if token will expire soon (within specified minutes)
   */
  public willExpireSoon(withinMinutes: number = 5): boolean {
    const timeUntilExpiration = this.getTimeUntilExpiration();
    const threshold = withinMinutes * 60 * 1000; // Convert to milliseconds
    
    return timeUntilExpiration > 0 && timeUntilExpiration <= threshold;
  }

  /**
   * Extend token expiration (useful for sliding sessions)
   */
  public extendExpiration(additionalMinutes: number): void {
    if (this.isRevoked) {
      throw new Error('Cannot extend expiration of revoked token');
    }
    
    if (this.isExpired()) {
      throw new Error('Cannot extend expiration of expired token');
    }
    
    const newExpiresAt = new Date(this.expiresAt);
    newExpiresAt.setMinutes(newExpiresAt.getMinutes() + additionalMinutes);
    
    // Type assertion to make expiresAt mutable for this update
    (this as any).expiresAt = newExpiresAt;
  }

  /**
   * Validate that expiration date is in the future
   */
  private validateExpiration(): void {
    if (this.expiresAt <= new Date()) {
      throw new Error('Token expiration date must be in the future');
    }
  }

  /**
   * Convert to plain object (for serialization)
   */
  public toObject(): Record<string, any> {
    return {
      id: this.id,
      userId: this.userId,
      type: this.type,
      value: this.value,
      expiresAt: this.expiresAt,
      isRevoked: this.isRevoked,
      createdAt: this.createdAt,
      isValid: this.isValid(),
      isExpired: this.isExpired(),
    };
  }

  /**
   * Convert to safe object (without sensitive data)
   */
  public toSafeObject(): Record<string, any> {
    return {
      id: this.id,
      type: this.type,
      expiresAt: this.expiresAt,
      isValid: this.isValid(),
    };
  }
}