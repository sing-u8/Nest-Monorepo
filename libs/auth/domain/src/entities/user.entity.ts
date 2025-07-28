import { AuthProvider, UserStatus, DEFAULT_PASSWORD_RULES, PasswordRules } from '@auth/shared';

/**
 * User Entity - Core business entity
 * 
 * This entity represents the core user model with business logic.
 * It follows Domain-Driven Design principles and encapsulates
 * all user-related business rules and behaviors.
 */
export class User {
  constructor(
    public readonly id: string,
    public readonly email: string,
    private password: string,
    public readonly name: string,
    public readonly profilePicture?: string,
    public readonly provider: AuthProvider = AuthProvider.LOCAL,
    public readonly providerId?: string,
    private status: UserStatus = UserStatus.ACTIVE,
    private readonly createdAt: Date = new Date(),
    private updatedAt: Date = new Date()
  ) {
    this.validateEmail(email);
    if (provider === AuthProvider.LOCAL) {
      this.validatePasswordStrength(password);
    }
  }

  /**
   * Factory method to create a new user
   */
  static create(params: {
    id: string;
    email: string;
    password: string;
    name: string;
    profilePicture?: string;
    provider?: AuthProvider;
    providerId?: string;
  }): User {
    return new User(
      params.id,
      params.email,
      params.password,
      params.name,
      params.profilePicture,
      params.provider,
      params.providerId
    );
  }

  /**
   * Factory method to create a social login user
   */
  static createFromSocialProvider(params: {
    id: string;
    email: string;
    name: string;
    provider: AuthProvider;
    providerId: string;
    profilePicture?: string;
  }): User {
    return new User(
      params.id,
      params.email,
      '', // No password for social login
      params.name,
      params.profilePicture,
      params.provider,
      params.providerId
    );
  }

  /**
   * Validate password against hashed password
   * This method should be used with a proper hashing service
   */
  public validatePassword(plainPassword: string): boolean {
    // In a real implementation, this would use bcrypt or similar
    // For now, we're just doing a simple comparison
    // The infrastructure layer will handle actual password hashing
    return this.password === plainPassword;
  }

  /**
   * Update user password
   */
  public updatePassword(newPassword: string): void {
    if (this.provider !== AuthProvider.LOCAL) {
      throw new Error('Cannot update password for non-local authentication provider');
    }
    
    this.validatePasswordStrength(newPassword);
    this.password = newPassword;
    this.updatedAt = new Date();
  }

  /**
   * Update user profile information
   */
  public updateProfile(name: string, profilePicture?: string): void {
    if (!name || name.trim().length === 0) {
      throw new Error('Name cannot be empty');
    }
    
    // Type assertion to make name mutable for this update
    (this as any).name = name.trim();
    
    if (profilePicture !== undefined) {
      (this as any).profilePicture = profilePicture;
    }
    
    this.updatedAt = new Date();
  }

  /**
   * Deactivate user account
   */
  public deactivate(): void {
    if (this.status === UserStatus.DELETED) {
      throw new Error('Cannot deactivate deleted account');
    }
    this.status = UserStatus.INACTIVE;
    this.updatedAt = new Date();
  }

  /**
   * Activate user account
   */
  public activate(): void {
    if (this.status === UserStatus.DELETED) {
      throw new Error('Cannot activate deleted account');
    }
    if (this.status === UserStatus.SUSPENDED) {
      throw new Error('Cannot activate suspended account without admin intervention');
    }
    this.status = UserStatus.ACTIVE;
    this.updatedAt = new Date();
  }

  /**
   * Suspend user account (typically by admin)
   */
  public suspend(): void {
    if (this.status === UserStatus.DELETED) {
      throw new Error('Cannot suspend deleted account');
    }
    this.status = UserStatus.SUSPENDED;
    this.updatedAt = new Date();
  }

  /**
   * Soft delete user account
   */
  public softDelete(): void {
    this.status = UserStatus.DELETED;
    this.updatedAt = new Date();
  }

  /**
   * Check if account is active
   */
  public isAccountActive(): boolean {
    return this.status === UserStatus.ACTIVE;
  }

  /**
   * Get account status
   */
  public getStatus(): UserStatus {
    return this.status;
  }

  /**
   * Get password (for infrastructure layer only)
   */
  public getPassword(): string {
    return this.password;
  }

  /**
   * Get creation date
   */
  public getCreatedAt(): Date {
    return this.createdAt;
  }

  /**
   * Get last update date
   */
  public getUpdatedAt(): Date {
    return this.updatedAt;
  }

  /**
   * Validate email format
   */
  private validateEmail(email: string): void {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new Error('Invalid email format');
    }
  }

  /**
   * Validate password strength
   */
  private validatePasswordStrength(password: string, rules: PasswordRules = DEFAULT_PASSWORD_RULES): void {
    if (password.length < rules.minLength) {
      throw new Error(`Password must be at least ${rules.minLength} characters long`);
    }

    if (rules.requireUppercase && !/[A-Z]/.test(password)) {
      throw new Error('Password must contain at least one uppercase letter');
    }

    if (rules.requireLowercase && !/[a-z]/.test(password)) {
      throw new Error('Password must contain at least one lowercase letter');
    }

    if (rules.requireNumbers && !/\d/.test(password)) {
      throw new Error('Password must contain at least one number');
    }

    if (rules.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      throw new Error('Password must contain at least one special character');
    }
  }

  /**
   * Convert to plain object (for serialization)
   */
  public toObject(): Record<string, any> {
    return {
      id: this.id,
      email: this.email,
      name: this.name,
      profilePicture: this.profilePicture,
      provider: this.provider,
      providerId: this.providerId,
      status: this.status,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    };
  }
}