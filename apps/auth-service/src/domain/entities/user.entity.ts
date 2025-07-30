import { AuthProvider } from '@auth/shared/types/auth.types';

export class User {
  constructor(
    public readonly id: string,
    public readonly email: string,
    private password: string,
    public readonly name: string,
    public readonly profilePicture?: string,
    public readonly provider: AuthProvider = AuthProvider.LOCAL,
    public readonly providerId?: string,
    private isActive: boolean = true,
    private readonly createdAt: Date = new Date(),
    private updatedAt: Date = new Date()
  ) {
    this.validateEmail(email);
    this.validateName(name);
    if (provider === AuthProvider.LOCAL && !password) {
      throw new Error('Password is required for local authentication');
    }
  }

  private validateEmail(email: string): void {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new Error('Invalid email format');
    }
  }

  private validateName(name: string): void {
    if (!name || name.trim().length === 0) {
      throw new Error('Name cannot be empty');
    }
    if (name.length > 100) {
      throw new Error('Name cannot exceed 100 characters');
    }
  }

  public validatePassword(plainPassword: string): boolean {
    if (this.provider !== AuthProvider.LOCAL) {
      return false;
    }
    // In real implementation, this would use bcrypt.compare
    // For now, we'll just do a simple comparison
    // This will be properly implemented in the infrastructure layer
    return this.password === plainPassword;
  }

  public updatePassword(newPassword: string): void {
    if (this.provider !== AuthProvider.LOCAL) {
      throw new Error('Cannot update password for non-local authentication');
    }
    if (!newPassword || newPassword.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }
    this.password = newPassword;
    this.updatedAt = new Date();
  }

  public updateProfile(name: string, profilePicture?: string): void {
    this.validateName(name);
    // Note: Since name is readonly, we need to use Object.defineProperty
    // In a real implementation, we might use a different approach
    Object.defineProperty(this, 'name', {
      value: name,
      writable: false,
      enumerable: true,
      configurable: true
    });
    
    if (profilePicture !== undefined) {
      Object.defineProperty(this, 'profilePicture', {
        value: profilePicture,
        writable: false,
        enumerable: true,
        configurable: true
      });
    }
    
    this.updatedAt = new Date();
  }

  public deactivate(): void {
    if (!this.isActive) {
      throw new Error('User is already deactivated');
    }
    this.isActive = false;
    this.updatedAt = new Date();
  }

  public activate(): void {
    if (this.isActive) {
      throw new Error('User is already active');
    }
    this.isActive = true;
    this.updatedAt = new Date();
  }

  public isAccountActive(): boolean {
    return this.isActive;
  }

  public getPassword(): string {
    return this.password;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getUpdatedAt(): Date {
    return this.updatedAt;
  }

  public toJSON(): Record<string, any> {
    return {
      id: this.id,
      email: this.email,
      name: this.name,
      profilePicture: this.profilePicture,
      provider: this.provider,
      providerId: this.providerId,
      isActive: this.isActive,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    };
  }
}