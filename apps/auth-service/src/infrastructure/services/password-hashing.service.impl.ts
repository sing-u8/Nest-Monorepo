import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PasswordHashingService } from '../../domain/ports/password-hashing.service';

@Injectable()
export class PasswordHashingServiceImpl implements PasswordHashingService {
  private readonly saltRounds: number;
  private readonly passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  constructor(
    @Inject(ConfigService)
    private readonly configService: ConfigService,
  ) {
    this.saltRounds = this.configService.get<number>('auth.bcrypt.saltRounds', 12);
  }

  async hash(password: string): Promise<string> {
    if (!password || typeof password !== 'string') {
      throw new Error('Password must be a non-empty string');
    }

    if (!this.isValidPasswordFormat(password)) {
      throw new Error('Password does not meet security requirements');
    }

    try {
      const salt = await bcrypt.genSalt(this.saltRounds);
      return await bcrypt.hash(password, salt);
    } catch (error) {
      throw new Error(`Failed to hash password: ${error.message}`);
    }
  }

  async compare(password: string, hashedPassword: string): Promise<boolean> {
    if (!password || !hashedPassword) {
      return false;
    }

    if (typeof password !== 'string' || typeof hashedPassword !== 'string') {
      return false;
    }

    try {
      return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
      // Log error but don't expose internal details
      console.error('Password comparison error:', error);
      return false;
    }
  }

  isValidPasswordFormat(password: string): boolean {
    if (!password || typeof password !== 'string') {
      return false;
    }

    // Minimum 8 characters
    if (password.length < 8) {
      return false;
    }

    // Maximum 128 characters (reasonable limit to prevent DoS)
    if (password.length > 128) {
      return false;
    }

    // Must contain at least one lowercase letter, one uppercase letter, one digit, and one special character
    return this.passwordRegex.test(password);
  }

  async generateSalt(rounds?: number): Promise<string> {
    const saltRounds = rounds || this.saltRounds;
    
    if (saltRounds < 10 || saltRounds > 15) {
      throw new Error('Salt rounds must be between 10 and 15 for security');
    }

    try {
      return await bcrypt.genSalt(saltRounds);
    } catch (error) {
      throw new Error(`Failed to generate salt: ${error.message}`);
    }
  }

  validateHashedPassword(hashedPassword: string): boolean {
    if (!hashedPassword || typeof hashedPassword !== 'string') {
      return false;
    }

    // Basic bcrypt hash format validation
    // Bcrypt hashes start with $2a$, $2b$ or $2y$ followed by cost and salt
    const bcryptRegex = /^\$2[abyxz]\$[0-9]{2}\$[A-Za-z0-9./]{53}$/;
    return bcryptRegex.test(hashedPassword);
  }

  getPasswordRequirements(): string {
    return 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character';
  }

  getSaltRounds(): number {
    return this.saltRounds;
  }

  async rehashIfNeeded(password: string, currentHash: string, targetRounds?: number): Promise<string | null> {
    const target = targetRounds || this.saltRounds;
    
    try {
      // Extract current rounds from hash
      const roundsMatch = currentHash.match(/^\$2[abyxz]\$([0-9]{2})\$/);
      if (!roundsMatch) {
        // Invalid hash format, needs rehashing
        return await this.hash(password);
      }

      const currentRounds = parseInt(roundsMatch[1]);
      
      // Rehash if current rounds are lower than target
      if (currentRounds < target) {
        return await this.hash(password);
      }

      return null; // No rehashing needed
    } catch (error) {
      throw new Error(`Failed to check if rehashing is needed: ${error.message}`);
    }
  }

  isPasswordCompromised(password: string): boolean {
    // Common weak passwords list (in production, this could be a more comprehensive check)
    const commonWeakPasswords = [
      'password',
      'password123',
      '123456789',
      'qwerty123',
      'admin123',
      'letmein',
      'welcome123',
    ];

    const lowerPassword = password.toLowerCase();
    return commonWeakPasswords.some(weak => lowerPassword.includes(weak));
  }

  generatePasswordStrengthScore(password: string): number {
    if (!password) return 0;

    let score = 0;
    
    // Length scoring
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;

    // Character variety scoring
    if (/[a-z]/.test(password)) score += 1; // lowercase
    if (/[A-Z]/.test(password)) score += 1; // uppercase
    if (/\d/.test(password)) score += 1;    // numbers
    if (/[@$!%*?&]/.test(password)) score += 1; // special chars

    // Complexity patterns
    if (/(.)\1{2,}/.test(password)) score -= 1; // repeated characters
    if (this.isPasswordCompromised(password)) score -= 2; // common weak passwords

    return Math.max(0, Math.min(8, score)); // Score between 0-8
  }
}