import { Injectable, Inject } from '@nestjs/common';
import { User } from '../entities/user.entity';
import { Token } from '../entities/token.entity';
import { AuthSession } from '../entities/auth-session.entity';
import { UserRepository } from '../ports/user.repository';
import { TokenRepository } from '../ports/token.repository';
import { AuthSessionRepository } from '../ports/auth-session.repository';
import { PasswordHashingService } from '../ports/password-hashing.service';
import { TokenService, TokenPayload } from '../ports/token.service';
import { LoginUserRequest, LoginUserResponse } from '../models/auth.models';
import { TokenType } from '@auth/shared/types/auth.types';

export class InvalidCredentialsError extends Error {
  constructor() {
    super('Invalid email or password');
    this.name = 'InvalidCredentialsError';
  }
}

export class UserNotActiveError extends Error {
  constructor() {
    super('User account is not active');
    this.name = 'UserNotActiveError';
  }
}

export class AccountLockedError extends Error {
  constructor(lockDuration: number) {
    super(`Account is temporarily locked. Try again in ${lockDuration} minutes.`);
    this.name = 'AccountLockedError';
  }
}

@Injectable()
export class LoginUserUseCase {
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes
  private readonly ACCESS_TOKEN_EXPIRES_IN = '15m';
  private readonly REFRESH_TOKEN_EXPIRES_IN = '7d';
  private readonly SESSION_EXPIRES_IN_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

  constructor(
    @Inject('UserRepository')
    private readonly userRepository: UserRepository,
    @Inject('TokenRepository')
    private readonly tokenRepository: TokenRepository,
    @Inject('AuthSessionRepository')
    private readonly authSessionRepository: AuthSessionRepository,
    @Inject('PasswordHashingService')
    private readonly passwordHashingService: PasswordHashingService,
    @Inject('TokenService')
    private readonly tokenService: TokenService,
  ) {}

  async execute(request: LoginUserRequest): Promise<LoginUserResponse> {
    // Validate input
    this.validateRequest(request);

    // Find user by email
    const user = await this.userRepository.findByEmail(request.email);
    if (!user) {
      throw new InvalidCredentialsError();
    }

    // Check if user is active
    if (!user.isAccountActive()) {
      throw new UserNotActiveError();
    }

    // Validate password
    const isPasswordValid = await this.passwordHashingService.compare(
      request.password,
      user.getPassword()
    );

    if (!isPasswordValid) {
      throw new InvalidCredentialsError();
    }

    // Generate session ID and tokens
    const sessionId = this.generateSessionId();
    const tokenPayload: TokenPayload = {
      userId: user.id,
      email: user.email,
      type: TokenType.ACCESS,
      sessionId,
    };

    // Generate token pair
    const { accessToken, refreshToken } = await this.tokenService.generateTokenPair(tokenPayload);

    // Create session
    const sessionExpiresAt = new Date(Date.now() + this.SESSION_EXPIRES_IN_MS);
    const authSession = new AuthSession(
      sessionId,
      user.id,
      this.generateSessionToken(),
      sessionExpiresAt,
      request.clientInfo
    );

    // Create token entities
    const accessTokenEntity = new Token(
      this.generateTokenId(),
      user.id,
      TokenType.ACCESS,
      accessToken,
      new Date(Date.now() + 15 * 60 * 1000) // 15 minutes
    );

    const refreshTokenEntity = new Token(
      this.generateTokenId(),
      user.id,
      TokenType.REFRESH,
      refreshToken,
      new Date(Date.now() + this.SESSION_EXPIRES_IN_MS) // 7 days
    );

    // Revoke any existing active tokens for this user
    await this.tokenRepository.revokeAllByUserId(user.id);

    // Save session and tokens
    await Promise.all([
      this.authSessionRepository.save(authSession),
      this.tokenRepository.save(accessTokenEntity),
      this.tokenRepository.save(refreshTokenEntity),
    ]);

    // Return response
    return {
      accessToken,
      refreshToken,
      sessionId,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        profilePicture: user.profilePicture,
        isActive: user.isAccountActive(),
      },
      expiresAt: accessTokenEntity.expiresAt,
    };
  }

  private validateRequest(request: LoginUserRequest): void {
    if (!request.email || request.email.trim().length === 0) {
      throw new Error('Email is required');
    }

    if (!request.password || request.password.trim().length === 0) {
      throw new Error('Password is required');
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(request.email)) {
      throw new Error('Invalid email format');
    }
  }

  private generateSessionId(): string {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateTokenId(): string {
    return `token_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateSessionToken(): string {
    return `sess_${Date.now()}_${Math.random().toString(36).substr(2, 16)}`;
  }
}