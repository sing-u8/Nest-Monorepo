import { Injectable, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { TokenService, TokenPayload } from '../../domain/ports/token.service';
import { Token } from '../../domain/entities/token.entity';
import { TokenType } from '@auth/shared/types/auth.types';

@Injectable()
export class JwtTokenServiceImpl implements TokenService {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(ConfigService)
    private readonly configService: ConfigService,
  ) {}

  async generateToken(payload: TokenPayload, expiresIn?: string | number): Promise<string> {
    try {
      const jwtPayload = {
        sub: payload.userId,
        email: payload.email,
        type: payload.type,
        sessionId: payload.sessionId,
        iat: Math.floor(Date.now() / 1000),
        ...payload, // Include any additional properties
      };

      const options: any = {};

      if (expiresIn) {
        options.expiresIn = expiresIn;
      } else {
        // Set default expiration based on token type
        options.expiresIn = payload.type === TokenType.ACCESS ? '15m' : '7d';
      }

      // Use different secrets for different token types for enhanced security
      if (payload.type === TokenType.REFRESH) {
        options.secret = this.configService.get<string>('auth.jwt.refreshTokenSecret');
      } else {
        options.secret = this.configService.get<string>('auth.jwt.accessTokenSecret');
      }

      return await this.jwtService.signAsync(jwtPayload, options);
    } catch (error) {
      throw new Error(`Failed to generate JWT token: ${error.message}`);
    }
  }

  async generateTokenPair(payload: TokenPayload): Promise<{ accessToken: Token; refreshToken: Token }> {
    try {
      // Generate access token (15 minutes)
      const accessTokenValue = await this.generateToken(
        { ...payload, type: TokenType.ACCESS },
        this.configService.get<string>('auth.jwt.accessTokenExpiresIn', '15m')
      );

      // Generate refresh token (7 days)
      const refreshTokenValue = await this.generateToken(
        { ...payload, type: TokenType.REFRESH },
        this.configService.get<string>('auth.jwt.refreshTokenExpiresIn', '7d')
      );

      // Create access token entity
      const accessToken = new Token(
        this.generateTokenId(),
        payload.userId,
        TokenType.ACCESS,
        accessTokenValue,
        new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      );

      // Create refresh token entity
      const refreshToken = new Token(
        this.generateTokenId(),
        payload.userId,
        TokenType.REFRESH,
        refreshTokenValue,
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      );

      return { accessToken, refreshToken };
    } catch (error) {
      throw new Error(`Failed to generate token pair: ${error.message}`);
    }
  }

  async verifyToken(token: string, tokenType: TokenType): Promise<TokenPayload | null> {
    try {
      const secret = tokenType === TokenType.REFRESH
        ? this.configService.get<string>('auth.jwt.refreshTokenSecret')
        : this.configService.get<string>('auth.jwt.accessTokenSecret');

      const decoded = await this.jwtService.verifyAsync(token, { secret });
      
      // Validate token type matches expected type
      if (decoded.type !== tokenType) {
        return null;
      }

      return {
        userId: decoded.sub,
        email: decoded.email,
        type: decoded.type,
        sessionId: decoded.sessionId,
        iat: decoded.iat,
        exp: decoded.exp,
        ...decoded, // Include any additional properties
      };
    } catch (error) {
      // Token verification failed (expired, invalid signature, etc.)
      return null;
    }
  }

  async decodeToken(token: string): Promise<any> {
    try {
      return this.jwtService.decode(token);
    } catch (error) {
      throw new Error(`Failed to decode token: ${error.message}`);
    }
  }

  async revokeToken(tokenId: string): Promise<void> {
    // JWT tokens are stateless, so we can't revoke them directly
    // In practice, this would add the token to a blacklist
    // For now, we'll implement this as a no-op since the repository layer handles revocation
    
    // In a production system, you might:
    // 1. Add token to Redis blacklist
    // 2. Store revoked tokens in database
    // 3. Use shorter expiration times and refresh frequently
    
    // For this implementation, revocation is handled at the repository level
    // by marking tokens as revoked in the database
  }

  async refreshTokens(refreshToken: string): Promise<{ accessToken: Token; refreshToken: Token } | null> {
    try {
      // Verify the refresh token
      const payload = await this.verifyToken(refreshToken, TokenType.REFRESH);
      if (!payload) {
        return null;
      }

      // Generate new token pair
      return await this.generateTokenPair({
        userId: payload.userId,
        email: payload.email,
        type: TokenType.ACCESS, // This will be overridden in generateTokenPair
        sessionId: payload.sessionId,
      });
    } catch (error) {
      throw new Error(`Failed to refresh tokens: ${error.message}`);
    }
  }

  getTokenExpiration(token: string): Date | null {
    try {
      const decoded = this.jwtService.decode(token) as any;
      if (decoded && decoded.exp) {
        return new Date(decoded.exp * 1000); // Convert from Unix timestamp
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  isTokenExpired(token: string): boolean {
    const expiration = this.getTokenExpiration(token);
    if (!expiration) {
      return true; // If we can't determine expiration, consider it expired
    }
    return expiration <= new Date();
  }

  getTokenRemainingTime(token: string): number {
    const expiration = this.getTokenExpiration(token);
    if (!expiration) {
      return 0;
    }
    const remaining = expiration.getTime() - Date.now();
    return Math.max(0, remaining);
  }

  validateTokenFormat(token: string): boolean {
    if (!token || typeof token !== 'string') {
      return false;
    }

    // JWT tokens have three parts separated by dots
    const parts = token.split('.');
    if (parts.length !== 3) {
      return false;
    }

    // Each part should be base64 encoded (with URL-safe characters)
    const base64UrlRegex = /^[A-Za-z0-9_-]+$/;
    return parts.every(part => base64UrlRegex.test(part));
  }

  extractTokenPayload(token: string): TokenPayload | null {
    try {
      const decoded = this.jwtService.decode(token) as any;
      if (!decoded) {
        return null;
      }

      return {
        userId: decoded.sub,
        email: decoded.email,
        type: decoded.type,
        sessionId: decoded.sessionId,
        iat: decoded.iat,
        exp: decoded.exp,
      };
    } catch (error) {
      return null;
    }
  }

  private generateTokenId(): string {
    return `token_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private parseExpirationTime(expiresIn: string | number): number {
    if (typeof expiresIn === 'number') {
      return expiresIn * 1000; // Convert seconds to milliseconds
    }

    if (typeof expiresIn === 'string') {
      const timeMap: { [key: string]: number } = {
        's': 1000,
        'm': 60 * 1000,
        'h': 60 * 60 * 1000,
        'd': 24 * 60 * 60 * 1000,
      };

      const match = expiresIn.match(/^(\d+)([smhd])$/);
      if (match) {
        const value = parseInt(match[1]);
        const unit = match[2];
        return value * timeMap[unit];
      }
    }

    throw new Error(`Invalid expiration time format: ${expiresIn}`);
  }
}