import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService as NestJwtService } from '@nestjs/jwt';
import * as crypto from 'node:crypto';
import { JwtPayload, jwtConfig, RefreshTokenPayload } from '@config/jwt.config';
import { InvalidRefreshTokenException } from '@/auth/domain';

/**
 * JWT 애플리케이션 서비스
 * JWT 토큰 생성, 검증, 갱신 등을 담당
 */
@Injectable()
export class JwtApplicationService {
	@Inject(jwtConfig.KEY)
	private readonly jwtConfiguration: ConfigType<typeof jwtConfig>;

  constructor(
    private readonly jwtService: NestJwtService,
  ) {}

  /**
   * Access Token 생성
   */
  async generateAccessToken(userId: string, email: string): Promise<string> {
    const payload: JwtPayload = {
      sub: userId,
      email,
      type: 'access',
    };

    return this.jwtService.signAsync(payload, {
      secret: this.jwtConfiguration.accessToken.secret,
      expiresIn: this.jwtConfiguration.accessToken.expiresIn,
      issuer: 'auth-vC',
      audience: 'auth-vC-client',
    });
  }

  /**
   * Refresh Token 생성
   */
  async generateRefreshToken(userId: string): Promise<string> {
    const tokenId = crypto.randomUUID();
    const payload: RefreshTokenPayload = {
      sub: userId,
      tokenId,
      type: 'refresh',
    };

    return this.jwtService.signAsync(payload, {
      secret: this.jwtConfiguration.refreshToken.secret,
      expiresIn: this.jwtConfiguration.refreshToken.expiresIn,
      issuer: 'auth-vC',
      audience: 'auth-vC-client',
    });
  }

  /**
   * Access Token과 Refresh Token 한번에 생성
   */
  async generateTokenPair(userId: string, email: string): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    const [accessToken, refreshToken] = await Promise.all([
      this.generateAccessToken(userId, email),
      this.generateRefreshToken(userId),
    ]);

    return {
      accessToken,
      refreshToken,
      expiresIn: this.getAccessTokenExpiresIn(),
    };
  }

  /**
   * Access Token 검증
   */
  async verifyAccessToken(token: string): Promise<JwtPayload> {
    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: this.jwtConfiguration.accessToken.secret,
        issuer: 'auth-vC',
        audience: 'auth-vC-client',
      });

      if (payload.type !== 'access') {
        throw new InvalidRefreshTokenException('유효하지 않은 토큰 타입입니다.');
      }

      return payload;
    } catch (error) {
      throw new InvalidRefreshTokenException('Access Token이 유효하지 않습니다.');
    }
  }

  /**
   * Refresh Token 검증
   */
  async verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    try {
      const payload = await this.jwtService.verifyAsync<RefreshTokenPayload>(token, {
        secret: this.jwtConfiguration.refreshToken.secret,
        issuer: 'auth-vC',
        audience: 'auth-vC-client',
      });

      if (payload.type !== 'refresh') {
        throw new InvalidRefreshTokenException('유효하지 않은 토큰 타입입니다.');
      }

      return payload;
    } catch (error) {
      throw new InvalidRefreshTokenException('Refresh Token이 유효하지 않습니다.');
    }
  }

  /**
   * 토큰에서 사용자 ID 추출 (검증 없이)
   */
  extractUserIdFromToken(token: string): string | null {
    try {
      const decoded = this.jwtService.decode(token) as JwtPayload;
      return decoded?.sub || null;
    } catch {
      return null;
    }
  }

  /**
   * 토큰 만료 시간 확인
   */
  isTokenExpired(token: string): boolean {
    try {
      const decoded = this.jwtService.decode(token) as any;
      if (!decoded || !decoded.exp) {
        return true;
      }

      const currentTime = Math.floor(Date.now() / 1000);
      return decoded.exp < currentTime;
    } catch {
      return true;
    }
  }

  /**
   * Access Token TTL (초 단위) 반환
   */
  getAccessTokenExpiresIn(): number {
    const ttl = this.jwtConfiguration.accessToken.expiresIn;

    // TTL이 문자열인 경우 파싱 (예: "1h" -> 3600)
    if (typeof ttl === 'string') {
      return this.parseTtlToSeconds(ttl);
    }

    return ttl;
  }

  /**
   * Refresh Token TTL (초 단위) 반환
   */
  getRefreshTokenExpiresIn(): number {
    const ttl = this.jwtConfiguration.refreshToken.expiresIn;

    if (typeof ttl === 'string') {
      return this.parseTtlToSeconds(ttl);
    }

    return ttl;
  }

  /**
   * TTL 문자열을 초 단위로 변환
   */
  private parseTtlToSeconds(ttl: string): number {
    const units: Record<string, number> = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400,
    };

    const match = ttl.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error(`Invalid TTL format: ${ttl}`);
    }

    const [, value, unit] = match;
    return parseInt(value, 10) * units[unit];
  }

  /**
   * 토큰 만료까지 남은 시간 (초) 계산
   */
  getTokenRemainingTime(token: string): number {
    try {
      const decoded = this.jwtService.decode(token) as any;
      if (!decoded || !decoded.exp) {
        return 0;
      }

      const currentTime = Math.floor(Date.now() / 1000);
      const remainingTime = decoded.exp - currentTime;

      return Math.max(0, remainingTime);
    } catch {
      return 0;
    }
  }

  /**
   * 토큰이 곧 만료되는지 확인 (임계값: 5분)
   */
  isTokenExpiringSoon(token: string, thresholdMinutes: number = 5): boolean {
    const remainingTime = this.getTokenRemainingTime(token);
    return remainingTime <= (thresholdMinutes * 60);
  }
}


