import { Injectable } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { TokenService } from '@auth/domain';
import { TokenType, JwtPayload, TokenValidationResult } from '@auth/shared';

/**
 * JWT Token Service Implementation
 * 
 * Implements the TokenService port interface using jsonwebtoken for JWT operations.
 * Provides secure token generation, validation, and management with RS256 signing.
 */
@Injectable()
export class JwtTokenService implements TokenService {
  private readonly algorithm = 'RS256';
  private readonly issuer = 'auth-service';
  private readonly audience = 'auth-client';
  
  // In production, these should come from environment variables or secure key management
  private readonly privateKey: string;
  private readonly publicKey: string;
  
  // Token blacklist - in production, use Redis or database
  private readonly tokenBlacklist = new Set<string>();

  constructor() {
    // Generate RSA key pair for demonstration
    // In production, use pre-generated keys from secure storage
    const { privateKey, publicKey } = this.generateRSAKeyPair();
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Generate a JWT token with custom payload
   */
  async generateToken(
    payload: JwtPayload,
    type: TokenType,
    expiresIn: string
  ): Promise<string> {
    try {
      this.validateTokenPayload(payload);
      this.validateExpirationTime(expiresIn);

      const tokenPayload: JwtPayload = {
        ...payload,
        type,
        iat: Math.floor(Date.now() / 1000),
      };

      const options: jwt.SignOptions = {
        algorithm: this.algorithm,
        expiresIn,
        issuer: this.issuer,
        audience: this.audience,
        subject: payload.sub,
      };

      const token = jwt.sign(tokenPayload, this.privateKey, options);
      return token;
    } catch (error) {
      console.error('Error generating token:', error);
      throw new Error('Failed to generate JWT token');
    }
  }

  /**
   * Generate an access token
   */
  async generateAccessToken(
    userId: string,
    email: string,
    expiresIn: string = '15m'
  ): Promise<string> {
    try {
      this.validateUserId(userId);
      this.validateEmail(email);

      const payload: JwtPayload = {
        sub: userId,
        email,
        type: TokenType.ACCESS,
      };

      return await this.generateToken(payload, TokenType.ACCESS, expiresIn);
    } catch (error) {
      console.error('Error generating access token:', error);
      throw new Error('Failed to generate access token');
    }
  }

  /**
   * Generate a refresh token
   */
  async generateRefreshToken(
    userId: string,
    email: string,
    expiresIn: string = '7d'
  ): Promise<string> {
    try {
      this.validateUserId(userId);
      this.validateEmail(email);

      const payload: JwtPayload = {
        sub: userId,
        email,
        type: TokenType.REFRESH,
      };

      return await this.generateToken(payload, TokenType.REFRESH, expiresIn);
    } catch (error) {
      console.error('Error generating refresh token:', error);
      throw new Error('Failed to generate refresh token');
    }
  }

  /**
   * Validate and decode a JWT token
   */
  async validateToken(token: string): Promise<TokenValidationResult> {
    try {
      this.validateTokenString(token);

      // Check if token is blacklisted
      if (await this.isTokenBlacklisted(token)) {
        return {
          isValid: false,
          error: 'Token has been revoked',
        };
      }

      const options: jwt.VerifyOptions = {
        algorithms: [this.algorithm],
        issuer: this.issuer,
        audience: this.audience,
      };

      const decoded = jwt.verify(token, this.publicKey, options) as JwtPayload;
      
      // Additional payload validation
      this.validateDecodedPayload(decoded);

      return {
        isValid: true,
        payload: decoded,
      };
    } catch (error) {
      console.error('Token validation error:', error);
      
      if (error instanceof jwt.TokenExpiredError) {
        return {
          isValid: false,
          error: 'Token has expired',
        };
      }
      
      if (error instanceof jwt.JsonWebTokenError) {
        return {
          isValid: false,
          error: 'Invalid token format or signature',
        };
      }

      return {
        isValid: false,
        error: 'Token validation failed',
      };
    }
  }

  /**
   * Decode a JWT token without verification
   */
  decodeToken(token: string): JwtPayload | null {
    try {
      this.validateTokenString(token);
      
      const decoded = jwt.decode(token) as JwtPayload;
      
      if (!decoded || typeof decoded !== 'object') {
        return null;
      }

      return decoded;
    } catch (error) {
      console.error('Error decoding token:', error);
      return null;
    }
  }

  /**
   * Get token expiration date
   */
  getTokenExpiration(token: string): Date | null {
    try {
      const decoded = this.decodeToken(token);
      
      if (!decoded || !decoded.exp) {
        return null;
      }

      return new Date(decoded.exp * 1000);
    } catch (error) {
      console.error('Error getting token expiration:', error);
      return null;
    }
  }

  /**
   * Check if a token is expired
   */
  isTokenExpired(token: string): boolean {
    try {
      const expiration = this.getTokenExpiration(token);
      
      if (!expiration) {
        return true; // Consider invalid tokens as expired
      }

      return expiration.getTime() <= Date.now();
    } catch (error) {
      console.error('Error checking token expiration:', error);
      return true; // Consider error as expired for security
    }
  }

  /**
   * Get remaining time until token expiration
   */
  getTimeUntilExpiration(token: string): number {
    try {
      const expiration = this.getTokenExpiration(token);
      
      if (!expiration) {
        return 0;
      }

      const remaining = expiration.getTime() - Date.now();
      return Math.max(0, remaining);
    } catch (error) {
      console.error('Error getting time until expiration:', error);
      return 0;
    }
  }

  /**
   * Refresh an access token using a refresh token
   */
  async refreshAccessToken(refreshToken: string): Promise<string | null> {
    try {
      const validationResult = await this.validateToken(refreshToken);
      
      if (!validationResult.isValid || !validationResult.payload) {
        return null;
      }

      const payload = validationResult.payload;
      
      // Verify it's a refresh token
      if (payload.type !== TokenType.REFRESH) {
        return null;
      }

      // Generate new access token
      const newAccessToken = await this.generateAccessToken(
        payload.sub,
        payload.email,
        '15m'
      );

      return newAccessToken;
    } catch (error) {
      console.error('Error refreshing access token:', error);
      return null;
    }
  }

  /**
   * Blacklist a token
   */
  async blacklistToken(token: string): Promise<boolean> {
    try {
      this.validateTokenString(token);
      
      // Extract token ID for blacklisting (using JTI if available, otherwise token hash)
      const decoded = this.decodeToken(token);
      const tokenId = decoded?.jti || this.generateTokenHash(token);
      
      this.tokenBlacklist.add(tokenId);
      return true;
    } catch (error) {
      console.error('Error blacklisting token:', error);
      return false;
    }
  }

  /**
   * Check if a token is blacklisted
   */
  async isTokenBlacklisted(token: string): Promise<boolean> {
    try {
      this.validateTokenString(token);
      
      const decoded = this.decodeToken(token);
      const tokenId = decoded?.jti || this.generateTokenHash(token);
      
      return this.tokenBlacklist.has(tokenId);
    } catch (error) {
      console.error('Error checking token blacklist:', error);
      return false; // Don't block on error, let validation handle it
    }
  }

  /**
   * Generate a secure random token
   */
  generateSecureRandomToken(length: number = 32): string {
    try {
      this.validateTokenLength(length);
      
      const randomBytes = crypto.randomBytes(Math.ceil(length / 2));
      return randomBytes.toString('hex').slice(0, length);
    } catch (error) {
      console.error('Error generating secure random token:', error);
      throw new Error('Failed to generate secure random token');
    }
  }

  /**
   * Sign custom data with JWT
   */
  async signData(data: Record<string, any>, expiresIn: string): Promise<string> {
    try {
      this.validateSignData(data);
      this.validateExpirationTime(expiresIn);

      const options: jwt.SignOptions = {
        algorithm: this.algorithm,
        expiresIn,
        issuer: this.issuer,
        audience: this.audience,
      };

      const token = jwt.sign(data, this.privateKey, options);
      return token;
    } catch (error) {
      console.error('Error signing data:', error);
      throw new Error('Failed to sign data');
    }
  }

  /**
   * Verify and extract data from a signed JWT
   */
  async verifyData(token: string): Promise<Record<string, any> | null> {
    try {
      this.validateTokenString(token);

      const options: jwt.VerifyOptions = {
        algorithms: [this.algorithm],
        issuer: this.issuer,
        audience: this.audience,
      };

      const decoded = jwt.verify(token, this.publicKey, options) as Record<string, any>;
      return decoded;
    } catch (error) {
      console.error('Error verifying data:', error);
      return null;
    }
  }

  /**
   * Get service configuration
   */
  getConfiguration(): {
    algorithm: string;
    issuer: string;
    audience: string;
    keyType: string;
  } {
    return {
      algorithm: this.algorithm,
      issuer: this.issuer,
      audience: this.audience,
      keyType: 'RSA',
    };
  }

  /**
   * Health check for the token service
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Test token generation and validation
      const testPayload: JwtPayload = {
        sub: 'health-check-user',
        email: 'health@example.com',
        type: TokenType.ACCESS,
      };

      const token = await this.generateToken(testPayload, TokenType.ACCESS, '1m');
      const validation = await this.validateToken(token);
      
      return validation.isValid === true;
    } catch (error) {
      console.error('Token service health check failed:', error);
      return false;
    }
  }

  // Private validation methods

  private validateTokenPayload(payload: JwtPayload): void {
    if (!payload || typeof payload !== 'object') {
      throw new Error('Token payload is required');
    }

    if (!payload.sub || typeof payload.sub !== 'string') {
      throw new Error('Token payload must include a valid subject (sub)');
    }

    if (!payload.email || typeof payload.email !== 'string') {
      throw new Error('Token payload must include a valid email');
    }
  }

  private validateUserId(userId: string): void {
    if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
      throw new Error('User ID is required and must be a non-empty string');
    }
  }

  private validateEmail(email: string): void {
    if (!email || typeof email !== 'string') {
      throw new Error('Email is required and must be a string');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new Error('Email must be in valid format');
    }
  }

  private validateTokenString(token: string): void {
    if (!token || typeof token !== 'string' || token.trim().length === 0) {
      throw new Error('Token is required and must be a non-empty string');
    }

    // Basic JWT format validation (3 parts separated by dots)
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }
  }

  private validateExpirationTime(expiresIn: string): void {
    if (!expiresIn || typeof expiresIn !== 'string') {
      throw new Error('Expiration time is required and must be a string');
    }

    // Validate format (number followed by time unit)
    const expirationRegex = /^\d+[smhd]$/;
    if (!expirationRegex.test(expiresIn)) {
      throw new Error('Expiration time must be in format like "15m", "7d", "1h"');
    }
  }

  private validateTokenLength(length: number): void {
    if (typeof length !== 'number' || !Number.isInteger(length) || length <= 0) {
      throw new Error('Token length must be a positive integer');
    }

    if (length > 256) {
      throw new Error('Token length cannot exceed 256 characters');
    }
  }

  private validateSignData(data: Record<string, any>): void {
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('Data to sign must be a valid object');
    }

    if (Object.keys(data).length === 0) {
      throw new Error('Data to sign cannot be empty');
    }
  }

  private validateDecodedPayload(decoded: JwtPayload): void {
    if (!decoded.sub) {
      throw new Error('Token payload missing subject (sub)');
    }

    if (!decoded.email) {
      throw new Error('Token payload missing email');
    }

    if (!decoded.type) {
      throw new Error('Token payload missing type');
    }
  }

  private generateTokenHash(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  private generateRSAKeyPair(): { privateKey: string; publicKey: string } {
    // Generate RSA key pair for demonstration
    // In production, use pre-generated keys from secure key management
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    return { privateKey, publicKey };
  }
}