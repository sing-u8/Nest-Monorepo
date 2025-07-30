import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

// Repositories
import { UserRepository } from '../../domain/ports/user.repository';
import { TokenRepository } from '../../domain/ports/token.repository';
import { AuthSessionRepository } from '../../domain/ports/auth-session.repository';

// Domain
import { TokenType } from '../../domain/entities/token.entity';
import { UserStatus } from '../../domain/entities/user.entity';

export interface JwtPayload {
  sub: string; // User ID
  email: string;
  type: TokenType;
  sessionId: string;
  iat?: number;
  exp?: number;
}

export interface AuthenticatedUser {
  userId: string;
  email: string;
  sessionId: string;
  tokenType: TokenType;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly configService: ConfigService,
    private readonly userRepository: UserRepository,
    private readonly tokenRepository: TokenRepository,
    private readonly authSessionRepository: AuthSessionRepository,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('auth.jwt.accessTokenSecret'),
      algorithms: ['HS256'],
    });
  }

  /**
   * Validate JWT payload and return authenticated user
   * This method is called automatically by Passport after token verification
   */
  async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
    // Validate token type
    if (payload.type !== TokenType.ACCESS) {
      throw new UnauthorizedException('Invalid token type');
    }

    // Validate user exists and is active
    const user = await this.userRepository.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (user.getStatus() !== UserStatus.ACTIVE) {
      throw new UnauthorizedException('User account is not active');
    }

    // Validate session exists and is active
    const session = await this.authSessionRepository.findBySessionToken(payload.sessionId);
    if (!session) {
      throw new UnauthorizedException('Session not found');
    }

    if (session.isExpired()) {
      throw new UnauthorizedException('Session has expired');
    }

    // Update session activity
    session.updateActivity();
    await this.authSessionRepository.save(session);

    // Return authenticated user object
    // This will be attached to request.user
    return {
      userId: payload.sub,
      email: payload.email,
      sessionId: payload.sessionId,
      tokenType: payload.type,
    };
  }
}