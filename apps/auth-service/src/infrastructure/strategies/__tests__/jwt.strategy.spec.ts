import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import { JwtStrategy, JwtPayload } from '../jwt.strategy';

// Repositories
import { UserRepository } from '../../../domain/ports/user.repository';
import { TokenRepository } from '../../../domain/ports/token.repository';
import { AuthSessionRepository } from '../../../domain/ports/auth-session.repository';

// Entities
import { User, UserStatus, AuthProvider } from '../../../domain/entities/user.entity';
import { AuthSession } from '../../../domain/entities/auth-session.entity';
import { TokenType } from '../../../domain/entities/token.entity';

describe('JwtStrategy', () => {
  let strategy: JwtStrategy;
  let userRepository: jest.Mocked<UserRepository>;
  let tokenRepository: jest.Mocked<TokenRepository>;
  let authSessionRepository: jest.Mocked<AuthSessionRepository>;
  let configService: jest.Mocked<ConfigService>;

  const mockUser = User.create(
    'user_123',
    'test@example.com',
    'Test User',
    'hashedPassword',
    AuthProvider.LOCAL,
    UserStatus.ACTIVE,
  );

  const mockSession = AuthSession.create(
    'session_123',
    'user_123',
    'session_token_123',
    new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
    {
      userAgent: 'Test-Agent/1.0',
      ipAddress: '192.168.1.1',
      deviceId: 'device_123',
    },
  );

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtStrategy,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue('test-secret'),
          },
        },
        {
          provide: UserRepository,
          useValue: {
            findById: jest.fn(),
          },
        },
        {
          provide: TokenRepository,
          useValue: {},
        },
        {
          provide: AuthSessionRepository,
          useValue: {
            findBySessionToken: jest.fn(),
            save: jest.fn(),
          },
        },
      ],
    }).compile();

    strategy = module.get<JwtStrategy>(JwtStrategy);
    userRepository = module.get(UserRepository);
    tokenRepository = module.get(TokenRepository);
    authSessionRepository = module.get(AuthSessionRepository);
    configService = module.get(ConfigService);
  });

  describe('validate', () => {
    const validPayload: JwtPayload = {
      sub: 'user_123',
      email: 'test@example.com',
      type: TokenType.ACCESS,
      sessionId: 'session_123',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 900, // 15 minutes
    };

    it('should validate a valid JWT payload and return authenticated user', async () => {
      // Arrange
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findBySessionToken.mockResolvedValue(mockSession);
      authSessionRepository.save.mockResolvedValue(mockSession);

      // Act
      const result = await strategy.validate(validPayload);

      // Assert
      expect(result).toEqual({
        userId: 'user_123',
        email: 'test@example.com',
        sessionId: 'session_123',
        tokenType: TokenType.ACCESS,
      });
      expect(userRepository.findById).toHaveBeenCalledWith('user_123');
      expect(authSessionRepository.findBySessionToken).toHaveBeenCalledWith('session_123');
      expect(mockSession.updateActivity).toHaveBeenCalled();
      expect(authSessionRepository.save).toHaveBeenCalledWith(mockSession);
    });

    it('should throw UnauthorizedException for non-access token type', async () => {
      // Arrange
      const invalidPayload: JwtPayload = {
        ...validPayload,
        type: TokenType.REFRESH,
      };

      // Act & Assert
      await expect(strategy.validate(invalidPayload)).rejects.toThrow(
        new UnauthorizedException('Invalid token type'),
      );
    });

    it('should throw UnauthorizedException when user not found', async () => {
      // Arrange
      userRepository.findById.mockResolvedValue(null);

      // Act & Assert
      await expect(strategy.validate(validPayload)).rejects.toThrow(
        new UnauthorizedException('User not found'),
      );
    });

    it('should throw UnauthorizedException when user is inactive', async () => {
      // Arrange
      const inactiveUser = User.create(
        'user_123',
        'test@example.com',
        'Test User',
        'hashedPassword',
        AuthProvider.LOCAL,
        UserStatus.INACTIVE,
      );
      userRepository.findById.mockResolvedValue(inactiveUser);

      // Act & Assert
      await expect(strategy.validate(validPayload)).rejects.toThrow(
        new UnauthorizedException('User account is not active'),
      );
    });

    it('should throw UnauthorizedException when session not found', async () => {
      // Arrange
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findBySessionToken.mockResolvedValue(null);

      // Act & Assert
      await expect(strategy.validate(validPayload)).rejects.toThrow(
        new UnauthorizedException('Session not found'),
      );
    });

    it('should throw UnauthorizedException when session is expired', async () => {
      // Arrange
      const expiredSession = AuthSession.create(
        'session_123',
        'user_123',
        'session_token_123',
        new Date(Date.now() - 1000), // Expired
        {
          userAgent: 'Test-Agent/1.0',
          ipAddress: '192.168.1.1',
          deviceId: 'device_123',
        },
      );
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findBySessionToken.mockResolvedValue(expiredSession);

      // Act & Assert
      await expect(strategy.validate(validPayload)).rejects.toThrow(
        new UnauthorizedException('Session has expired'),
      );
    });

    it('should update session activity on successful validation', async () => {
      // Arrange
      const updateActivitySpy = jest.spyOn(mockSession, 'updateActivity');
      userRepository.findById.mockResolvedValue(mockUser);
      authSessionRepository.findBySessionToken.mockResolvedValue(mockSession);
      authSessionRepository.save.mockResolvedValue(mockSession);

      // Act
      await strategy.validate(validPayload);

      // Assert
      expect(updateActivitySpy).toHaveBeenCalled();
      expect(authSessionRepository.save).toHaveBeenCalledWith(mockSession);
    });
  });

  describe('constructor', () => {
    it('should configure strategy with correct options', () => {
      // Assert
      expect(configService.get).toHaveBeenCalledWith('auth.jwt.accessTokenSecret');
    });
  });
});