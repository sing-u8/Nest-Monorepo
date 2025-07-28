import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { JwtStrategy } from './jwt.strategy';
import { User } from '@auth/domain';
import { AuthProvider, UserStatus } from '@auth/shared';

describe('JwtStrategy', () => {
  let strategy: JwtStrategy;
  let userRepository: any;

  const mockUser = User.create({
    id: 'user-789',
    email: 'jwt.user@example.com',
    password: 'HashedPassword123!',
    name: 'JWT Test User',
    provider: AuthProvider.LOCAL,
  });

  const mockJwtPayload = {
    sub: 'user-789',
    email: 'jwt.user@example.com',
    iat: Math.floor(Date.now() / 1000) - 300, // 5 minutes ago
    exp: Math.floor(Date.now() / 1000) + 600, // 10 minutes from now
    iss: 'auth-service',
    aud: 'auth-service-api',
    scope: 'read:profile write:profile',
    permissions: ['user:read', 'profile:update'],
  };

  beforeEach(async () => {
    // Set required environment variables
    process.env['JWT_PUBLIC_KEY'] = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2btf+FxoiLTj12Gm6Fv+4jQ==
-----END PUBLIC KEY-----`;
    process.env['JWT_ISSUER'] = 'auth-service';
    process.env['JWT_AUDIENCE'] = 'auth-service-api';

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtStrategy,
        {
          provide: 'UserRepository',
          useValue: {
            findById: jest.fn(),
          },
        },
      ],
    }).compile();

    strategy = module.get<JwtStrategy>(JwtStrategy);
    userRepository = module.get('UserRepository');

    jest.clearAllMocks();
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env['JWT_PUBLIC_KEY'];
    delete process.env['JWT_SECRET'];
    delete process.env['JWT_ISSUER'];
    delete process.env['JWT_AUDIENCE'];
  });

  describe('Strategy initialization', () => {
    it('should be defined', () => {
      expect(strategy).toBeDefined();
    });

    it('should throw error when no JWT key is provided', () => {
      delete process.env['JWT_PUBLIC_KEY'];
      delete process.env['JWT_SECRET'];

      expect(() => {
        new JwtStrategy(userRepository);
      }).toThrow('JWT_PUBLIC_KEY or JWT_SECRET environment variable is required');
    });
  });

  describe('validate', () => {
    it('should successfully validate JWT and return user data', async () => {
      userRepository.findById.mockResolvedValue(mockUser);

      const mockRequest = {
        headers: {
          'user-agent': 'Mozilla/5.0 Test Browser',
          'x-forwarded-for': '192.168.1.100',
          'x-device-id': 'jwt-device-123',
        },
      };

      const result = await strategy.validate(mockRequest, mockJwtPayload);

      expect(result).toEqual({
        id: 'user-789',
        email: 'jwt.user@example.com',
        name: 'JWT Test User',
        status: UserStatus.ACTIVE,
        provider: AuthProvider.LOCAL,
        emailVerified: true,
        lastLoginAt: mockUser.getUpdatedAt(),
        tokenClaims: expect.objectContaining({
          iat: mockJwtPayload.iat,
          exp: mockJwtPayload.exp,
          iss: 'auth-service',
          aud: 'auth-service-api',
        }),
        clientInfo: expect.objectContaining({
          userAgent: 'Mozilla/5.0 Test Browser',
          ipAddress: '192.168.1.100',
          deviceId: 'jwt-device-123',
        }),
      });

      expect(userRepository.findById).toHaveBeenCalledWith('user-789');
    });

    it('should throw error for invalid payload structure (missing sub)', async () => {
      const invalidPayload = {
        ...mockJwtPayload,
        sub: undefined,
      };

      await expect(strategy.validate({}, invalidPayload)).rejects.toThrow(
        UnauthorizedException
      );
    });

    it('should throw error when user not found', async () => {
      userRepository.findById.mockResolvedValue(null);

      await expect(strategy.validate({}, mockJwtPayload)).rejects.toThrow(
        UnauthorizedException
      );
    });

    it('should throw error for inactive user', async () => {
      const inactiveUser = User.create({
        id: 'user-789',
        email: 'jwt.user@example.com',
        password: 'HashedPassword123!',
        name: 'JWT Test User',
        provider: AuthProvider.LOCAL,
      });
      inactiveUser.suspend();
      userRepository.findById.mockResolvedValue(inactiveUser);

      await expect(strategy.validate({}, mockJwtPayload)).rejects.toThrow(
        UnauthorizedException
      );
    });

    it('should throw error for email mismatch', async () => {
      const userWithDifferentEmail = User.create({
        id: 'user-789',
        email: 'different@example.com',
        password: 'HashedPassword123!',
        name: 'JWT Test User',
        provider: AuthProvider.LOCAL,
      });
      userRepository.findById.mockResolvedValue(userWithDifferentEmail);

      await expect(strategy.validate({}, mockJwtPayload)).rejects.toThrow(
        UnauthorizedException
      );
    });
  });

  describe('Client IP extraction', () => {
    it('should extract IP from x-forwarded-for header (first IP)', () => {
      const extractClientIP = (strategy as any).extractClientIP.bind(strategy);
      
      const request = {
        headers: { 'x-forwarded-for': '203.0.113.1,192.168.1.1' },
      };
      
      const result = extractClientIP(request);
      
      expect(result).toBe('203.0.113.1');
    });

    it('should return "unknown" when no IP is available', () => {
      const extractClientIP = (strategy as any).extractClientIP.bind(strategy);
      
      const request = { headers: {} };
      
      const result = extractClientIP(request);
      
      expect(result).toBe('unknown');
    });
  });
});