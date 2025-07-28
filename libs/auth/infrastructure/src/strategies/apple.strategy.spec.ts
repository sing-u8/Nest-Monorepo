import { Test, TestingModule } from '@nestjs/testing';
import { AppleStrategy } from './apple.strategy';
import { SocialLoginUseCase } from '@auth/domain';
import { AppleOAuthService } from '../services';

describe('AppleStrategy', () => {
  let strategy: AppleStrategy;
  let socialLoginUseCase: jest.Mocked<SocialLoginUseCase>;
  let appleOAuthService: jest.Mocked<AppleOAuthService>;

  const mockAppleProfile = {
    id: 'apple-user-123456',
    email: 'john.doe@privaterelay.appleid.com',
    emailVerified: true,
    name: { firstName: 'John', lastName: 'Doe' },
    isPrivateEmail: true,
    realUserStatus: 'likelyReal',
  };

  const mockSocialLoginResult = {
    user: {
      id: 'user-456',
      email: 'john.doe@privaterelay.appleid.com',
      name: 'John Doe',
      provider: 'apple',
      isNewUser: true,
    },
    tokens: {
      accessToken: 'jwt-access-token',
      refreshToken: 'jwt-refresh-token',
      expiresIn: 900,
      tokenType: 'Bearer',
    },
    session: {
      id: 'session-456',
      expiresAt: new Date(),
    },
  };

  beforeEach(async () => {
    // Set required environment variables
    process.env['APPLE_CLIENT_ID'] = 'com.example.app';
    process.env['APPLE_TEAM_ID'] = 'ABC123DEF4';
    process.env['APPLE_KEY_ID'] = 'KEY123ID45';
    process.env['APPLE_PRIVATE_KEY'] = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHGc4iJI+F2yyYZ2S1HQ2xG3dJz9Zf8XNVR6WqT7Qa0CoAoGCCqGSM49
AwEHoUQDQgAEfHhAfLbdTxHmQOgNjA=
-----END EC PRIVATE KEY-----`;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AppleStrategy,
        {
          provide: SocialLoginUseCase,
          useValue: {
            execute: jest.fn(),
          },
        },
        {
          provide: AppleOAuthService,
          useValue: {
            validateIdToken: jest.fn(),
          },
        },
      ],
    }).compile();

    strategy = module.get<AppleStrategy>(AppleStrategy);
    socialLoginUseCase = module.get(SocialLoginUseCase);
    appleOAuthService = module.get(AppleOAuthService);

    jest.clearAllMocks();
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env['APPLE_CLIENT_ID'];
    delete process.env['APPLE_TEAM_ID'];
    delete process.env['APPLE_KEY_ID'];
    delete process.env['APPLE_PRIVATE_KEY'];
  });

  describe('Strategy initialization', () => {
    it('should be defined', () => {
      expect(strategy).toBeDefined();
    });

    it('should throw error when required environment variables are missing', () => {
      delete process.env['APPLE_CLIENT_ID'];

      expect(() => {
        new AppleStrategy(socialLoginUseCase, appleOAuthService);
      }).toThrow('Missing required environment variables for Apple Sign In: APPLE_CLIENT_ID');
    });

    it('should warn about invalid client ID format', () => {
      process.env['APPLE_CLIENT_ID'] = 'invalid-client-id';
      
      const loggerSpy = jest.spyOn((AppleStrategy as any).prototype.logger, 'warn');

      new AppleStrategy(socialLoginUseCase, appleOAuthService);

      expect(loggerSpy).toHaveBeenCalledWith(
        'Apple Client ID should be a bundle identifier (e.g., com.example.app)'
      );

      loggerSpy.mockRestore();
    });
  });

  describe('validate', () => {
    it('should successfully validate Apple Sign In and return user data', async () => {
      appleOAuthService.validateIdToken.mockResolvedValue(mockAppleProfile);
      socialLoginUseCase.execute.mockResolvedValue(mockSocialLoginResult);

      const mockRequest = {
        body: {
          code: 'apple-auth-code',
          id_token: 'apple.id.token.jwt',
          user: JSON.stringify({
            name: { firstName: 'John', lastName: 'Doe' },
            email: 'john.doe@privaterelay.appleid.com',
          }),
          state: 'originalState|https://app.example.com|dGVzdC1ub25jZQ==',
        },
        headers: {
          'user-agent': 'Mozilla/5.0 Apple WebKit',
          'x-forwarded-for': '203.0.113.100',
          'x-device-id': 'apple-device-123',
        },
      };

      const result = await strategy.validate(mockRequest as any);

      expect(result).toEqual({
        id: 'user-456',
        email: 'john.doe@privaterelay.appleid.com',
        name: 'John Doe',
        provider: 'apple',
        isNewUser: true,
        tokens: mockSocialLoginResult.tokens,
        session: mockSocialLoginResult.session,
      });

      expect(appleOAuthService.validateIdToken).toHaveBeenCalledWith(
        'apple.id.token.jwt',
        'test-nonce'
      );
    });

    it('should throw error when ID token is missing', async () => {
      const requestWithoutIdToken = {
        body: {
          code: 'apple-auth-code',
          // id_token is missing
        },
        headers: {},
      };

      await expect(strategy.validate(requestWithoutIdToken as any)).rejects.toThrow(
        'Apple ID token is required'
      );
    });

    it('should handle Apple OAuth service errors', async () => {
      const error = new Error('Invalid Apple ID token');
      appleOAuthService.validateIdToken.mockRejectedValue(error);

      const mockRequest = {
        body: {
          code: 'apple-auth-code',
          id_token: 'apple.id.token.jwt',
        },
        headers: {},
      };

      await expect(strategy.validate(mockRequest as any)).rejects.toThrow(
        'Invalid Apple ID token'
      );
    });
  });

  describe('Nonce extraction', () => {
    it('should extract base64 encoded nonce from state', () => {
      const extractNonceFromState = (strategy as any).extractNonceFromState.bind(strategy);
      
      // 'test-nonce' encoded as base64 is 'dGVzdC1ub25jZQ=='
      const result = extractNonceFromState('state|redirect|dGVzdC1ub25jZQ==');
      
      expect(result).toBe('test-nonce');
    });

    it('should return undefined for empty state', () => {
      const extractNonceFromState = (strategy as any).extractNonceFromState.bind(strategy);
      
      expect(extractNonceFromState()).toBeUndefined();
      expect(extractNonceFromState('')).toBeUndefined();
    });
  });

  describe('Apple user info parsing', () => {
    it('should parse user info from JSON string', () => {
      const parseAppleUserInfo = (strategy as any).parseAppleUserInfo.bind(strategy);
      
      const userInfo = JSON.stringify({
        name: { firstName: 'Jane', lastName: 'Smith' },
        email: 'jane.smith@privaterelay.appleid.com',
      });
      
      const result = parseAppleUserInfo(userInfo);
      
      expect(result).toEqual({
        name: 'Jane Smith',
        email: 'jane.smith@privaterelay.appleid.com',
        emailVerified: true,
      });
    });

    it('should return empty object for invalid user info', () => {
      const parseAppleUserInfo = (strategy as any).parseAppleUserInfo.bind(strategy);
      
      expect(parseAppleUserInfo('invalid-json')).toEqual({});
      expect(parseAppleUserInfo()).toEqual({});
    });
  });

  describe('Apple name construction', () => {
    it('should construct full name from name object', () => {
      const constructAppleName = (strategy as any).constructAppleName.bind(strategy);
      
      const result = constructAppleName({
        firstName: 'John',
        lastName: 'Doe',
      });
      
      expect(result).toBe('John Doe');
    });

    it('should return empty string for empty name object', () => {
      const constructAppleName = (strategy as any).constructAppleName.bind(strategy);
      
      expect(constructAppleName({})).toBe('');
      expect(constructAppleName()).toBe('');
    });
  });
});