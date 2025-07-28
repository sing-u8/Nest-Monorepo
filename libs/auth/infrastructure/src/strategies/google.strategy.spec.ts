import { Test, TestingModule } from '@nestjs/testing';
import { GoogleStrategy } from './google.strategy';
import { SocialLoginUseCase } from '@auth/domain';

describe('GoogleStrategy', () => {
  let strategy: GoogleStrategy;
  let socialLoginUseCase: jest.Mocked<SocialLoginUseCase>;

  const mockGoogleProfile = {
    id: 'google-123456',
    displayName: 'John Doe',
    name: {
      givenName: 'John',
      familyName: 'Doe',
    },
    emails: [
      {
        value: 'john.doe@gmail.com',
        type: 'primary',
        verified: true,
      },
    ],
    photos: [
      {
        value: 'https://lh3.googleusercontent.com/a/photo.jpg',
      },
    ],
    profileUrl: 'https://plus.google.com/123456',
    _json: {
      id: 'google-123456',
      email: 'john.doe@gmail.com',
      verified_email: true,
      name: 'John Doe',
      given_name: 'John',
      family_name: 'Doe',
      picture: 'https://lh3.googleusercontent.com/a/photo.jpg',
      locale: 'en',
      hd: 'example.com',
      id_token: 'google.id.token',
    },
  };

  const mockSocialLoginResult = {
    user: {
      id: 'user-123',
      email: 'john.doe@gmail.com',
      name: 'John Doe',
      provider: 'google',
      isNewUser: false,
    },
    tokens: {
      accessToken: 'jwt-access-token',
      refreshToken: 'jwt-refresh-token',
      expiresIn: 900,
      tokenType: 'Bearer',
    },
    session: {
      id: 'session-123',
      expiresAt: new Date(),
    },
  };

  beforeEach(async () => {
    // Set required environment variables
    process.env['GOOGLE_CLIENT_ID'] = 'test-google-client-id.googleusercontent.com';
    process.env['GOOGLE_CLIENT_SECRET'] = 'test-google-client-secret';
    process.env['GOOGLE_REDIRECT_URI'] = 'http://localhost:3000/auth/google/callback';

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        GoogleStrategy,
        {
          provide: SocialLoginUseCase,
          useValue: {
            execute: jest.fn(),
          },
        },
      ],
    }).compile();

    strategy = module.get<GoogleStrategy>(GoogleStrategy);
    socialLoginUseCase = module.get(SocialLoginUseCase);

    jest.clearAllMocks();
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env['GOOGLE_CLIENT_ID'];
    delete process.env['GOOGLE_CLIENT_SECRET'];
    delete process.env['GOOGLE_REDIRECT_URI'];
  });

  describe('Strategy initialization', () => {
    it('should be defined', () => {
      expect(strategy).toBeDefined();
    });

    it('should throw error when required environment variables are missing', () => {
      delete process.env['GOOGLE_CLIENT_ID'];

      expect(() => {
        new GoogleStrategy(socialLoginUseCase);
      }).toThrow('Missing required environment variables for Google OAuth: GOOGLE_CLIENT_ID');
    });

    it('should warn about invalid client ID format', () => {
      process.env['GOOGLE_CLIENT_ID'] = 'invalid-client-id';
      
      const loggerSpy = jest.spyOn((GoogleStrategy as any).prototype.logger, 'warn');

      new GoogleStrategy(socialLoginUseCase);

      expect(loggerSpy).toHaveBeenCalledWith(
        'Google Client ID does not have expected format (.googleusercontent.com)'
      );

      loggerSpy.mockRestore();
    });
  });

  describe('validate', () => {
    it('should successfully validate Google OAuth and return user data', async () => {
      socialLoginUseCase.execute.mockResolvedValue(mockSocialLoginResult);

      const mockRequest = {
        headers: {
          'user-agent': 'Mozilla/5.0 Test Browser',
          'x-forwarded-for': '192.168.1.1',
          'x-device-id': 'device-123',
        },
        query: {
          code: 'google-auth-code',
        },
      };

      const mockCallback = jest.fn();

      await strategy.validate(
        mockRequest,
        'google-access-token',
        'google-refresh-token',
        mockGoogleProfile,
        mockCallback
      );

      expect(mockCallback).toHaveBeenCalledWith(null, {
        id: 'user-123',
        email: 'john.doe@gmail.com',
        name: 'John Doe',
        provider: 'google',
        isNewUser: false,
        tokens: mockSocialLoginResult.tokens,
        session: mockSocialLoginResult.session,
      });

      expect(socialLoginUseCase.execute).toHaveBeenCalledWith({
        provider: 'google',
        authorizationCode: 'google-auth-code',
        idToken: 'google.id.token',
        accessToken: 'google-access-token',
        refreshToken: 'google-refresh-token',
        profile: {
          id: 'google-123456',
          email: 'john.doe@gmail.com',
          emailVerified: true,
          name: 'John Doe',
          givenName: 'John',
          familyName: 'Doe',
          picture: 'https://lh3.googleusercontent.com/a/photo.jpg',
          locale: 'en',
          hostedDomain: 'example.com',
          profileUrl: 'https://plus.google.com/123456',
          rawProfile: mockGoogleProfile._json,
        },
        clientInfo: {
          userAgent: 'Mozilla/5.0 Test Browser',
          ipAddress: '192.168.1.1',
          deviceId: 'device-123',
        },
      });
    });

    it('should handle social login use case errors', async () => {
      const error = new Error('Social login failed');
      socialLoginUseCase.execute.mockRejectedValue(error);

      const mockRequest = {
        headers: {
          'user-agent': 'Mozilla/5.0 Test Browser',
          'x-forwarded-for': '192.168.1.1',
        },
        query: {
          code: 'google-auth-code',
        },
      };

      const mockCallback = jest.fn();

      await strategy.validate(
        mockRequest,
        'google-access-token',
        'google-refresh-token',
        mockGoogleProfile,
        mockCallback
      );

      expect(mockCallback).toHaveBeenCalledWith(error, null);
    });
  });

  describe('Profile mapping', () => {
    it('should map complete Google profile correctly', () => {
      // Access private method through reflection
      const mapGoogleProfile = (strategy as any).mapGoogleProfile.bind(strategy);
      const result = mapGoogleProfile(mockGoogleProfile);

      expect(result).toEqual({
        id: 'google-123456',
        email: 'john.doe@gmail.com',
        emailVerified: true,
        name: 'John Doe',
        givenName: 'John',
        familyName: 'Doe',
        picture: 'https://lh3.googleusercontent.com/a/photo.jpg',
        locale: 'en',
        hostedDomain: 'example.com',
        profileUrl: 'https://plus.google.com/123456',
        rawProfile: mockGoogleProfile._json,
      });
    });

    it('should handle profile without emails', () => {
      const profileWithoutEmails = {
        ...mockGoogleProfile,
        emails: [],
      };

      const mapGoogleProfile = (strategy as any).mapGoogleProfile.bind(strategy);
      const result = mapGoogleProfile(profileWithoutEmails);

      expect(result.email).toBeUndefined();
    });

    it('should construct name from name components when displayName is missing', () => {
      const profileWithoutDisplayName = {
        ...mockGoogleProfile,
        displayName: undefined,
      };

      const mapGoogleProfile = (strategy as any).mapGoogleProfile.bind(strategy);
      const result = mapGoogleProfile(profileWithoutDisplayName);

      expect(result.name).toBe('John Doe'); // Constructed from givenName + familyName
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
      
      const request = {
        headers: {},
      };
      
      const result = extractClientIP(request);
      
      expect(result).toBe('unknown');
    });
  });
});