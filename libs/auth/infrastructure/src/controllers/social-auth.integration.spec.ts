import { Test, TestingModule } from '@nestjs/testing';
import { SocialAuthController } from './social-auth.controller';
import { SocialLoginUseCase, AuthPresenter } from '@auth/domain';
import { GoogleOAuthService, AppleOAuthService } from '../services';

describe('SocialAuthController (Integration)', () => {
  let controller: SocialAuthController;
  let googleOAuthService: GoogleOAuthService;
  let appleOAuthService: AppleOAuthService;

  beforeEach(async () => {
    // Create real service instances with test configuration
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SocialAuthController],
      providers: [
        {
          provide: 'SocialLoginUseCase',
          useValue: {
            execute: jest.fn(),
          },
        },
        {
          provide: 'AuthPresenter',
          useValue: {
            presentSocialLoginSuccess: jest.fn(),
            presentOAuthError: jest.fn(),
            presentValidationError: jest.fn(),
            presentInternalError: jest.fn(),
          },
        },
        {
          provide: GoogleOAuthService,
          useFactory: () => {
            // Set test environment variables
            process.env.GOOGLE_CLIENT_ID = 'test-google-client-id.googleusercontent.com';
            process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';
            process.env.GOOGLE_REDIRECT_URI = 'http://localhost:3000/auth/google/callback';
            
            return new GoogleOAuthService();
          },
        },
        {
          provide: AppleOAuthService,
          useFactory: () => {
            // Set test environment variables
            process.env.APPLE_CLIENT_ID = 'com.test.app';
            process.env.APPLE_TEAM_ID = 'TEST123456';
            process.env.APPLE_KEY_ID = 'TEST987654';
            process.env.APPLE_PRIVATE_KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBCgM2gR4K2YCZKpFyCPKtHQcjQwgBFfQr/n7ZX5rHkroAoGCCqGSM49
AwEHoUQDQgAE8bF9h0Jh6yT3iyTyK+l8P7P3d4X5k6l0H7X8K7Y3j4K1q5R2S4U8
V2W7Y8Z3T9V3W1Y6R7Q8S9P2K5L4N8M5==
-----END EC PRIVATE KEY-----`;
            process.env.APPLE_REDIRECT_URI = 'http://localhost:3000/auth/apple/callback';
            
            return new AppleOAuthService();
          },
        },
      ],
    }).compile();

    controller = module.get<SocialAuthController>(SocialAuthController);
    googleOAuthService = module.get<GoogleOAuthService>(GoogleOAuthService);
    appleOAuthService = module.get<AppleOAuthService>(AppleOAuthService);
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    delete process.env.GOOGLE_REDIRECT_URI;
    delete process.env.APPLE_CLIENT_ID;
    delete process.env.APPLE_TEAM_ID;
    delete process.env.APPLE_KEY_ID;
    delete process.env.APPLE_PRIVATE_KEY;
    delete process.env.APPLE_REDIRECT_URI;
  });

  describe('Controller initialization', () => {
    it('should be defined', () => {
      expect(controller).toBeDefined();
    });

    it('should have access to OAuth services', () => {
      expect(googleOAuthService).toBeDefined();
      expect(appleOAuthService).toBeDefined();
    });
  });

  describe('Google OAuth flow integration', () => {
    it('should generate valid Google OAuth URLs', async () => {
      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      await controller.initiateGoogleAuth('test-state', undefined, mockResponse);

      expect(mockResponse.redirect).toHaveBeenCalledWith(
        expect.stringContaining('https://accounts.google.com/o/oauth2/v2/auth')
      );
      expect(mockResponse.redirect).toHaveBeenCalledWith(
        expect.stringContaining('client_id=test-google-client-id.googleusercontent.com')
      );
      expect(mockResponse.redirect).toHaveBeenCalledWith(
        expect.stringContaining('state=test-state')
      );
    });

    it('should include redirect URI in state when provided', async () => {
      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      const redirectUri = 'https://app.example.com/dashboard';
      await controller.initiateGoogleAuth('test-state', redirectUri, mockResponse);

      expect(mockResponse.redirect).toHaveBeenCalledWith(
        expect.stringContaining('state=test-state%7C') // %7C is URL-encoded |
      );
    });

    it('should generate unique states for concurrent requests', async () => {
      const mockResponse1 = { redirect: jest.fn() } as any;
      const mockResponse2 = { redirect: jest.fn() } as any;

      await Promise.all([
        controller.initiateGoogleAuth(undefined, undefined, mockResponse1),
        controller.initiateGoogleAuth(undefined, undefined, mockResponse2),
      ]);

      const url1 = mockResponse1.redirect.mock.calls[0][0];
      const url2 = mockResponse2.redirect.mock.calls[0][0];

      // Extract state parameters
      const state1 = new URL(url1).searchParams.get('state');
      const state2 = new URL(url2).searchParams.get('state');

      expect(state1).not.toEqual(state2);
      expect(state1?.length).toBeGreaterThan(20);
      expect(state2?.length).toBeGreaterThan(20);
    });
  });

  describe('Apple OAuth flow integration', () => {
    it('should generate valid Apple Sign In URLs', async () => {
      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      await controller.initiateAppleAuth('test-state', undefined, mockResponse);

      expect(mockResponse.redirect).toHaveBeenCalledWith(
        expect.stringContaining('https://appleid.apple.com/auth/authorize')
      );
      expect(mockResponse.redirect).toHaveBeenCalledWith(
        expect.stringContaining('client_id=com.test.app')
      );
      expect(mockResponse.redirect).toHaveBeenCalledWith(
        expect.stringContaining('response_type=code%20id_token')
      );
    });

    it('should include nonce in Apple OAuth URLs', async () => {
      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      await controller.initiateAppleAuth('test-state', undefined, mockResponse);

      const redirectUrl = mockResponse.redirect.mock.calls[0][0];
      expect(redirectUrl).toContain('nonce=');
    });

    it('should encode redirect URI and nonce in Apple state', async () => {
      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      const redirectUri = 'https://app.example.com/dashboard';
      await controller.initiateAppleAuth('test-state', redirectUri, mockResponse);

      const redirectUrl = mockResponse.redirect.mock.calls[0][0];
      const urlParams = new URL(redirectUrl).searchParams;
      const state = urlParams.get('state');

      expect(state).toContain('test-state');
      expect(state).toContain('|'); // Contains encoded redirect URI
    });
  });

  describe('OAuth configuration endpoint', () => {
    it('should return valid OAuth configuration', async () => {
      const config = await controller.getOAuthConfig();

      expect(config).toEqual({
        success: true,
        data: {
          google: {
            clientId: 'test-google-client-id.googleusercontent.com',
            redirectUri: 'http://localhost:3000/auth/google/callback',
            scopes: [
              'https://www.googleapis.com/auth/userinfo.email',
              'https://www.googleapis.com/auth/userinfo.profile',
            ],
          },
          apple: {
            clientId: 'com.test.app',
            redirectUri: 'http://localhost:3000/auth/apple/callback',
            scopes: ['name', 'email'],
          },
        },
      });
    });

    it('should provide configuration for client-side integration', async () => {
      const config = await controller.getOAuthConfig();

      // Google configuration should have client ID for frontend
      expect(config.data.google.clientId).toBeDefined();
      expect(config.data.google.redirectUri).toBeDefined();
      expect(config.data.google.scopes).toBeInstanceOf(Array);

      // Apple configuration should have client ID for frontend
      expect(config.data.apple.clientId).toBeDefined();
      expect(config.data.apple.redirectUri).toBeDefined();
      expect(config.data.apple.scopes).toBeInstanceOf(Array);
    });
  });

  describe('State management', () => {
    it('should handle state parsing correctly', async () => {
      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      // Test various state formats
      const testCases = [
        { state: 'simple-state', redirectUri: undefined },
        { state: 'complex-state-123', redirectUri: 'https://app.com/dashboard' },
        { state: 'state-with-special-chars!@#', redirectUri: 'https://app.com/path?param=value' },
      ];

      for (const testCase of testCases) {
        jest.clearAllMocks();

        await controller.initiateGoogleAuth(testCase.state, testCase.redirectUri, mockResponse);

        expect(mockResponse.redirect).toHaveBeenCalledWith(
          expect.stringContaining(`state=${encodeURIComponent(testCase.state)}`)
        );

        if (testCase.redirectUri) {
          const redirectUrl = mockResponse.redirect.mock.calls[0][0];
          const urlParams = new URL(redirectUrl).searchParams;
          const state = urlParams.get('state');
          
          expect(state).toContain(testCase.state);
          expect(state).toContain('|'); // Should contain encoded redirect URI
        }
      }
    });
  });

  describe('Error handling', () => {
    it('should handle OAuth service unavailability', async () => {
      // Temporarily break the Google service configuration
      process.env.GOOGLE_CLIENT_ID = '';

      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      await expect(
        controller.initiateGoogleAuth('test-state', undefined, mockResponse)
      ).rejects.toThrow();

      // Restore configuration
      process.env.GOOGLE_CLIENT_ID = 'test-google-client-id.googleusercontent.com';
    });

    it('should handle invalid Apple configuration', async () => {
      // Temporarily break the Apple service configuration
      process.env.APPLE_TEAM_ID = 'INVALID';

      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      await expect(
        controller.initiateAppleAuth('test-state', undefined, mockResponse)
      ).rejects.toThrow();

      // Restore configuration
      process.env.APPLE_TEAM_ID = 'TEST123456';
    });
  });

  describe('Security features', () => {
    it('should generate cryptographically secure states', async () => {
      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      // Generate multiple states and verify they're unique and random
      const states = new Set<string>();
      
      for (let i = 0; i < 10; i++) {
        jest.clearAllMocks();
        await controller.initiateGoogleAuth(undefined, undefined, mockResponse);
        
        const redirectUrl = mockResponse.redirect.mock.calls[0][0];
        const urlParams = new URL(redirectUrl).searchParams;
        const state = urlParams.get('state');
        
        expect(state).toBeDefined();
        expect(state!.length).toBeGreaterThan(20);
        expect(states.has(state!)).toBe(false);
        
        states.add(state!);
      }

      expect(states.size).toBe(10);
    });

    it('should generate secure nonces for Apple', async () => {
      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      // Generate multiple nonces and verify they're unique
      const nonces = new Set<string>();
      
      for (let i = 0; i < 5; i++) {
        jest.clearAllMocks();
        await controller.initiateAppleAuth(undefined, undefined, mockResponse);
        
        const redirectUrl = mockResponse.redirect.mock.calls[0][0];
        const urlParams = new URL(redirectUrl).searchParams;
        const nonce = urlParams.get('nonce');
        
        expect(nonce).toBeDefined();
        expect(nonce!.length).toBeGreaterThan(20);
        expect(nonces.has(nonce!)).toBe(false);
        
        nonces.add(nonce!);
      }

      expect(nonces.size).toBe(5);
    });

    it('should properly encode sensitive data in state', async () => {
      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      const sensitiveRedirectUri = 'https://app.com/admin?token=secret&user=admin';
      
      await controller.initiateGoogleAuth('test-state', sensitiveRedirectUri, mockResponse);

      const redirectUrl = mockResponse.redirect.mock.calls[0][0];
      const urlParams = new URL(redirectUrl).searchParams;
      const state = urlParams.get('state');

      // The redirect URI should be base64 encoded in the state
      expect(state).not.toContain('secret');
      expect(state).not.toContain('admin');
      expect(state).toContain('|'); // Should contain the separator
    });
  });

  describe('Performance characteristics', () => {
    it('should generate OAuth URLs quickly', async () => {
      const mockResponse = {
        redirect: jest.fn(),
      } as any;

      const startTime = Date.now();
      
      await Promise.all([
        controller.initiateGoogleAuth('state1', undefined, mockResponse),
        controller.initiateAppleAuth('state2', undefined, mockResponse),
      ]);
      
      const duration = Date.now() - startTime;
      
      expect(duration).toBeLessThan(1000); // Should complete within 1 second
      expect(mockResponse.redirect).toHaveBeenCalledTimes(2);
    });

    it('should handle concurrent OAuth initiations', async () => {
      const mockResponses = Array.from({ length: 5 }, () => ({
        redirect: jest.fn(),
      }));

      const startTime = Date.now();
      
      await Promise.all(
        mockResponses.map((res, i) => 
          controller.initiateGoogleAuth(`state-${i}`, undefined, res as any)
        )
      );
      
      const duration = Date.now() - startTime;
      
      expect(duration).toBeLessThan(2000); // Should complete within 2 seconds
      
      // All responses should have been called
      mockResponses.forEach(res => {
        expect(res.redirect).toHaveBeenCalledTimes(1);
      });
      
      // All URLs should be unique (different states)
      const urls = mockResponses.map(res => res.redirect.mock.calls[0][0]);
      const uniqueUrls = new Set(urls);
      expect(uniqueUrls.size).toBe(5);
    });
  });
});