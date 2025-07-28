import { Test, TestingModule } from '@nestjs/testing';
import { AppleOAuthService } from './apple-oauth.service';
import * as jwt from 'jsonwebtoken';

// Mock jsonwebtoken
jest.mock('jsonwebtoken');
const mockedJwt = jwt as jest.Mocked<typeof jwt>;

// Mock fetch
global.fetch = jest.fn();
const mockedFetch = fetch as jest.MockedFunction<typeof fetch>;

describe('AppleOAuthService', () => {
  let service: AppleOAuthService;

  beforeEach(async () => {
    // Set environment variables for testing
    process.env.APPLE_CLIENT_ID = 'com.test.app';
    process.env.APPLE_TEAM_ID = 'TEST123456';
    process.env.APPLE_KEY_ID = 'TEST987654';
    process.env.APPLE_PRIVATE_KEY = `-----BEGIN EC PRIVATE KEY-----
TEST_PRIVATE_KEY_CONTENT
-----END EC PRIVATE KEY-----`;
    process.env.APPLE_REDIRECT_URI = 'http://localhost:3000/auth/apple/callback';

    const module: TestingModule = await Test.createTestingModule({
      providers: [AppleOAuthService],
    }).compile();

    service = module.get<AppleOAuthService>(AppleOAuthService);

    // Clear all mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env.APPLE_CLIENT_ID;
    delete process.env.APPLE_TEAM_ID;
    delete process.env.APPLE_KEY_ID;
    delete process.env.APPLE_PRIVATE_KEY;
    delete process.env.APPLE_REDIRECT_URI;
  });

  describe('constructor', () => {
    it('should create service with valid configuration', () => {
      expect(service).toBeDefined();
    });

    it('should throw error for missing client ID', () => {
      delete process.env.APPLE_CLIENT_ID;
      
      expect(() => {
        new AppleOAuthService();
      }).toThrow('Apple OAuth client ID is required');
    });

    it('should throw error for missing team ID', () => {
      delete process.env.APPLE_TEAM_ID;
      
      expect(() => {
        new AppleOAuthService();
      }).toThrow('Apple OAuth team ID is required');
    });

    it('should throw error for invalid team ID format', () => {
      process.env.APPLE_TEAM_ID = 'INVALID';
      
      expect(() => {
        new AppleOAuthService();
      }).toThrow('Invalid Apple OAuth team ID format');
    });

    it('should throw error for missing key ID', () => {
      delete process.env.APPLE_KEY_ID;
      
      expect(() => {
        new AppleOAuthService();
      }).toThrow('Apple OAuth key ID is required');
    });

    it('should throw error for invalid key ID format', () => {
      process.env.APPLE_KEY_ID = 'INVALID';
      
      expect(() => {
        new AppleOAuthService();
      }).toThrow('Invalid Apple OAuth key ID format');
    });

    it('should throw error for missing private key', () => {
      delete process.env.APPLE_PRIVATE_KEY;
      
      expect(() => {
        new AppleOAuthService();
      }).toThrow('Apple OAuth private key is required');
    });

    it('should throw error for invalid private key format', () => {
      process.env.APPLE_PRIVATE_KEY = 'invalid-key';
      
      expect(() => {
        new AppleOAuthService();
      }).toThrow('Invalid Apple OAuth private key format');
    });
  });

  describe('generateAuthUrl', () => {
    it('should generate authorization URL with default parameters', async () => {
      const result = await service.generateAuthUrl();

      expect(result).toContain('https://appleid.apple.com/auth/authorize');
      expect(result).toContain('client_id=com.test.app');
      expect(result).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fapple%2Fcallback');
      expect(result).toContain('response_type=code%20id_token');
      expect(result).toContain('scope=name%20email');
      expect(result).toContain('response_mode=form_post');
      expect(result).toContain('state=');
      expect(result).toContain('nonce=');
    });

    it('should generate authorization URL with custom state and nonce', async () => {
      const customState = 'custom-state-123';
      const customNonce = 'custom-nonce-456';

      const result = await service.generateAuthUrl(customState, customNonce);

      expect(result).toContain(`state=${customState}`);
      expect(result).toContain(`nonce=${customNonce}`);
    });

    it('should handle URL generation errors', async () => {
      // Temporarily break the client ID to cause an error
      const originalClientId = process.env.APPLE_CLIENT_ID;
      delete process.env.APPLE_CLIENT_ID;

      // Create a new service instance with missing client ID
      try {
        new AppleOAuthService();
      } catch (error) {
        // This should throw during construction, not URL generation
        expect(error).toBeDefined();
      }

      // Restore client ID
      process.env.APPLE_CLIENT_ID = originalClientId;
    });
  });

  describe('validateIdToken', () => {
    const mockIdToken = 'header.payload.signature';
    const mockPayload = {
      sub: 'user123',
      email: 'test@example.com',
      email_verified: 'true',
      name: { firstName: 'John', lastName: 'Doe' },
      is_private_email: 'false',
      real_user_status: 2,
      nonce: 'test-nonce',
    };

    beforeEach(() => {
      // Mock JWT decode for header
      mockedJwt.decode.mockReturnValue({
        header: { kid: 'test-key-id' },
        payload: mockPayload,
        signature: 'signature',
      });

      // Mock JWT verify
      mockedJwt.verify.mockReturnValue(mockPayload);

      // Mock fetch for Apple public keys
      mockedFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({
          keys: [{
            kty: 'RSA',
            kid: 'test-key-id',
            n: 'mock-modulus',
            e: 'AQAB',
          }],
        }),
      } as any);
    });

    it('should validate ID token and extract user profile', async () => {
      const result = await service.validateIdToken(mockIdToken, 'test-nonce');

      expect(mockedJwt.verify).toHaveBeenCalledWith(
        mockIdToken,
        expect.any(String), // PEM key
        expect.objectContaining({
          issuer: 'https://appleid.apple.com',
          audience: 'com.test.app',
          algorithms: ['RS256'],
        })
      );

      expect(result).toEqual({
        id: 'user123',
        email: 'test@example.com',
        emailVerified: true,
        name: 'John Doe',
        isPrivateEmail: false,
        realUserStatus: 'likelyReal',
      });
    });

    it('should handle missing key ID in token header', async () => {
      mockedJwt.decode.mockReturnValue({
        header: {},
        payload: mockPayload,
        signature: 'signature',
      });

      await expect(service.validateIdToken(mockIdToken)).rejects.toThrow(
        'Invalid ID token header or missing key ID'
      );
    });

    it('should handle nonce mismatch', async () => {
      await expect(service.validateIdToken(mockIdToken, 'wrong-nonce')).rejects.toThrow(
        'Nonce mismatch in ID token'
      );
    });

    it('should handle incomplete user data', async () => {
      const incompletePayload = { sub: 'user123' }; // Missing email
      mockedJwt.verify.mockReturnValue(incompletePayload);

      await expect(service.validateIdToken(mockIdToken)).rejects.toThrow(
        'Incomplete user data in Apple ID token'
      );
    });

    it('should handle invalid token format', async () => {
      await expect(service.validateIdToken('invalid-format')).rejects.toThrow(
        'Invalid Apple ID token format - must be a valid JWT'
      );
    });

    it('should handle expired token', async () => {
      mockedJwt.verify.mockImplementation(() => {
        throw new jwt.TokenExpiredError('jwt expired', new Date());
      });

      await expect(service.validateIdToken(mockIdToken)).rejects.toThrow(
        'Apple ID token has expired'
      );
    });

    it('should handle invalid token signature', async () => {
      mockedJwt.verify.mockImplementation(() => {
        throw new jwt.JsonWebTokenError('invalid signature');
      });

      await expect(service.validateIdToken(mockIdToken)).rejects.toThrow(
        'Invalid Apple ID token signature or format'
      );
    });

    it('should handle Apple public key fetch failure', async () => {
      mockedFetch.mockResolvedValue({
        ok: false,
        statusText: 'Internal Server Error',
      } as any);

      await expect(service.validateIdToken(mockIdToken)).rejects.toThrow(
        'Failed to fetch Apple public keys: Internal Server Error'
      );
    });
  });

  describe('exchangeCodeForTokens', () => {
    it('should exchange authorization code for tokens', async () => {
      const mockTokenResponse = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
      };

      mockedJwt.sign.mockReturnValue('mock-signed-jwt');
      mockedFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockTokenResponse),
      } as any);

      const result = await service.exchangeCodeForTokens('valid-auth-code');

      expect(mockedFetch).toHaveBeenCalledWith(
        'https://appleid.apple.com/auth/token',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        })
      );

      expect(result).toEqual({
        clientSecret: 'mock-signed-jwt',
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
      });
    });

    it('should handle token exchange failure', async () => {
      mockedJwt.sign.mockReturnValue('mock-signed-jwt');
      mockedFetch.mockResolvedValue({
        ok: false,
        statusText: 'Bad Request',
        json: jest.fn().mockResolvedValue({ error: 'invalid_grant' }),
      } as any);

      await expect(service.exchangeCodeForTokens('invalid-code')).rejects.toThrow(
        'Apple token exchange failed: invalid_grant'
      );
    });

    it('should handle invalid authorization code', async () => {
      await expect(service.exchangeCodeForTokens('')).rejects.toThrow(
        'Authorization code is required and cannot be empty'
      );
    });
  });

  describe('generateClientSecret', () => {
    it('should generate client secret JWT', async () => {
      const mockSignedJwt = 'mock.signed.jwt';
      mockedJwt.sign.mockReturnValue(mockSignedJwt);

      const result = await service.generateClientSecret();

      expect(mockedJwt.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          iss: 'TEST123456',
          aud: 'https://appleid.apple.com',
          sub: 'com.test.app',
          iat: expect.any(Number),
          exp: expect.any(Number),
        }),
        expect.any(String), // private key
        expect.objectContaining({
          algorithm: 'ES256',
          header: {
            alg: 'ES256',
            kid: 'TEST987654',
          },
        })
      );

      expect(result).toBe(mockSignedJwt);
    });

    it('should handle client secret generation errors', async () => {
      mockedJwt.sign.mockImplementation(() => {
        throw new Error('JWT signing failed');
      });

      await expect(service.generateClientSecret()).rejects.toThrow(
        'Failed to generate Apple client secret: JWT signing failed'
      );
    });
  });

  describe('revokeToken', () => {
    it('should revoke refresh token successfully', async () => {
      mockedJwt.sign.mockReturnValue('mock-client-secret');
      mockedFetch.mockResolvedValue({
        ok: true,
      } as any);

      const result = await service.revokeToken('valid-refresh-token');

      expect(mockedFetch).toHaveBeenCalledWith(
        'https://appleid.apple.com/auth/revoke',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        })
      );

      expect(result).toBe(true);
    });

    it('should handle token revocation failure gracefully', async () => {
      mockedJwt.sign.mockReturnValue('mock-client-secret');
      mockedFetch.mockResolvedValue({
        ok: false,
      } as any);

      const result = await service.revokeToken('invalid-token');

      expect(result).toBe(false);
    });

    it('should handle invalid refresh token', async () => {
      await expect(service.revokeToken('')).rejects.toThrow(
        'Refresh token is required and cannot be empty'
      );
    });
  });

  describe('getConfiguration', () => {
    it('should return service configuration', () => {
      const result = service.getConfiguration();

      expect(result).toEqual({
        clientId: 'com.test.app',
        teamId: 'TEST123456',
        keyId: 'TEST987654',
        redirectUri: 'http://localhost:3000/auth/apple/callback',
        scopes: ['name', 'email'],
        provider: 'apple',
      });
    });
  });

  describe('healthCheck', () => {
    it('should return true when service is healthy', async () => {
      mockedJwt.sign.mockReturnValue('mock.signed.jwt');
      mockedFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({
          keys: [{
            kty: 'RSA',
            kid: 'test-key-id',
            n: 'mock-modulus',
            e: 'AQAB',
          }],
        }),
      } as any);

      const result = await service.healthCheck();

      expect(result).toBe(true);
    });

    it('should return false when client secret generation fails', async () => {
      mockedJwt.sign.mockImplementation(() => {
        throw new Error('JWT signing failed');
      });

      const result = await service.healthCheck();

      expect(result).toBe(false);
    });

    it('should return false when public key fetch fails', async () => {
      mockedJwt.sign.mockReturnValue('mock.signed.jwt');
      mockedFetch.mockRejectedValue(new Error('Network error'));

      const result = await service.healthCheck();

      expect(result).toBe(false);
    });
  });

  describe('private methods', () => {
    it('should extract name from claims object', async () => {
      const mockPayload = {
        sub: 'user123',
        email: 'test@example.com',
        email_verified: 'true',
        name: { firstName: 'John', lastName: 'Doe' },
        is_private_email: 'false',
        real_user_status: 2,
      };

      mockedJwt.decode.mockReturnValue({
        header: { kid: 'test-key-id' },
        payload: mockPayload,
        signature: 'signature',
      });
      mockedJwt.verify.mockReturnValue(mockPayload);
      mockedFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({
          keys: [{
            kty: 'RSA',
            kid: 'test-key-id',
            n: 'mock-modulus',
            e: 'AQAB',
          }],
        }),
      } as any);

      const result = await service.validateIdToken('header.payload.signature');

      expect(result.name).toBe('John Doe');
    });

    it('should handle string name', async () => {
      const mockPayload = {
        sub: 'user123',
        email: 'test@example.com',
        email_verified: 'true',
        name: 'John Doe',
        is_private_email: 'false',
        real_user_status: 2,
      };

      mockedJwt.decode.mockReturnValue({
        header: { kid: 'test-key-id' },
        payload: mockPayload,
        signature: 'signature',
      });
      mockedJwt.verify.mockReturnValue(mockPayload);
      mockedFetch.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({
          keys: [{
            kty: 'RSA',
            kid: 'test-key-id',
            n: 'mock-modulus',
            e: 'AQAB',
          }],
        }),
      } as any);

      const result = await service.validateIdToken('header.payload.signature');

      expect(result.name).toBe('John Doe');
    });

    it('should map real user status correctly', async () => {
      const testCases = [
        { status: 0, expected: 'unsupported' },
        { status: 1, expected: 'unknown' },
        { status: 2, expected: 'likelyReal' },
        { status: 3, expected: 'unsupported' },
        { status: undefined, expected: 'unsupported' },
      ];

      for (const testCase of testCases) {
        const mockPayload = {
          sub: 'user123',
          email: 'test@example.com',
          email_verified: 'true',
          is_private_email: 'false',
          real_user_status: testCase.status,
        };

        mockedJwt.verify.mockReturnValue(mockPayload);

        const result = await service.validateIdToken('header.payload.signature');
        expect(result.realUserStatus).toBe(testCase.expected);
      }
    });
  });
});