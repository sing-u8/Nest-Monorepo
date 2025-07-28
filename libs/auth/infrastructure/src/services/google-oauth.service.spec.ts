import { Test, TestingModule } from '@nestjs/testing';
import { GoogleOAuthService } from './google-oauth.service';
import { google } from 'googleapis';

// Mock googleapis
jest.mock('googleapis');
const mockedGoogle = google as jest.Mocked<typeof google>;

describe('GoogleOAuthService', () => {
  let service: GoogleOAuthService;
  let mockOAuth2Client: any;

  beforeEach(async () => {
    // Mock OAuth2Client
    mockOAuth2Client = {
      generateAuthUrl: jest.fn(),
      getToken: jest.fn(),
      setCredentials: jest.fn(),
      verifyIdToken: jest.fn(),
      refreshAccessToken: jest.fn(),
      revokeToken: jest.fn(),
    };

    // Mock google.auth.OAuth2 constructor
    mockedGoogle.auth.OAuth2 = jest.fn().mockImplementation(() => mockOAuth2Client);

    // Mock google.oauth2
    const mockOAuth2 = {
      userinfo: {
        get: jest.fn(),
      },
    };
    mockedGoogle.oauth2 = jest.fn().mockReturnValue(mockOAuth2);

    // Set environment variables for testing
    process.env.GOOGLE_CLIENT_ID = 'test-client-id.googleusercontent.com';
    process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret';
    process.env.GOOGLE_REDIRECT_URI = 'http://localhost:3000/auth/google/callback';

    const module: TestingModule = await Test.createTestingModule({
      providers: [GoogleOAuthService],
    }).compile();

    service = module.get<GoogleOAuthService>(GoogleOAuthService);

    // Clear all mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    delete process.env.GOOGLE_REDIRECT_URI;
  });

  describe('constructor', () => {
    it('should create service with valid configuration', () => {
      expect(service).toBeDefined();
      expect(mockedGoogle.auth.OAuth2).toHaveBeenCalledWith(
        'test-client-id.googleusercontent.com',
        'test-client-secret',
        'http://localhost:3000/auth/google/callback'
      );
    });

    it('should throw error for missing client ID', () => {
      delete process.env.GOOGLE_CLIENT_ID;
      
      expect(() => {
        new GoogleOAuthService();
      }).toThrow('Google OAuth client ID is required');
    });

    it('should throw error for invalid client ID format', () => {
      process.env.GOOGLE_CLIENT_ID = 'invalid-client-id';
      
      expect(() => {
        new GoogleOAuthService();
      }).toThrow('Invalid Google OAuth client ID format');
    });

    it('should throw error for missing client secret', () => {
      delete process.env.GOOGLE_CLIENT_SECRET;
      
      expect(() => {
        new GoogleOAuthService();
      }).toThrow('Google OAuth client secret is required');
    });
  });

  describe('generateAuthUrl', () => {
    it('should generate authorization URL with default state', async () => {
      const mockAuthUrl = 'https://accounts.google.com/oauth/authorize?client_id=test';
      mockOAuth2Client.generateAuthUrl.mockReturnValue(mockAuthUrl);

      const result = await service.generateAuthUrl();

      expect(mockOAuth2Client.generateAuthUrl).toHaveBeenCalledWith({
        access_type: 'offline',
        scope: [
          'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/userinfo.profile',
        ],
        include_granted_scopes: true,
        state: expect.any(String),
        prompt: 'consent',
      });
      expect(result).toBe(mockAuthUrl);
    });

    it('should generate authorization URL with custom state', async () => {
      const mockAuthUrl = 'https://accounts.google.com/oauth/authorize?client_id=test';
      const customState = 'custom-state-123';
      mockOAuth2Client.generateAuthUrl.mockReturnValue(mockAuthUrl);

      const result = await service.generateAuthUrl(customState);

      expect(mockOAuth2Client.generateAuthUrl).toHaveBeenCalledWith(
        expect.objectContaining({
          state: customState,
        })
      );
      expect(result).toBe(mockAuthUrl);
    });

    it('should handle authorization URL generation errors', async () => {
      mockOAuth2Client.generateAuthUrl.mockImplementation(() => {
        throw new Error('URL generation failed');
      });

      await expect(service.generateAuthUrl()).rejects.toThrow(
        'Failed to generate Google auth URL: URL generation failed'
      );
    });
  });

  describe('exchangeCodeForTokens', () => {
    it('should exchange authorization code for tokens', async () => {
      const mockTokens = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        id_token: 'mock-id-token',
        expiry_date: Date.now() + 3600000,
        token_type: 'Bearer',
        scope: 'email profile',
      };

      mockOAuth2Client.getToken.mockResolvedValue({ tokens: mockTokens });

      const result = await service.exchangeCodeForTokens('valid-auth-code');

      expect(mockOAuth2Client.getToken).toHaveBeenCalledWith('valid-auth-code');
      expect(result).toEqual({
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        idToken: 'mock-id-token',
        expiryDate: new Date(mockTokens.expiry_date),
        tokenType: 'Bearer',
        scope: 'email profile',
      });
    });

    it('should handle missing access token', async () => {
      mockOAuth2Client.getToken.mockResolvedValue({ 
        tokens: { refresh_token: 'mock-refresh-token' } 
      });

      await expect(service.exchangeCodeForTokens('valid-auth-code')).rejects.toThrow(
        'No access token received from Google'
      );
    });

    it('should handle invalid authorization code', async () => {
      await expect(service.exchangeCodeForTokens('')).rejects.toThrow(
        'Authorization code is required and cannot be empty'
      );
    });

    it('should handle token exchange errors', async () => {
      mockOAuth2Client.getToken.mockRejectedValue(new Error('invalid_grant'));

      await expect(service.exchangeCodeForTokens('invalid-code')).rejects.toThrow(
        'Invalid or expired authorization code'
      );
    });
  });

  describe('getUserProfile', () => {
    it('should get user profile with access token', async () => {
      const mockUserInfo = {
        id: 'user123',
        email: 'test@example.com',
        verified_email: true,
        name: 'John Doe',
        given_name: 'John',
        family_name: 'Doe',
        picture: 'https://example.com/picture.jpg',
        locale: 'en',
        hd: 'example.com',
      };

      const mockOAuth2 = mockedGoogle.oauth2();
      mockOAuth2.userinfo.get.mockResolvedValue({ data: mockUserInfo });

      const result = await service.getUserProfile('valid-access-token');

      expect(mockOAuth2Client.setCredentials).toHaveBeenCalledWith({
        access_token: 'valid-access-token',
      });
      expect(mockOAuth2.userinfo.get).toHaveBeenCalled();
      expect(result).toEqual({
        id: 'user123',
        email: 'test@example.com',
        emailVerified: true,
        name: 'John Doe',
        givenName: 'John',
        familyName: 'Doe',
        picture: 'https://example.com/picture.jpg',
        locale: 'en',
        hostedDomain: 'example.com',
      });
    });

    it('should handle incomplete user profile data', async () => {
      const mockUserInfo = { id: 'user123' }; // Missing email

      const mockOAuth2 = mockedGoogle.oauth2();
      mockOAuth2.userinfo.get.mockResolvedValue({ data: mockUserInfo });

      await expect(service.getUserProfile('valid-access-token')).rejects.toThrow(
        'Incomplete user profile data received from Google'
      );
    });

    it('should handle invalid access token', async () => {
      await expect(service.getUserProfile('')).rejects.toThrow(
        'Access token is required and cannot be empty'
      );
    });

    it('should handle API errors', async () => {
      const mockOAuth2 = mockedGoogle.oauth2();
      mockOAuth2.userinfo.get.mockRejectedValue(new Error('Invalid Credentials'));

      await expect(service.getUserProfile('invalid-token')).rejects.toThrow(
        'Invalid or expired access token'
      );
    });
  });

  describe('validateIdToken', () => {
    it('should validate ID token and extract user profile', async () => {
      const mockPayload = {
        sub: 'user123',
        email: 'test@example.com',
        email_verified: true,
        name: 'John Doe',
        given_name: 'John',
        family_name: 'Doe',
        picture: 'https://example.com/picture.jpg',
        locale: 'en',
        hd: 'example.com',
      };

      const mockTicket = {
        getPayload: jest.fn().mockReturnValue(mockPayload),
      };

      mockOAuth2Client.verifyIdToken.mockResolvedValue(mockTicket);

      const result = await service.validateIdToken('valid-id-token');

      expect(mockOAuth2Client.verifyIdToken).toHaveBeenCalledWith({
        idToken: 'valid-id-token',
        audience: 'test-client-id.googleusercontent.com',
      });
      expect(result).toEqual({
        id: 'user123',
        email: 'test@example.com',
        emailVerified: true,
        name: 'John Doe',
        givenName: 'John',
        familyName: 'Doe',
        picture: 'https://example.com/picture.jpg',
        locale: 'en',
        hostedDomain: 'example.com',
      });
    });

    it('should handle invalid ID token format', async () => {
      await expect(service.validateIdToken('invalid-format')).rejects.toThrow(
        'Invalid ID token format - must be a valid JWT'
      );
    });

    it('should handle empty payload', async () => {
      const mockTicket = {
        getPayload: jest.fn().mockReturnValue(null),
      };

      mockOAuth2Client.verifyIdToken.mockResolvedValue(mockTicket);

      await expect(service.validateIdToken('valid.id.token')).rejects.toThrow(
        'Invalid ID token payload'
      );
    });

    it('should handle incomplete payload data', async () => {
      const mockPayload = { sub: 'user123' }; // Missing email

      const mockTicket = {
        getPayload: jest.fn().mockReturnValue(mockPayload),
      };

      mockOAuth2Client.verifyIdToken.mockResolvedValue(mockTicket);

      await expect(service.validateIdToken('valid.id.token')).rejects.toThrow(
        'Incomplete user data in ID token'
      );
    });
  });

  describe('refreshAccessToken', () => {
    it('should refresh access token using refresh token', async () => {
      const mockCredentials = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        id_token: 'new-id-token',
        expiry_date: Date.now() + 3600000,
        token_type: 'Bearer',
        scope: 'email profile',
      };

      mockOAuth2Client.refreshAccessToken.mockResolvedValue({ 
        credentials: mockCredentials 
      });

      const result = await service.refreshAccessToken('valid-refresh-token');

      expect(mockOAuth2Client.setCredentials).toHaveBeenCalledWith({
        refresh_token: 'valid-refresh-token',
      });
      expect(mockOAuth2Client.refreshAccessToken).toHaveBeenCalled();
      expect(result).toEqual({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        idToken: 'new-id-token',
        expiryDate: new Date(mockCredentials.expiry_date),
        tokenType: 'Bearer',
        scope: 'email profile',
      });
    });

    it('should handle missing access token in refresh response', async () => {
      mockOAuth2Client.refreshAccessToken.mockResolvedValue({ 
        credentials: { refresh_token: 'token' } 
      });

      await expect(service.refreshAccessToken('valid-refresh-token')).rejects.toThrow(
        'No access token received from refresh'
      );
    });

    it('should handle invalid refresh token', async () => {
      await expect(service.refreshAccessToken('')).rejects.toThrow(
        'Refresh token is required and cannot be empty'
      );
    });

    it('should handle refresh errors', async () => {
      mockOAuth2Client.refreshAccessToken.mockRejectedValue(new Error('invalid_grant'));

      await expect(service.refreshAccessToken('invalid-refresh-token')).rejects.toThrow(
        'Invalid or expired refresh token'
      );
    });
  });

  describe('revokeToken', () => {
    it('should revoke token successfully', async () => {
      mockOAuth2Client.revokeToken.mockResolvedValue(undefined);

      const result = await service.revokeToken('valid-token');

      expect(mockOAuth2Client.revokeToken).toHaveBeenCalledWith('valid-token');
      expect(result).toBe(true);
    });

    it('should handle token revocation errors gracefully', async () => {
      mockOAuth2Client.revokeToken.mockRejectedValue(new Error('Revocation failed'));

      const result = await service.revokeToken('invalid-token');

      expect(result).toBe(false);
    });

    it('should handle invalid token format', async () => {
      await expect(service.revokeToken('')).rejects.toThrow(
        'Token is required and cannot be empty'
      );
    });
  });

  describe('getConfiguration', () => {
    it('should return service configuration', () => {
      const result = service.getConfiguration();

      expect(result).toEqual({
        clientId: 'test-client-id.googleusercontent.com',
        redirectUri: 'http://localhost:3000/auth/google/callback',
        scopes: [
          'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/userinfo.profile',
        ],
        provider: 'google',
      });
    });
  });

  describe('healthCheck', () => {
    it('should return true when service is healthy', async () => {
      const mockAuthUrl = 'https://accounts.google.com/oauth/authorize?client_id=test-client-id.googleusercontent.com';
      mockOAuth2Client.generateAuthUrl.mockReturnValue(mockAuthUrl);

      const result = await service.healthCheck();

      expect(result).toBe(true);
    });

    it('should return false when auth URL generation fails', async () => {
      mockOAuth2Client.generateAuthUrl.mockImplementation(() => {
        throw new Error('Auth URL generation failed');
      });

      const result = await service.healthCheck();

      expect(result).toBe(false);
    });

    it('should return false when auth URL is invalid', async () => {
      mockOAuth2Client.generateAuthUrl.mockReturnValue('invalid-url');

      const result = await service.healthCheck();

      expect(result).toBe(false);
    });
  });
});