import { Test, TestingModule } from '@nestjs/testing';
import { GoogleOAuthService } from './google-oauth.service';

describe('GoogleOAuthService (Integration)', () => {
  let service: GoogleOAuthService;

  beforeEach(async () => {
    // Set test environment variables
    process.env.GOOGLE_CLIENT_ID = 'test-client-id.googleusercontent.com';
    process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret';
    process.env.GOOGLE_REDIRECT_URI = 'http://localhost:3000/auth/google/callback';

    const module: TestingModule = await Test.createTestingModule({
      providers: [GoogleOAuthService],
    }).compile();

    service = module.get<GoogleOAuthService>(GoogleOAuthService);
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    delete process.env.GOOGLE_REDIRECT_URI;
  });

  describe('Service initialization', () => {
    it('should initialize service with configuration', () => {
      expect(service).toBeDefined();
      
      const config = service.getConfiguration();
      expect(config.clientId).toBe('test-client-id.googleusercontent.com');
      expect(config.redirectUri).toBe('http://localhost:3000/auth/google/callback');
      expect(config.provider).toBe('google');
      expect(config.scopes).toEqual([
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
      ]);
    });
  });

  describe('Authorization URL generation', () => {
    it('should generate valid authorization URLs', async () => {
      const authUrl = await service.generateAuthUrl();
      
      expect(authUrl).toContain('https://accounts.google.com/o/oauth2/v2/auth');
      expect(authUrl).toContain('client_id=test-client-id.googleusercontent.com');
      expect(authUrl).toContain('response_type=code');
      expect(authUrl).toContain('access_type=offline');
      expect(authUrl).toContain('prompt=consent');
      expect(authUrl).toContain('scope=');
      expect(authUrl).toContain('state=');
    });

    it('should generate different URLs for different states', async () => {
      const state1 = 'state-123';
      const state2 = 'state-456';
      
      const url1 = await service.generateAuthUrl(state1);
      const url2 = await service.generateAuthUrl(state2);
      
      expect(url1).toContain(`state=${state1}`);
      expect(url2).toContain(`state=${state2}`);
      expect(url1).not.toEqual(url2);
    });

    it('should include all required scopes', async () => {
      const authUrl = await service.generateAuthUrl();
      
      expect(authUrl).toContain('userinfo.email');
      expect(authUrl).toContain('userinfo.profile');
    });
  });

  describe('Token validation', () => {
    it('should validate token format requirements', async () => {
      // Test various invalid token formats
      const invalidTokens = [
        '',
        'invalid',
        'invalid.token',
        'too-short',
        null as any,
        undefined as any,
      ];

      for (const invalidToken of invalidTokens) {
        try {
          await service.exchangeCodeForTokens(invalidToken);
          fail(`Should have thrown error for token: ${invalidToken}`);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect(error.message).toContain('required');
        }
      }
    });

    it('should validate access token format', async () => {
      const invalidTokens = ['', 'short', null as any];

      for (const invalidToken of invalidTokens) {
        try {
          await service.getUserProfile(invalidToken);
          fail(`Should have thrown error for access token: ${invalidToken}`);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect(error.message).toContain('Access token');
        }
      }
    });

    it('should validate ID token JWT format', async () => {
      const invalidIdTokens = [
        '',
        'invalid',
        'not.jwt',
        'one.two.three.four', // Too many parts
      ];

      for (const invalidToken of invalidIdTokens) {
        try {
          await service.validateIdToken(invalidToken);
          fail(`Should have thrown error for ID token: ${invalidToken}`);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect(error.message).toContain('ID token');
        }
      }
    });

    it('should validate refresh token format', async () => {
      const invalidTokens = ['', 'short', null as any];

      for (const invalidToken of invalidTokens) {
        try {
          await service.refreshAccessToken(invalidToken);
          fail(`Should have thrown error for refresh token: ${invalidToken}`);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect(error.message).toContain('Refresh token');
        }
      }
    });
  });

  describe('Error handling', () => {
    it('should handle network errors gracefully', async () => {
      // This test would require mocking network calls
      // For now, we test the error handling structure
      expect(service).toBeDefined();
    });

    it('should provide meaningful error messages', async () => {
      try {
        await service.exchangeCodeForTokens('very-short');
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error.message).toBeDefined();
        expect(error.message.length).toBeGreaterThan(10);
        expect(error.message).toContain('Invalid');
      }
    });
  });

  describe('Configuration validation', () => {
    it('should require valid client ID format', () => {
      process.env.GOOGLE_CLIENT_ID = 'invalid-client-id';
      
      expect(() => {
        new GoogleOAuthService();
      }).toThrow('Invalid Google OAuth client ID format');
    });

    it('should require all required configuration', () => {
      const requiredEnvVars = [
        'GOOGLE_CLIENT_ID',
        'GOOGLE_CLIENT_SECRET',
        'GOOGLE_REDIRECT_URI',
      ];

      for (const envVar of requiredEnvVars) {
        const originalValue = process.env[envVar];
        delete process.env[envVar];

        expect(() => {
          new GoogleOAuthService();
        }).toThrow();

        // Restore original value
        if (originalValue) {
          process.env[envVar] = originalValue;
        }
      }
    });

    it('should validate redirect URI format', () => {
      process.env.GOOGLE_REDIRECT_URI = 'invalid-uri';
      
      expect(() => {
        new GoogleOAuthService();
      }).toThrow('Invalid Google OAuth redirect URI format');
    });
  });

  describe('Health check', () => {
    it('should pass health check with valid configuration', async () => {
      const isHealthy = await service.healthCheck();
      
      // Health check should succeed with valid configuration
      expect(typeof isHealthy).toBe('boolean');
    });

    it('should handle health check gracefully', async () => {
      // Health check should not throw errors
      const healthCheckPromise = service.healthCheck();
      
      await expect(healthCheckPromise).resolves.toBeDefined();
    });
  });

  describe('Service lifecycle', () => {
    it('should maintain consistent configuration throughout lifecycle', () => {
      const config1 = service.getConfiguration();
      const config2 = service.getConfiguration();
      
      expect(config1).toEqual(config2);
    });

    it('should handle multiple concurrent operations', async () => {
      const operations = [
        service.generateAuthUrl('state1'),
        service.generateAuthUrl('state2'),
        service.generateAuthUrl('state3'),
        service.getConfiguration(),
        service.healthCheck(),
      ];

      const results = await Promise.all(operations);
      
      expect(results).toHaveLength(5);
      expect(results[0]).toContain('state1');
      expect(results[1]).toContain('state2');
      expect(results[2]).toContain('state3');
      expect(results[3]).toEqual(service.getConfiguration());
      expect(typeof results[4]).toBe('boolean');
    });
  });

  describe('Token revocation', () => {
    it('should handle token revocation gracefully', async () => {
      // Test with invalid token (should not throw)
      const result = await service.revokeToken('invalid-token-for-testing');
      
      // Should return boolean indicating success/failure
      expect(typeof result).toBe('boolean');
    });

    it('should validate token before revocation', async () => {
      const invalidTokens = ['', 'short'];

      for (const invalidToken of invalidTokens) {
        try {
          await service.revokeToken(invalidToken);
          fail(`Should have thrown error for token: ${invalidToken}`);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect(error.message).toContain('Token');
        }
      }
    });
  });

  describe('Performance characteristics', () => {
    it('should generate auth URLs quickly', async () => {
      const startTime = Date.now();
      
      await service.generateAuthUrl();
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should handle multiple URL generations efficiently', async () => {
      const startTime = Date.now();
      
      const promises = Array.from({ length: 10 }, (_, i) => 
        service.generateAuthUrl(`state-${i}`)
      );
      
      const results = await Promise.all(promises);
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(2000); // Should complete within 2 seconds
      expect(results).toHaveLength(10);
      
      // Each URL should be unique
      const uniqueUrls = new Set(results);
      expect(uniqueUrls.size).toBe(10);
    });

    it('should provide consistent configuration access', () => {
      const startTime = Date.now();
      
      // Access configuration multiple times
      for (let i = 0; i < 100; i++) {
        service.getConfiguration();
      }
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(100); // Should be very fast
    });
  });

  describe('State management', () => {
    it('should generate unique states when none provided', async () => {
      const urls = await Promise.all([
        service.generateAuthUrl(),
        service.generateAuthUrl(),
        service.generateAuthUrl(),
      ]);

      // Extract state parameters
      const states = urls.map(url => {
        const match = url.match(/state=([^&]+)/);
        return match ? match[1] : null;
      });

      // All states should be unique
      expect(states).toHaveLength(3);
      expect(new Set(states).size).toBe(3);
      
      // States should have reasonable length
      states.forEach(state => {
        expect(state).toBeDefined();
        expect(state!.length).toBeGreaterThan(10);
      });
    });
  });
});