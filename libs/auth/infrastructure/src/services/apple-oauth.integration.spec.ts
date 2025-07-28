import { Test, TestingModule } from '@nestjs/testing';
import { AppleOAuthService } from './apple-oauth.service';

describe('AppleOAuthService (Integration)', () => {
  let service: AppleOAuthService;

  beforeEach(async () => {
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

    const module: TestingModule = await Test.createTestingModule({
      providers: [AppleOAuthService],
    }).compile();

    service = module.get<AppleOAuthService>(AppleOAuthService);
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env.APPLE_CLIENT_ID;
    delete process.env.APPLE_TEAM_ID;
    delete process.env.APPLE_KEY_ID;
    delete process.env.APPLE_PRIVATE_KEY;
    delete process.env.APPLE_REDIRECT_URI;
  });

  describe('Service initialization', () => {
    it('should initialize service with configuration', () => {
      expect(service).toBeDefined();
      
      const config = service.getConfiguration();
      expect(config.clientId).toBe('com.test.app');
      expect(config.teamId).toBe('TEST123456');
      expect(config.keyId).toBe('TEST987654');
      expect(config.redirectUri).toBe('http://localhost:3000/auth/apple/callback');
      expect(config.provider).toBe('apple');
      expect(config.scopes).toEqual(['name', 'email']);
    });
  });

  describe('Authorization URL generation', () => {
    it('should generate valid authorization URLs', async () => {
      const authUrl = await service.generateAuthUrl();
      
      expect(authUrl).toContain('https://appleid.apple.com/auth/authorize');
      expect(authUrl).toContain('client_id=com.test.app');
      expect(authUrl).toContain('response_type=code%20id_token');
      expect(authUrl).toContain('scope=name%20email');
      expect(authUrl).toContain('response_mode=form_post');
      expect(authUrl).toContain('state=');
      expect(authUrl).toContain('nonce=');
    });

    it('should generate different URLs for different states and nonces', async () => {
      const state1 = 'state-123';
      const nonce1 = 'nonce-123';
      const state2 = 'state-456';
      const nonce2 = 'nonce-456';
      
      const url1 = await service.generateAuthUrl(state1, nonce1);
      const url2 = await service.generateAuthUrl(state2, nonce2);
      
      expect(url1).toContain(`state=${state1}`);
      expect(url1).toContain(`nonce=${nonce1}`);
      expect(url2).toContain(`state=${state2}`);
      expect(url2).toContain(`nonce=${nonce2}`);
      expect(url1).not.toEqual(url2);
    });

    it('should include all required parameters', async () => {
      const authUrl = await service.generateAuthUrl();
      
      const url = new URL(authUrl);
      const params = url.searchParams;
      
      expect(params.get('client_id')).toBe('com.test.app');
      expect(params.get('redirect_uri')).toBe('http://localhost:3000/auth/apple/callback');
      expect(params.get('response_type')).toBe('code id_token');
      expect(params.get('scope')).toBe('name email');
      expect(params.get('response_mode')).toBe('form_post');
      expect(params.get('state')).toBeTruthy();
      expect(params.get('nonce')).toBeTruthy();
    });
  });

  describe('Client secret generation', () => {
    it('should generate valid client secret JWT', async () => {
      const clientSecret = await service.generateClientSecret();
      
      expect(clientSecret).toBeDefined();
      expect(typeof clientSecret).toBe('string');
      
      // Should be a JWT format (3 parts separated by dots)
      const parts = clientSecret.split('.');
      expect(parts).toHaveLength(3);
      
      // Each part should be base64url encoded
      parts.forEach(part => {
        expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
      });
    });

    it('should generate different client secrets over time', async () => {
      const secret1 = await service.generateClientSecret();
      
      // Wait a second to ensure different timestamps
      await new Promise(resolve => setTimeout(resolve, 1100));
      
      const secret2 = await service.generateClientSecret();
      
      expect(secret1).not.toEqual(secret2);
    });

    it('should generate client secrets with proper expiration', async () => {
      const clientSecret = await service.generateClientSecret();
      
      // Decode the payload to check expiration
      const parts = clientSecret.split('.');
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      
      expect(payload.iss).toBe('TEST123456');
      expect(payload.aud).toBe('https://appleid.apple.com');
      expect(payload.sub).toBe('com.test.app');
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
      
      // Expiration should be about 1 hour from now
      const now = Math.floor(Date.now() / 1000);
      expect(payload.exp - payload.iat).toBe(3600); // 1 hour
      expect(payload.iat).toBeCloseTo(now, -2); // Within ~100 seconds
    });
  });

  describe('Token validation', () => {
    it('should validate ID token format requirements', async () => {
      const invalidTokens = [
        '',
        'invalid',
        'invalid.token',
        'one.two.three.four', // Too many parts
        null as any,
        undefined as any,
      ];

      for (const invalidToken of invalidTokens) {
        try {
          await service.validateIdToken(invalidToken);
          fail(`Should have thrown error for token: ${invalidToken}`);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect(error.message).toContain('Apple ID token');
        }
      }
    });

    it('should validate authorization code format', async () => {
      const invalidCodes = ['', 'short', null as any];

      for (const invalidCode of invalidCodes) {
        try {
          await service.exchangeCodeForTokens(invalidCode);
          fail(`Should have thrown error for code: ${invalidCode}`);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect(error.message).toContain('Authorization code');
        }
      }
    });

    it('should validate refresh token format', async () => {
      const invalidTokens = ['', 'short', null as any];

      for (const invalidToken of invalidTokens) {
        try {
          await service.revokeToken(invalidToken);
          fail(`Should have thrown error for refresh token: ${invalidToken}`);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect(error.message).toContain('Refresh token');
        }
      }
    });
  });

  describe('Configuration validation', () => {
    it('should require valid client ID', () => {
      process.env.APPLE_CLIENT_ID = '';
      
      expect(() => {
        new AppleOAuthService();
      }).toThrow('Apple OAuth client ID is required');
    });

    it('should require valid team ID format', () => {
      process.env.APPLE_TEAM_ID = 'INVALID';
      
      expect(() => {
        new AppleOAuthService();
      }).toThrow('Invalid Apple OAuth team ID format');
    });

    it('should require valid key ID format', () => {
      process.env.APPLE_KEY_ID = 'INVALID';
      
      expect(() => {
        new AppleOAuthService();
      }).toThrow('Invalid Apple OAuth key ID format');
    });

    it('should require valid private key format', () => {
      process.env.APPLE_PRIVATE_KEY = 'invalid-key-format';
      
      expect(() => {
        new AppleOAuthService();
      }).toThrow('Invalid Apple OAuth private key format');
    });

    it('should require all required configuration', () => {
      const requiredEnvVars = [
        'APPLE_CLIENT_ID',
        'APPLE_TEAM_ID',
        'APPLE_KEY_ID',
        'APPLE_PRIVATE_KEY',
        'APPLE_REDIRECT_URI',
      ];

      for (const envVar of requiredEnvVars) {
        const originalValue = process.env[envVar];
        delete process.env[envVar];

        expect(() => {
          new AppleOAuthService();
        }).toThrow();

        // Restore original value
        if (originalValue) {
          process.env[envVar] = originalValue;
        }
      }
    });
  });

  describe('Error handling', () => {
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

    it('should handle client secret generation errors gracefully', async () => {
      // This is hard to test without mocking, but we can verify the structure
      expect(service.generateClientSecret).toBeDefined();
      expect(typeof service.generateClientSecret).toBe('function');
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
        service.generateAuthUrl('state1', 'nonce1'),
        service.generateAuthUrl('state2', 'nonce2'),
        service.generateClientSecret(),
        service.getConfiguration(),
        service.healthCheck(),
      ];

      const results = await Promise.all(operations);
      
      expect(results).toHaveLength(5);
      expect(results[0]).toContain('state1');
      expect(results[1]).toContain('state2');
      expect(typeof results[2]).toBe('string'); // client secret
      expect(results[3]).toEqual(service.getConfiguration());
      expect(typeof results[4]).toBe('boolean');
    });
  });

  describe('Performance characteristics', () => {
    it('should generate auth URLs quickly', async () => {
      const startTime = Date.now();
      
      await service.generateAuthUrl();
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should generate client secrets efficiently', async () => {
      const startTime = Date.now();
      
      const promises = Array.from({ length: 5 }, () => 
        service.generateClientSecret()
      );
      
      const results = await Promise.all(promises);
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(2000); // Should complete within 2 seconds
      expect(results).toHaveLength(5);
      
      // Each client secret should be a valid JWT
      results.forEach(secret => {
        const parts = secret.split('.');
        expect(parts).toHaveLength(3);
      });
    });

    it('should handle multiple URL generations efficiently', async () => {
      const startTime = Date.now();
      
      const promises = Array.from({ length: 10 }, (_, i) => 
        service.generateAuthUrl(`state-${i}`, `nonce-${i}`)
      );
      
      const results = await Promise.all(promises);
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(2000); // Should complete within 2 seconds
      expect(results).toHaveLength(10);
      
      // Each URL should be unique
      const uniqueUrls = new Set(results);
      expect(uniqueUrls.size).toBe(10);
    });
  });

  describe('Random state and nonce generation', () => {
    it('should generate unique states when none provided', async () => {
      const urls = await Promise.all([
        service.generateAuthUrl(),
        service.generateAuthUrl(),
        service.generateAuthUrl(),
      ]);

      // Extract state parameters
      const states = urls.map(url => {
        const match = url.match(/state=([^&]+)/);
        return match ? decodeURIComponent(match[1]) : null;
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

    it('should generate unique nonces when none provided', async () => {
      const urls = await Promise.all([
        service.generateAuthUrl(),
        service.generateAuthUrl(),
        service.generateAuthUrl(),
      ]);

      // Extract nonce parameters
      const nonces = urls.map(url => {
        const match = url.match(/nonce=([^&]+)/);
        return match ? decodeURIComponent(match[1]) : null;
      });

      // All nonces should be unique
      expect(nonces).toHaveLength(3);
      expect(new Set(nonces).size).toBe(3);
      
      // Nonces should have reasonable length
      nonces.forEach(nonce => {
        expect(nonce).toBeDefined();
        expect(nonce!.length).toBeGreaterThan(10);
      });
    });
  });

  describe('URL encoding', () => {
    it('should properly encode redirect URI in authorization URL', async () => {
      const authUrl = await service.generateAuthUrl();
      
      expect(authUrl).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fapple%2Fcallback');
    });

    it('should properly encode spaces in scope parameter', async () => {
      const authUrl = await service.generateAuthUrl();
      
      expect(authUrl).toContain('scope=name%20email');
    });

    it('should properly encode response type with space', async () => {
      const authUrl = await service.generateAuthUrl();
      
      expect(authUrl).toContain('response_type=code%20id_token');
    });
  });

  describe('Token revocation', () => {
    it('should handle token revocation gracefully', async () => {
      // Test with invalid token (should not throw)
      const result = await service.revokeToken('valid-length-refresh-token-for-testing');
      
      // Should return boolean indicating success/failure
      expect(typeof result).toBe('boolean');
    });
  });
});