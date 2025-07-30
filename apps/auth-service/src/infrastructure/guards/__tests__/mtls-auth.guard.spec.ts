import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MtlsAuthGuard } from '../mtls-auth.guard';

describe('MtlsAuthGuard', () => {
  let guard: MtlsAuthGuard;
  let configService: jest.Mocked<ConfigService>;

  const mockCertificate = {
    subject: { CN: 'client.example.com', O: 'Example Corp', C: 'US' },
    issuer: { CN: 'CA.example.com', O: 'Example CA', C: 'US' },
    serialNumber: '1234567890',
    fingerprint: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
    valid_from: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
    valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
  };

  const createMockExecutionContext = (certificate?: any, headers?: any): ExecutionContext => {
    const request = {
      headers: headers || {},
      connection: certificate ? {
        getPeerCertificate: jest.fn().mockReturnValue(certificate),
      } : {},
      mtlsClient: undefined,
    };

    return {
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue(request),
      }),
    } as unknown as ExecutionContext;
  };

  beforeEach(async () => {
    const mockConfigService = {
      get: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MtlsAuthGuard,
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    guard = module.get<MtlsAuthGuard>(MtlsAuthGuard);
    configService = module.get(ConfigService);

    // Default config values
    configService.get.mockImplementation((key: string, defaultValue?: any) => {
      const config = {
        'auth.mtls.trustedCAs': ['CN=CA.example.com'],
        'auth.mtls.allowedSubjects': ['CN=client.example.com'],
        'auth.mtls.requireClientCert': true,
      };
      return config[key] !== undefined ? config[key] : defaultValue;
    });
  });

  describe('canActivate', () => {
    it('should allow access with valid client certificate', async () => {
      // Arrange
      const context = createMockExecutionContext(mockCertificate);

      // Act
      const result = await guard.canActivate(context);

      // Assert
      expect(result).toBe(true);
      const request = context.switchToHttp().getRequest();
      expect(request.mtlsClient).toBeDefined();
      expect(request.mtlsClient.certificateSubject).toContain('CN=client.example.com');
      expect(request.mtlsClient.certificateValid).toBe(true);
    });

    it('should throw UnauthorizedException when certificate is missing and required', async () => {
      // Arrange
      const context = createMockExecutionContext();

      // Act & Assert
      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('Client certificate required'),
      );
    });

    it('should allow access when certificate is not required and not provided', async () => {
      // Arrange
      configService.get.mockImplementation((key: string, defaultValue?: any) => {
        if (key === 'auth.mtls.requireClientCert') return false;
        return defaultValue;
      });
      const newGuard = new MtlsAuthGuard(configService);
      const context = createMockExecutionContext();

      // Act
      const result = await newGuard.canActivate(context);

      // Assert
      expect(result).toBe(true);
    });

    it('should reject self-signed certificates', async () => {
      // Arrange
      const selfSignedCert = {
        ...mockCertificate,
        subject: { CN: 'self-signed.example.com' },
        issuer: { CN: 'self-signed.example.com' }, // Same as subject
      };
      const context = createMockExecutionContext(selfSignedCert);

      // Act & Assert
      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('Invalid client certificate'),
      );
    });

    it('should reject expired certificates', async () => {
      // Arrange
      const expiredCert = {
        ...mockCertificate,
        valid_from: new Date(Date.now() - 2 * 365 * 24 * 60 * 60 * 1000).toISOString(),
        valid_to: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // Expired yesterday
      };
      const context = createMockExecutionContext(expiredCert);

      // Act & Assert
      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('Invalid client certificate'),
      );
    });

    it('should reject certificates not yet valid', async () => {
      // Arrange
      const futureCert = {
        ...mockCertificate,
        valid_from: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // Valid from tomorrow
        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      };
      const context = createMockExecutionContext(futureCert);

      // Act & Assert
      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('Invalid client certificate'),
      );
    });

    it('should reject certificates with disallowed subjects', async () => {
      // Arrange
      const unauthorizedCert = {
        ...mockCertificate,
        subject: { CN: 'unauthorized.example.com', O: 'Unknown Corp' },
      };
      const context = createMockExecutionContext(unauthorizedCert);

      // Act & Assert
      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('Client certificate not authorized'),
      );
    });

    it('should accept certificate from header when configured', async () => {
      // Arrange
      const certHeader = Buffer.from('Subject: CN=client.example.com\nIssuer: CN=CA.example.com\nSerial Number: 123').toString('base64');
      const context = createMockExecutionContext(null, { 'x-client-cert': certHeader });

      // Act
      const result = await guard.canActivate(context);

      // Assert
      expect(result).toBe(true);
    });

    it('should handle certificate validation errors gracefully', async () => {
      // Arrange
      const invalidCert = {
        subject: null, // Invalid structure
        issuer: null,
        serialNumber: null,
      };
      const context = createMockExecutionContext(invalidCert);

      // Act & Assert
      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('Invalid client certificate'),
      );
    });
  });

  describe('certificate parsing', () => {
    it('should extract client ID from CN in subject', async () => {
      // Arrange
      const certWithClientId = {
        ...mockCertificate,
        subject: { CN: 'service-auth-123', OU: 'Services', O: 'Example Corp' },
      };
      const context = createMockExecutionContext(certWithClientId);

      // Act
      await guard.canActivate(context);

      // Assert
      const request = context.switchToHttp().getRequest();
      expect(request.mtlsClient.clientId).toBe('service-auth-123');
    });

    it('should extract client ID from OU when CN not available', async () => {
      // Arrange
      const certWithOuOnly = {
        ...mockCertificate,
        subject: { OU: 'service-payment', O: 'Example Corp' },
      };
      const context = createMockExecutionContext(certWithOuOnly);
      
      // Update allowed subjects to accept OU
      configService.get.mockImplementation((key: string, defaultValue?: any) => {
        if (key === 'auth.mtls.allowedSubjects') return ['OU=service-payment'];
        if (key === 'auth.mtls.trustedCAs') return ['CN=CA.example.com'];
        if (key === 'auth.mtls.requireClientCert') return true;
        return defaultValue;
      });

      // Act
      await guard.canActivate(context);

      // Assert
      const request = context.switchToHttp().getRequest();
      expect(request.mtlsClient.clientId).toBe('service-payment');
    });

    it('should format distinguished names correctly', async () => {
      // Arrange
      const context = createMockExecutionContext(mockCertificate);

      // Act
      await guard.canActivate(context);

      // Assert
      const request = context.switchToHttp().getRequest();
      expect(request.mtlsClient.certificateSubject).toBe('CN=client.example.com, O=Example Corp, C=US');
      expect(request.mtlsClient.certificateIssuer).toBe('CN=CA.example.com, O=Example CA, C=US');
    });
  });

  describe('test certificate handling', () => {
    it('should accept test certificate in non-production environment', async () => {
      // Arrange
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      const testCertHeader = Buffer.from('Subject: CN=test-client\nIssuer: CN=CA.example.com\nSerial Number: test123').toString('base64');
      const context = createMockExecutionContext(null, { 'x-test-client-cert': testCertHeader });

      // Update config to allow test client
      configService.get.mockImplementation((key: string, defaultValue?: any) => {
        if (key === 'auth.mtls.allowedSubjects') return ['CN=test-client'];
        if (key === 'auth.mtls.trustedCAs') return ['CN=CA.example.com'];
        if (key === 'auth.mtls.requireClientCert') return true;
        return defaultValue;
      });

      // Act
      const result = await guard.canActivate(context);

      // Assert
      expect(result).toBe(true);

      // Cleanup
      process.env.NODE_ENV = originalEnv;
    });

    it('should reject test certificate in production environment', async () => {
      // Arrange
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const testCertHeader = Buffer.from('Test certificate').toString('base64');
      const context = createMockExecutionContext(null, { 'x-test-client-cert': testCertHeader });

      // Act & Assert
      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('Client certificate required'),
      );

      // Cleanup
      process.env.NODE_ENV = originalEnv;
    });
  });
});