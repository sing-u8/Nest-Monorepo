import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { MTLSAuthGuard } from './mtls-auth.guard';
import { Request } from 'express';
import { TLSSocket } from 'tls';

describe('MTLSAuthGuard', () => {
  let guard: MTLSAuthGuard;
  let mockExecutionContext: jest.Mocked<ExecutionContext>;
  let mockRequest: Partial<Request>;
  let mockTLSSocket: Partial<TLSSocket>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [MTLSAuthGuard],
    }).compile();

    guard = module.get<MTLSAuthGuard>(MTLSAuthGuard);

    // Setup mock TLS socket
    mockTLSSocket = {
      getPeerCertificate: jest.fn(),
      authorized: true,
      authorizationError: null,
    };

    // Setup mock request
    mockRequest = {
      socket: mockTLSSocket as any,
    };

    // Setup mock execution context
    mockExecutionContext = {
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue(mockRequest),
      }),
    } as any;

    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('canActivate', () => {
    it('should return true for valid mTLS certificate', async () => {
      const validCertificate = {
        subject: {
          CN: 'client.example.com',
          O: 'Example Organization',
          OU: 'IT Department',
          C: 'US',
        },
        issuer: {
          CN: 'Example CA',
          O: 'Example Organization',
          C: 'US',
        },
        serialNumber: '1234567890',
        valid_from: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // Yesterday
        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // Next year
        algorithm: 'sha256WithRSAEncryption',
        ext_key_usage: ['serverAuth', 'clientAuth'],
        raw: Buffer.from('certificate-data'),
      };

      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue(validCertificate);

      const result = await guard.canActivate(mockExecutionContext);

      expect(result).toBe(true);
      expect((mockRequest as any).certificate).toBeDefined();
      expect((mockRequest as any).user).toEqual({
        id: 'client.example.com',
        organization: 'Example Organization',
        certificateFingerprint: expect.any(String),
        authenticationType: 'mtls',
      });
    });

    it('should throw UnauthorizedException when not using TLS', async () => {
      mockRequest.socket = {} as any; // Not a TLS socket

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('mTLS connection required')
      );
    });

    it('should throw UnauthorizedException when no client certificate', async () => {
      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue({});

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Client certificate required')
      );
    });

    it('should throw UnauthorizedException when certificate not authorized', async () => {
      const validCertificate = {
        subject: { CN: 'client.example.com', O: 'Example Organization' },
        issuer: { CN: 'Example CA', O: 'Example Organization' },
        valid_from: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      };

      mockTLSSocket.authorized = false;
      mockTLSSocket.authorizationError = 'CERT_UNTRUSTED';
      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue(validCertificate);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Certificate validation failed: CERT_UNTRUSTED')
      );
    });

    it('should allow self-signed certificate in development mode', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const selfSignedCertificate = {
        subject: { CN: 'client.example.com', O: 'Example Organization' },
        issuer: { CN: 'client.example.com', O: 'Example Organization' }, // Self-signed
        valid_from: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        raw: Buffer.from('self-signed-cert'),
      };

      mockTLSSocket.authorized = false;
      mockTLSSocket.authorizationError = 'DEPTH_ZERO_SELF_SIGNED_CERT';
      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue(selfSignedCertificate);

      const result = await guard.canActivate(mockExecutionContext);

      expect(result).toBe(true);

      // Restore environment
      process.env.NODE_ENV = originalEnv;
    });

    it('should throw UnauthorizedException for expired certificate', async () => {
      const expiredCertificate = {
        subject: { CN: 'client.example.com', O: 'Example Organization' },
        issuer: { CN: 'Example CA', O: 'Example Organization' },
        valid_from: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(), // Last year
        valid_to: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // Yesterday (expired)
      };

      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue(expiredCertificate);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Certificate has expired')
      );
    });

    it('should throw UnauthorizedException for not-yet-valid certificate', async () => {
      const futureCertificate = {
        subject: { CN: 'client.example.com', O: 'Example Organization' },
        issuer: { CN: 'Example CA', O: 'Example Organization' },
        valid_from: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // Tomorrow
        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // Next year
      };

      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue(futureCertificate);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Certificate is not yet valid')
      );
    });

    it('should throw UnauthorizedException for missing required attributes', async () => {
      const certificateWithoutOrg = {
        subject: { CN: 'client.example.com' }, // Missing O (Organization)
        issuer: { CN: 'Example CA', O: 'Example Organization' },
        valid_from: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      };

      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue(certificateWithoutOrg);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Certificate missing required attribute: O')
      );
    });

    it('should throw UnauthorizedException for invalid Common Name', async () => {
      const certificateWithEmptyCN = {
        subject: { CN: '', O: 'Example Organization' }, // Empty CN
        issuer: { CN: 'Example CA', O: 'Example Organization' },
        valid_from: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      };

      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue(certificateWithEmptyCN);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Invalid Common Name in certificate')
      );
    });

    it('should throw UnauthorizedException for invalid certificate purposes', async () => {
      const certificateWithInvalidPurpose = {
        subject: { CN: 'client.example.com', O: 'Example Organization' },
        issuer: { CN: 'Example CA', O: 'Example Organization' },
        valid_from: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        ext_key_usage: ['codeSigning'], // Invalid purpose for client auth
      };

      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue(certificateWithInvalidPurpose);

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Certificate does not have valid purposes')
      );
    });

    it('should handle certificate extraction errors gracefully', async () => {
      (mockTLSSocket.getPeerCertificate as jest.Mock).mockImplementation(() => {
        throw new Error('TLS error');
      });

      await expect(guard.canActivate(mockExecutionContext)).rejects.toThrow(
        new UnauthorizedException('Client certificate required')
      );
    });
  });

  describe('Certificate information extraction', () => {
    it('should extract complete certificate information', async () => {
      const completeCertificate = {
        subject: {
          CN: 'client.example.com',
          O: 'Example Organization',
          OU: 'IT Department',
          C: 'US',
          ST: 'California',
          L: 'San Francisco',
        },
        issuer: {
          CN: 'Example CA',
          O: 'Example Organization',
          OU: 'Certificate Authority',
          C: 'US',
        },
        serialNumber: '1234567890ABCDEF',
        valid_from: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        algorithm: 'sha256WithRSAEncryption',
        ext_key_usage: ['serverAuth', 'clientAuth'],
        subjectaltname: 'DNS:client.example.com,DNS:www.client.example.com',
        raw: Buffer.from('certificate-raw-data'),
      };

      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue(completeCertificate);

      const result = await guard.canActivate(mockExecutionContext);

      expect(result).toBe(true);
      
      const certInfo = (mockRequest as any).certificate;
      expect(certInfo).toEqual(expect.objectContaining({
        subject: {
          CN: 'client.example.com',
          O: 'Example Organization',
          OU: 'IT Department',
          C: 'US',
          ST: 'California',
          L: 'San Francisco',
        },
        issuer: {
          CN: 'Example CA',
          O: 'Example Organization',
          OU: 'Certificate Authority',
          C: 'US',
        },
        serialNumber: '1234567890ABCDEF',
        fingerprint: expect.any(String),
        validFrom: completeCertificate.valid_from,
        validTo: completeCertificate.valid_to,
        algorithm: 'sha256WithRSAEncryption',
        keyUsage: ['serverAuth', 'clientAuth'],
        subjectAltName: 'DNS:client.example.com,DNS:www.client.example.com',
      }));
    });

    it('should calculate fingerprint from raw certificate data', async () => {
      const certificate = {
        subject: { CN: 'client.example.com', O: 'Example Organization' },
        issuer: { CN: 'Example CA', O: 'Example Organization' },
        valid_from: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        raw: Buffer.from('certificate-data'),
      };

      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue(certificate);

      const result = await guard.canActivate(mockExecutionContext);

      expect(result).toBe(true);
      
      const certInfo = (mockRequest as any).certificate;
      expect(certInfo.fingerprint).toBeDefined();
      expect(typeof certInfo.fingerprint).toBe('string');
      expect(certInfo.fingerprint.length).toBeGreaterThan(0);
    });
  });

  describe('Static utility methods', () => {
    beforeEach(() => {
      // Setup a request with certificate info
      (mockRequest as any).certificate = {
        subject: { CN: 'client.example.com', O: 'Example Organization' },
        fingerprint: 'ABC123DEF456',
      };
    });

    it('should get certificate info from request', () => {
      const certInfo = MTLSAuthGuard.getCertificateInfo(mockRequest as Request);
      
      expect(certInfo).toEqual({
        subject: { CN: 'client.example.com', O: 'Example Organization' },
        fingerprint: 'ABC123DEF456',
      });
    });

    it('should get certificate fingerprint from request', () => {
      const fingerprint = MTLSAuthGuard.getCertificateFingerprint(mockRequest as Request);
      
      expect(fingerprint).toBe('ABC123DEF456');
    });

    it('should get certificate subject from request', () => {
      const subject = MTLSAuthGuard.getCertificateSubject(mockRequest as Request);
      
      expect(subject).toEqual({
        CN: 'client.example.com',
        O: 'Example Organization',
      });
    });

    it('should return null when no certificate info in request', () => {
      delete (mockRequest as any).certificate;

      const certInfo = MTLSAuthGuard.getCertificateInfo(mockRequest as Request);
      const fingerprint = MTLSAuthGuard.getCertificateFingerprint(mockRequest as Request);
      const subject = MTLSAuthGuard.getCertificateSubject(mockRequest as Request);
      
      expect(certInfo).toBeNull();
      expect(fingerprint).toBeNull();
      expect(subject).toBeNull();
    });
  });

  describe('Certificate expiration warnings', () => {
    it('should log warning for certificates expiring soon', async () => {
      const soonToExpireCertificate = {
        subject: { CN: 'client.example.com', O: 'Example Organization' },
        issuer: { CN: 'Example CA', O: 'Example Organization' },
        valid_from: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        valid_to: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000).toISOString(), // Expires in 15 days
        raw: Buffer.from('certificate-data'),
      };

      (mockTLSSocket.getPeerCertificate as jest.Mock).mockReturnValue(soonToExpireCertificate);

      const loggerSpy = jest.spyOn((guard as any).logger, 'warn');

      const result = await guard.canActivate(mockExecutionContext);

      expect(result).toBe(true);
      expect(loggerSpy).toHaveBeenCalledWith('Certificate expires soon', expect.any(Object));

      loggerSpy.mockRestore();
    });
  });
});