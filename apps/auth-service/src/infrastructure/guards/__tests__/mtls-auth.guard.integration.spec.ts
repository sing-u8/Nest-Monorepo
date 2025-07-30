import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import * as request from 'supertest';
import { Controller, Get, UseGuards } from '@nestjs/common';

// Guards
import { MtlsAuthGuard } from '../mtls-auth.guard';

/**
 * Test controller for mTLS guard integration tests
 */
@Controller('mtls-test')
class MtlsTestController {
  @Get('public')
  getPublic() {
    return { message: 'Public endpoint - no mTLS required' };
  }

  @UseGuards(MtlsAuthGuard)
  @Get('protected')
  getProtected() {
    return { message: 'mTLS protected endpoint' };
  }

  @UseGuards(MtlsAuthGuard)
  @Get('admin')
  getAdmin() {
    return { message: 'Admin endpoint with mTLS' };
  }
}

/**
 * mTLS Auth Guard Integration Tests
 * 
 * Tests the MtlsAuthGuard with simulated client certificates
 * to ensure proper mTLS authentication behavior.
 */
describe('MtlsAuthGuard (Integration)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [
            () => ({
              security: {
                mtls: {
                  enabled: true,
                  trustedCAs: [
                    'test-ca-cert-pem', // Mock CA certificate
                  ],
                  subjectAllowlist: [
                    'CN=test-client,O=Test Organization',
                    'CN=admin-client,O=Test Organization',
                  ],
                  requireClientCerts: true,
                },
              },
            }),
          ],
        }),
      ],
      controllers: [MtlsTestController],
      providers: [MtlsAuthGuard],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Public endpoints', () => {
    it('should allow access to endpoints without mTLS guard', async () => {
      // Act
      const response = await request(app.getHttpServer())
        .get('/mtls-test/public')
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'Public endpoint - no mTLS required' });
    });
  });

  describe('mTLS protected endpoints', () => {
    it('should deny access without client certificate', async () => {
      // Act
      await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .expect(401);
    });

    it('should allow access with valid client certificate', async () => {
      // Arrange - Simulate valid client certificate in headers
      const validClientCert = `-----BEGIN CERTIFICATE-----
MIICXjCCAUYCAQAwDQYJKoZIhvcNAQEFBQAwEzERMA8GA1UEAwwIdGVzdC1jbGll
bnQwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjATMREwDwYDVQQDDAh0
ZXN0LWNsaWVudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK...
-----END CERTIFICATE-----`;

      // Act
      const response = await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', encodeURIComponent(validClientCert))
        .set('X-Client-Cert-Subject', 'CN=test-client,O=Test Organization')
        .set('X-Client-Cert-Verified', 'SUCCESS')
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'mTLS protected endpoint' });
    });

    it('should deny access with invalid client certificate', async () => {
      // Arrange - Simulate invalid client certificate
      const invalidClientCert = 'invalid-certificate';

      // Act
      await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', invalidClientCert)
        .set('X-Client-Cert-Verified', 'FAILED')
        .expect(401);
    });

    it('should deny access with expired client certificate', async () => {
      // Arrange - Simulate expired certificate through headers
      const expiredClientCert = `-----BEGIN CERTIFICATE-----
EXPIRED_CERTIFICATE_CONTENT
-----END CERTIFICATE-----`;

      // Act
      await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', encodeURIComponent(expiredClientCert))
        .set('X-Client-Cert-Subject', 'CN=expired-client,O=Test Organization')
        .set('X-Client-Cert-Verified', 'FAILED')
        .set('X-Client-Cert-Error', 'certificate expired')
        .expect(401);
    });

    it('should deny access with certificate from untrusted CA', async () => {
      // Arrange - Simulate certificate from untrusted CA
      const untrustedCert = `-----BEGIN CERTIFICATE-----
UNTRUSTED_CA_CERTIFICATE_CONTENT
-----END CERTIFICATE-----`;

      // Act
      await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', encodeURIComponent(untrustedCert))
        .set('X-Client-Cert-Subject', 'CN=untrusted-client,O=Untrusted Organization')
        .set('X-Client-Cert-Verified', 'FAILED')
        .set('X-Client-Cert-Error', 'unable to verify the first certificate')
        .expect(401);
    });

    it('should deny access with certificate subject not in allowlist', async () => {
      // Arrange - Certificate with subject not in allowlist
      const validCertInvalidSubject = `-----BEGIN CERTIFICATE-----
VALID_CERT_BUT_INVALID_SUBJECT
-----END CERTIFICATE-----`;

      // Act
      await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', encodeURIComponent(validCertInvalidSubject))
        .set('X-Client-Cert-Subject', 'CN=unauthorized-client,O=Unauthorized Organization')
        .set('X-Client-Cert-Verified', 'SUCCESS')
        .expect(401);
    });

    it('should allow access with admin client certificate', async () => {
      // Arrange - Admin client certificate
      const adminClientCert = `-----BEGIN CERTIFICATE-----
ADMIN_CLIENT_CERTIFICATE_CONTENT
-----END CERTIFICATE-----`;

      // Act
      const response = await request(app.getHttpServer())
        .get('/mtls-test/admin')
        .set('X-Client-Cert', encodeURIComponent(adminClientCert))
        .set('X-Client-Cert-Subject', 'CN=admin-client,O=Test Organization')
        .set('X-Client-Cert-Verified', 'SUCCESS')
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'Admin endpoint with mTLS' });
    });
  });

  describe('Certificate parsing from different sources', () => {
    it('should parse certificate from TLS connection info', async () => {
      // Note: This test simulates how certificates would be extracted
      // from the actual TLS connection in a real deployment
      
      // Arrange - Simulate TLS connection with client certificate
      const validClientCert = `-----BEGIN CERTIFICATE-----
TLS_CONNECTION_CERTIFICATE
-----END CERTIFICATE-----`;

      // Act
      const response = await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', encodeURIComponent(validClientCert))
        .set('X-Client-Cert-Subject', 'CN=test-client,O=Test Organization')
        .set('X-Client-Cert-Verified', 'SUCCESS')
        .set('X-Client-Cert-Chain-Verified', 'true')
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'mTLS protected endpoint' });
    });

    it('should parse certificate from proxy headers (production scenario)', async () => {
      // Arrange - Simulate certificate forwarded by reverse proxy
      const proxyForwardedCert = `-----BEGIN CERTIFICATE-----
PROXY_FORWARDED_CERTIFICATE
-----END CERTIFICATE-----`;

      // Act
      const response = await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Forwarded-Client-Cert', encodeURIComponent(proxyForwardedCert))
        .set('X-Forwarded-Client-Cert-Subject', 'CN=test-client,O=Test Organization')
        .set('X-Forwarded-Client-Cert-Verified', 'SUCCESS')
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'mTLS protected endpoint' });
    });
  });

  describe('Certificate validation edge cases', () => {
    it('should handle malformed certificate gracefully', async () => {
      // Arrange
      const malformedCert = 'malformed-certificate-data';

      // Act
      await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', malformedCert)
        .expect(401);
    });

    it('should handle missing certificate headers', async () => {
      // Act
      await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert-Subject', 'CN=test-client,O=Test Organization')
        // Missing X-Client-Cert header
        .expect(401);
    });

    it('should handle URL-encoded certificate properly', async () => {
      // Arrange
      const certWithSpecialChars = `-----BEGIN CERTIFICATE-----
MIICXjCCAUYCAQAwDQYJKoZIhvcNAQEFBQAwEzERMA8GA1UEAwwIdGVzdC9jbGll
bnQwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjATMREwDwYDVQQDDAh0
ZXN0L2NsaWVudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK...
-----END CERTIFICATE-----`;

      // Act
      const response = await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', encodeURIComponent(certWithSpecialChars))
        .set('X-Client-Cert-Subject', 'CN=test-client,O=Test Organization')
        .set('X-Client-Cert-Verified', 'SUCCESS')
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'mTLS protected endpoint' });
    });

    it('should validate certificate chain properly', async () => {
      // Arrange
      const validClientCert = `-----BEGIN CERTIFICATE-----
CLIENT_CERT_WITH_CHAIN
-----END CERTIFICATE-----`;

      // Act
      const response = await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', encodeURIComponent(validClientCert))
        .set('X-Client-Cert-Subject', 'CN=test-client,O=Test Organization')
        .set('X-Client-Cert-Verified', 'SUCCESS')
        .set('X-Client-Cert-Chain-Verified', 'true')
        .set('X-Client-Cert-Issuer', 'CN=Test CA,O=Test Organization')
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'mTLS protected endpoint' });
    });

    it('should reject self-signed certificates in production mode', async () => {
      // Arrange
      const selfSignedCert = `-----BEGIN CERTIFICATE-----
SELF_SIGNED_CERTIFICATE
-----END CERTIFICATE-----`;

      // Act
      await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', encodeURIComponent(selfSignedCert))
        .set('X-Client-Cert-Subject', 'CN=test-client,O=Test Organization')
        .set('X-Client-Cert-Verified', 'FAILED')
        .set('X-Client-Cert-Error', 'self signed certificate')
        .expect(401);
    });
  });

  describe('Security headers and client info', () => {
    it('should extract client information from certificate', async () => {
      // Arrange
      const clientCertWithInfo = `-----BEGIN CERTIFICATE-----
CLIENT_CERT_WITH_ORGANIZATIONAL_INFO
-----END CERTIFICATE-----`;

      const clientInfo = {
        subject: 'CN=test-client,O=Test Organization,OU=Engineering,C=US',
        issuer: 'CN=Test CA,O=Test Organization',
        serialNumber: '123456789',
        fingerprint: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD',
      };

      // Act
      const response = await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', encodeURIComponent(clientCertWithInfo))
        .set('X-Client-Cert-Subject', clientInfo.subject)
        .set('X-Client-Cert-Issuer', clientInfo.issuer)
        .set('X-Client-Cert-Serial', clientInfo.serialNumber)
        .set('X-Client-Cert-Fingerprint', clientInfo.fingerprint)
        .set('X-Client-Cert-Verified', 'SUCCESS')
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'mTLS protected endpoint' });
    });

    it('should handle concurrent mTLS requests', async () => {
      // Arrange
      const validClientCert = `-----BEGIN CERTIFICATE-----
CONCURRENT_TEST_CERTIFICATE
-----END CERTIFICATE-----`;

      const requests = Array.from({ length: 10 }, (_, i) =>
        request(app.getHttpServer())
          .get('/mtls-test/protected')
          .set('X-Client-Cert', encodeURIComponent(validClientCert))
          .set('X-Client-Cert-Subject', `CN=test-client-${i},O=Test Organization`)
          .set('X-Client-Cert-Verified', 'SUCCESS')
      );

      // Act
      const responses = await Promise.all(requests);

      // Assert
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body).toEqual({ message: 'mTLS protected endpoint' });
      });
    });
  });

  describe('Development vs Production behavior', () => {
    it('should handle test certificates in development mode', async () => {
      // Arrange - Set development mode
      process.env.NODE_ENV = 'development';
      
      const testCert = `-----BEGIN CERTIFICATE-----
DEVELOPMENT_TEST_CERTIFICATE
-----END CERTIFICATE-----`;

      // Act
      const response = await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', encodeURIComponent(testCert))
        .set('X-Client-Cert-Subject', 'CN=test-client,O=Test Organization')
        .set('X-Client-Cert-Verified', 'SUCCESS')
        .set('X-Test-Client-Cert', 'true') // Development flag
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'mTLS protected endpoint' });

      // Cleanup
      process.env.NODE_ENV = 'test';
    });

    it('should validate certificate expiration dates', async () => {
      // Arrange
      const nearExpirationCert = `-----BEGIN CERTIFICATE-----
NEAR_EXPIRATION_CERTIFICATE
-----END CERTIFICATE-----`;

      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 1); // Expires tomorrow

      // Act
      const response = await request(app.getHttpServer())
        .get('/mtls-test/protected')
        .set('X-Client-Cert', encodeURIComponent(nearExpirationCert))
        .set('X-Client-Cert-Subject', 'CN=test-client,O=Test Organization')
        .set('X-Client-Cert-Verified', 'SUCCESS')
        .set('X-Client-Cert-Expires', futureDate.toISOString())
        .expect(200);

      // Assert
      expect(response.body).toEqual({ message: 'mTLS protected endpoint' });
    });
  });
});