import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../app/app.module';
import { DataSource } from 'typeorm';
import { UserEntity, AuthSessionEntity } from '@auth/infrastructure';

describe('mTLS Authentication E2E Tests', () => {
  let app: INestApplication;
  let dataSource: DataSource;
  let httpsServer: https.Server;

  // Mock certificates for testing
  const testCertificatesPath = path.join(__dirname, '..', '..', 'test-certificates');
  const serverCertPath = path.join(testCertificatesPath, 'server-cert.pem');
  const serverKeyPath = path.join(testCertificatesPath, 'server-key.pem');
  const clientCertPath = path.join(testCertificatesPath, 'client-cert.pem');
  const clientKeyPath = path.join(testCertificatesPath, 'client-key.pem');
  const caCertPath = path.join(testCertificatesPath, 'ca-cert.pem');

  beforeAll(async () => {
    // Set test environment variables for mTLS
    process.env.NODE_ENV = 'test';
    process.env.PORT = '3102';
    process.env.JWT_SECRET = 'test-jwt-secret-for-mtls-e2e-testing-only';
    process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-for-mtls-e2e-testing-only';
    process.env.DATABASE_TYPE = 'postgres';
    process.env.DATABASE_HOST = 'localhost';
    process.env.DATABASE_PORT = '5432';
    process.env.DATABASE_USERNAME = 'test_user';
    process.env.DATABASE_PASSWORD = 'test_password';
    process.env.DATABASE_NAME = 'test_auth_mtls_e2e_db';
    process.env.DATABASE_SYNCHRONIZE = 'true';
    process.env.DATABASE_DROP_SCHEMA = 'true';
    process.env.API_PREFIX = 'api/v1';

    // mTLS Configuration
    process.env.SECURITY_ENABLE_MTLS = 'true';
    process.env.MTLS_SERVER_CERT_PATH = serverCertPath;
    process.env.MTLS_SERVER_KEY_PATH = serverKeyPath;
    process.env.MTLS_CA_CERT_PATH = caCertPath;
    process.env.MTLS_REQUIRE_CLIENT_CERT = 'true';
    process.env.MTLS_VERIFY_CLIENT_CERT = 'true';

    process.env.SECURITY_ENABLE_RATE_LIMITING = 'false';
    process.env.LOG_LEVEL = 'error';

    // Create test certificates directory if it doesn't exist
    if (!fs.existsSync(testCertificatesPath)) {
      fs.mkdirSync(testCertificatesPath, { recursive: true });
    }

    // Generate test certificates for mTLS testing
    await generateTestCertificates();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    dataSource = app.get(DataSource);

    // Configure HTTPS server with mTLS
    if (process.env.SECURITY_ENABLE_MTLS === 'true') {
      const httpsOptions = {
        key: fs.readFileSync(serverKeyPath),
        cert: fs.readFileSync(serverCertPath),
        ca: fs.readFileSync(caCertPath),
        requestCert: true,
        rejectUnauthorized: true,
      };

      httpsServer = https.createServer(httpsOptions, app.getHttpAdapter().getInstance());
      await app.init();
      httpsServer.listen(3102);
    } else {
      await app.init();
    }
  });

  afterAll(async () => {
    if (httpsServer) {
      httpsServer.close();
    }
    if (dataSource?.isInitialized) {
      await dataSource.destroy();
    }
    await app.close();

    // Clean up test certificates
    cleanupTestCertificates();
  });

  beforeEach(async () => {
    // Clean up database before each test
    await dataSource.getRepository(AuthSessionEntity).delete({});
    await dataSource.getRepository(UserEntity).delete({});
  });

  // Helper function to generate test certificates
  async function generateTestCertificates() {
    // Mock certificate generation for testing
    // In a real implementation, you would use proper certificate generation tools
    
    const mockCACert = `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDOxrWKFmG8mjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7X8/test-ca-cert-content
-----END CERTIFICATE-----`;

    const mockCAKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDtfz/test-ca-key
-----END PRIVATE KEY-----`;

    const mockServerCert = `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDOxrWKFmG8mjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7X8/test-server-cert
-----END CERTIFICATE-----`;

    const mockServerKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDtfz/test-server-key
-----END PRIVATE KEY-----`;

    const mockClientCert = `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDOxrWKFmG8mjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMA0xCzAJBgNVBAYTAlVT  
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7X8/test-client-cert
-----END CERTIFICATE-----`;

    const mockClientKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDtfz/test-client-key
-----END PRIVATE KEY-----`;

    // Write mock certificates for testing
    fs.writeFileSync(caCertPath, mockCACert);
    fs.writeFileSync(serverCertPath, mockServerCert);
    fs.writeFileSync(serverKeyPath, mockServerKey);
    fs.writeFileSync(clientCertPath, mockClientCert);
    fs.writeFileSync(clientKeyPath, mockClientKey);
  }

  function cleanupTestCertificates() {
    const certFiles = [caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath];
    certFiles.forEach(file => {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    });
    if (fs.existsSync(testCertificatesPath)) {
      fs.rmdirSync(testCertificatesPath);
    }
  }

  // Helper function to create HTTPS agent with client certificate
  function createMTLSAgent(useClientCert = true) {
    const options: https.AgentOptions = {
      ca: fs.readFileSync(caCertPath),
      rejectUnauthorized: false, // For testing with self-signed certificates
    };

    if (useClientCert) {
      options.cert = fs.readFileSync(clientCertPath);
      options.key = fs.readFileSync(clientKeyPath);
    }

    return new https.Agent(options);
  }

  describe('mTLS Connection Establishment', () => {
    it('should establish secure mTLS connection with valid client certificate', async () => {
      // Skip if mTLS is not enabled
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      const agent = createMTLSAgent(true);

      // Test basic mTLS connection
      const response = await new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/health',
          method: 'GET',
          agent: agent,
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
        });

        req.on('error', reject);
        req.setTimeout(5000, () => reject(new Error('Request timeout')));
        req.end();
      });

      expect((response as any).statusCode).toBe(200);
    });

    it('should reject connection without client certificate', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      const agent = createMTLSAgent(false); // No client certificate

      // Connection should be rejected
      await expect(new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/health',
          method: 'GET',
          agent: agent,
        }, resolve);

        req.on('error', reject);
        req.setTimeout(5000, () => reject(new Error('Request timeout')));
        req.end();
      })).rejects.toThrow();
    });

    it('should reject connection with invalid client certificate', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      // Create invalid certificate
      const invalidCertPath = path.join(testCertificatesPath, 'invalid-cert.pem');
      const invalidKeyPath = path.join(testCertificatesPath, 'invalid-key.pem');

      fs.writeFileSync(invalidCertPath, `-----BEGIN CERTIFICATE-----
INVALID_CERTIFICATE_CONTENT
-----END CERTIFICATE-----`);

      fs.writeFileSync(invalidKeyPath, `-----BEGIN PRIVATE KEY-----
INVALID_PRIVATE_KEY_CONTENT
-----END PRIVATE KEY-----`);

      const invalidAgent = new https.Agent({
        cert: fs.readFileSync(invalidCertPath),
        key: fs.readFileSync(invalidKeyPath),
        ca: fs.readFileSync(caCertPath),
        rejectUnauthorized: false,
      });

      // Connection should be rejected
      await expect(new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/health',
          method: 'GET',
          agent: invalidAgent,
        }, resolve);

        req.on('error', reject);
        req.setTimeout(5000, () => reject(new Error('Request timeout')));
        req.end();
      })).rejects.toThrow();

      // Cleanup
      fs.unlinkSync(invalidCertPath);
      fs.unlinkSync(invalidKeyPath);
    });
  });

  describe('mTLS Authentication Flow', () => {
    it('should authenticate user with valid mTLS certificate', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      // Create user associated with client certificate
      const userRepository = dataSource.getRepository(UserEntity);
      const clientCertUser = await userRepository.save({
        id: 'mtls-user-1',
        email: 'mtls@example.com',
        name: 'mTLS Test User',
        provider: 'mtls',
        certificate_fingerprint: 'test-cert-fingerprint-123',
        status: 'active',
        email_verified: true,
      });

      const agent = createMTLSAgent(true);

      // Test mTLS authentication endpoint
      const response = await new Promise<any>((resolve, reject) => {
        const postData = JSON.stringify({
          certificateFingerprint: 'test-cert-fingerprint-123',
        });

        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/api/v1/auth/mtls/authenticate',
          method: 'POST',
          agent: agent,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try {
              resolve({
                statusCode: res.statusCode,
                body: JSON.parse(data),
                headers: res.headers,
              });
            } catch (e) {
              resolve({ statusCode: res.statusCode, body: data, headers: res.headers });
            }
          });
        });

        req.on('error', reject);
        req.setTimeout(10000, () => reject(new Error('Request timeout')));
        req.write(postData);
        req.end();
      });

      expect(response.statusCode).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.user.id).toBe(clientCertUser.id);
      expect(response.body.data.tokens.accessToken).toBeDefined();
    });

    it('should reject authentication with unregistered certificate', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      const agent = createMTLSAgent(true);

      const response = await new Promise<any>((resolve, reject) => {
        const postData = JSON.stringify({
          certificateFingerprint: 'unregistered-cert-fingerprint-999',
        });

        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/api/v1/auth/mtls/authenticate',
          method: 'POST',
          agent: agent,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try {
              resolve({
                statusCode: res.statusCode,
                body: JSON.parse(data),
              });
            } catch (e) {
              resolve({ statusCode: res.statusCode, body: data });
            }
          });
        });

        req.on('error', reject);
        req.setTimeout(10000, () => reject(new Error('Request timeout')));
        req.write(postData);
        req.end();
      });

      expect(response.statusCode).toBe(401);
      expect(response.body.message).toContain('Invalid certificate');
    });

    it('should handle certificate registration for new users', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      const agent = createMTLSAgent(true);
      const newCertFingerprint = 'new-cert-fingerprint-456';

      const response = await new Promise<any>((resolve, reject) => {
        const postData = JSON.stringify({
          certificateFingerprint: newCertFingerprint,
          email: 'newmtls@example.com',
          name: 'New mTLS User',
        });

        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/api/v1/auth/mtls/register',
          method: 'POST',
          agent: agent,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try {
              resolve({
                statusCode: res.statusCode,
                body: JSON.parse(data),
              });
            } catch (e) {
              resolve({ statusCode: res.statusCode, body: data });
            }
          });
        });

        req.on('error', reject);
        req.setTimeout(10000, () => reject(new Error('Request timeout')));
        req.write(postData);
        req.end();
      });

      expect(response.statusCode).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.data.user.provider).toBe('mtls');
      expect(response.body.data.user.certificate_fingerprint).toBe(newCertFingerprint);

      // Verify user was created in database
      const userRepository = dataSource.getRepository(UserEntity);
      const newUser = await userRepository.findOne({
        where: { certificate_fingerprint: newCertFingerprint },
      });
      expect(newUser).toBeDefined();
      expect(newUser?.email).toBe('newmtls@example.com');
    });
  });

  describe('mTLS Session Management', () => {
    let mtlsUser: UserEntity;
    let mtlsAccessToken: string;

    beforeEach(async () => {
      // Create mTLS user for session tests
      const userRepository = dataSource.getRepository(UserEntity);
      mtlsUser = await userRepository.save({
        id: 'mtls-session-user',
        email: 'mtlssession@example.com',
        name: 'mTLS Session User',
        provider: 'mtls',
        certificate_fingerprint: 'session-cert-fingerprint-789',
        status: 'active',
        email_verified: true,
      });

      // Simulate mTLS authentication to get access token
      if (process.env.SECURITY_ENABLE_MTLS === 'true') {
        const agent = createMTLSAgent(true);

        const authResponse = await new Promise<any>((resolve, reject) => {
          const postData = JSON.stringify({
            certificateFingerprint: 'session-cert-fingerprint-789',
          });

          const req = https.request({
            hostname: 'localhost',
            port: 3102,
            path: '/api/v1/auth/mtls/authenticate',
            method: 'POST',
            agent: agent,
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(postData),
            },
          }, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
              resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
            });
          });

          req.on('error', reject);
          req.setTimeout(10000, () => reject(new Error('Request timeout')));
          req.write(postData);
          req.end();
        });

        mtlsAccessToken = authResponse.body.data.tokens.accessToken;
      }
    });

    it('should access protected routes with mTLS authentication', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      const agent = createMTLSAgent(true);

      const response = await new Promise<any>((resolve, reject) => {
        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/api/v1/auth/profile',
          method: 'GET',
          agent: agent,
          headers: {
            'Authorization': `Bearer ${mtlsAccessToken}`,
          },
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
          });
        });

        req.on('error', reject);
        req.setTimeout(10000, () => reject(new Error('Request timeout')));
        req.end();
      });

      expect(response.statusCode).toBe(200);
      expect(response.body.data.user.id).toBe(mtlsUser.id);
      expect(response.body.data.user.provider).toBe('mtls');
    });

    it('should handle mTLS session logout', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      const agent = createMTLSAgent(true);

      // Logout
      const logoutResponse = await new Promise<any>((resolve, reject) => {
        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/api/v1/auth/logout',
          method: 'POST',
          agent: agent,
          headers: {
            'Authorization': `Bearer ${mtlsAccessToken}`,
          },
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
          });
        });

        req.on('error', reject);
        req.setTimeout(10000, () => reject(new Error('Request timeout')));
        req.end();
      });

      expect(logoutResponse.statusCode).toBe(200);
      expect(logoutResponse.body.success).toBe(true);

      // Verify token is invalidated
      const profileResponse = await new Promise<any>((resolve, reject) => {
        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/api/v1/auth/profile',
          method: 'GET',
          agent: agent,
          headers: {
            'Authorization': `Bearer ${mtlsAccessToken}`,
          },
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, body: data });
          });
        });

        req.on('error', reject);
        req.setTimeout(10000, () => reject(new Error('Request timeout')));
        req.end();
      });

      expect(profileResponse.statusCode).toBe(401);
    });
  });

  describe('mTLS Security and Validation', () => {
    it('should validate certificate expiration', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      // Create expired certificate user
      const userRepository = dataSource.getRepository(UserEntity);
      const expiredCertUser = await userRepository.save({
        id: 'expired-cert-user',
        email: 'expired@example.com',
        name: 'Expired Cert User',
        provider: 'mtls',
        certificate_fingerprint: 'expired-cert-fingerprint',
        certificate_expires_at: new Date(Date.now() - 24 * 60 * 60 * 1000), // Expired yesterday
        status: 'active',
        email_verified: true,
      });

      const agent = createMTLSAgent(true);

      const response = await new Promise<any>((resolve, reject) => {
        const postData = JSON.stringify({
          certificateFingerprint: 'expired-cert-fingerprint',
        });

        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/api/v1/auth/mtls/authenticate',
          method: 'POST',
          agent: agent,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
          });
        });

        req.on('error', reject);
        req.setTimeout(10000, () => reject(new Error('Request timeout')));
        req.write(postData);
        req.end();
      });

      expect(response.statusCode).toBe(401);
      expect(response.body.message).toContain('expired');
    });

    it('should handle certificate revocation', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      // Create revoked certificate user
      const userRepository = dataSource.getRepository(UserEntity);
      const revokedCertUser = await userRepository.save({
        id: 'revoked-cert-user',
        email: 'revoked@example.com',
        name: 'Revoked Cert User',
        provider: 'mtls',
        certificate_fingerprint: 'revoked-cert-fingerprint',
        certificate_status: 'revoked',
        status: 'active',
        email_verified: true,
      });

      const agent = createMTLSAgent(true);

      const response = await new Promise<any>((resolve, reject) => {
        const postData = JSON.stringify({
          certificateFingerprint: 'revoked-cert-fingerprint',
        });

        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/api/v1/auth/mtls/authenticate',
          method: 'POST',
          agent: agent,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
          });
        });

        req.on('error', reject);
        req.setTimeout(10000, () => reject(new Error('Request timeout')));
        req.write(postData);
        req.end();
      });

      expect(response.statusCode).toBe(401);
      expect(response.body.message).toContain('revoked');
    });

    it('should prevent certificate fingerprint spoofing', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      // Create legitimate user
      const userRepository = dataSource.getRepository(UserEntity);
      await userRepository.save({
        id: 'legitimate-user',
        email: 'legitimate@example.com',
        name: 'Legitimate User',
        provider: 'mtls',
        certificate_fingerprint: 'legitimate-cert-fingerprint',
        status: 'active',
        email_verified: true,
      });

      const agent = createMTLSAgent(true);

      // Try to authenticate with spoofed fingerprint
      const response = await new Promise<any>((resolve, reject) => {
        const postData = JSON.stringify({
          certificateFingerprint: 'legitimate-cert-fingerprint', // Spoofed
        });

        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/api/v1/auth/mtls/authenticate',
          method: 'POST',
          agent: agent,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
          });
        });

        req.on('error', reject);
        req.setTimeout(10000, () => reject(new Error('Request timeout')));
        req.write(postData);
        req.end();
      });

      // Should reject due to certificate mismatch
      expect(response.statusCode).toBe(401);
    });
  });

  describe('mTLS Performance and Reliability', () => {
    it('should handle multiple concurrent mTLS connections', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      // Create multiple users for concurrent testing
      const userRepository = dataSource.getRepository(UserEntity);
      const concurrentUsers = await Promise.all(
        Array.from({ length: 5 }, (_, i) =>
          userRepository.save({
            id: `concurrent-mtls-user-${i}`,
            email: `concurrent${i}@example.com`,
            name: `Concurrent mTLS User ${i}`,
            provider: 'mtls',
            certificate_fingerprint: `concurrent-cert-${i}`,
            status: 'active',
            email_verified: true,
          })
        )
      );

      const agent = createMTLSAgent(true);

      // Make concurrent authentication requests
      const authPromises = concurrentUsers.map((user, i) =>
        new Promise<any>((resolve, reject) => {
          const postData = JSON.stringify({
            certificateFingerprint: `concurrent-cert-${i}`,
          });

          const req = https.request({
            hostname: 'localhost',
            port: 3102,
            path: '/api/v1/auth/mtls/authenticate',
            method: 'POST',
            agent: agent,
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(postData),
            },
          }, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
              resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
            });
          });

          req.on('error', reject);
          req.setTimeout(15000, () => reject(new Error('Request timeout')));
          req.write(postData);
          req.end();
        })
      );

      const responses = await Promise.all(authPromises);

      // All should succeed
      responses.forEach((response, i) => {
        expect(response.statusCode).toBe(200);
        expect(response.body.data.user.id).toBe(`concurrent-mtls-user-${i}`);
      });
    });

    it('should handle mTLS connection timeouts gracefully', async () => {
      if (process.env.SECURITY_ENABLE_MTLS !== 'true') {
        console.log('Skipping mTLS test - mTLS not enabled');
        return;
      }

      const agent = createMTLSAgent(true);

      // Test with very short timeout
      await expect(new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'localhost',
          port: 3102,
          path: '/health',
          method: 'GET',
          agent: agent,
        }, resolve);

        req.on('error', reject);
        req.setTimeout(1, () => reject(new Error('Request timeout'))); // 1ms timeout
        req.end();
      })).rejects.toThrow('Request timeout');
    });
  });
});