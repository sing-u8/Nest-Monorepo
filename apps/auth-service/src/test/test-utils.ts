import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';

// Domain entities
import { User } from '../domain/entities/user.entity';
import { Token } from '../domain/entities/token.entity';
import { AuthSession } from '../domain/entities/auth-session.entity';

/**
 * Test utilities and helper functions
 * 
 * Provides common test utilities, mock factories, and helper functions
 * for consistent testing across the authentication service.
 */

/**
 * Create a mock repository
 */
export function createMockRepository<T>(): jest.Mocked<Repository<T>> {
  return {
    find: jest.fn(),
    findOne: jest.fn(),
    findOneBy: jest.fn(),
    save: jest.fn(),
    remove: jest.fn(),
    delete: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    count: jest.fn(),
    query: jest.fn(),
    createQueryBuilder: jest.fn(() => ({
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      leftJoinAndSelect: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      offset: jest.fn().mockReturnThis(),
      getOne: jest.fn(),
      getMany: jest.fn(),
      getManyAndCount: jest.fn(),
      execute: jest.fn(),
    })),
  } as unknown as jest.Mocked<Repository<T>>;
}

/**
 * Create a test user entity
 */
export function createTestUser(overrides?: Partial<User>): User {
  const user = new User(
    uuidv4(),
    `test.user.${Date.now()}@example.com`,
    'hashedPassword123',
    'Test User',
    overrides?.profilePicture || null,
    overrides?.isActive ?? true,
    overrides?.emailVerified ?? false,
    overrides?.authProvider || 'LOCAL',
    overrides?.providerId || null,
    overrides?.lastLoginAt || null,
    overrides?.createdAt || new Date(),
    overrides?.updatedAt || new Date()
  );

  return user;
}

/**
 * Create a test token entity
 */
export function createTestToken(userId: string, type: 'ACCESS' | 'REFRESH', overrides?: Partial<Token>): Token {
  const token = new Token(
    uuidv4(),
    userId,
    type,
    `test.token.${Date.now()}.${Math.random().toString(36).substr(2, 9)}`,
    overrides?.expiresAt || new Date(Date.now() + (type === 'ACCESS' ? 900000 : 604800000)), // 15m or 7d
    overrides?.isRevoked ?? false,
    overrides?.revokedAt || null,
    overrides?.createdAt || new Date(),
    overrides?.updatedAt || new Date()
  );

  return token;
}

/**
 * Create a test auth session entity
 */
export function createTestAuthSession(userId: string, overrides?: Partial<AuthSession>): AuthSession {
  const session = new AuthSession(
    uuidv4(),
    userId,
    `session.${Date.now()}.${Math.random().toString(36).substr(2, 9)}`,
    overrides?.clientInfo || {
      userAgent: 'Test-Agent/1.0',
      ipAddress: '192.168.1.1',
      deviceId: 'test-device-123',
    },
    overrides?.expiresAt || new Date(Date.now() + 86400000), // 24 hours
    overrides?.lastActivityAt || new Date(),
    overrides?.isRevoked ?? false,
    overrides?.revokedAt || null,
    overrides?.createdAt || new Date(),
    overrides?.updatedAt || new Date()
  );

  return session;
}

/**
 * Create a mock JWT service
 */
export function createMockJwtService(): jest.Mocked<JwtService> {
  return {
    sign: jest.fn((payload) => `mock.jwt.token.${JSON.stringify(payload)}`),
    signAsync: jest.fn((payload) => Promise.resolve(`mock.jwt.token.${JSON.stringify(payload)}`)),
    verify: jest.fn((token) => ({ sub: 'user123', email: 'test@example.com' })),
    verifyAsync: jest.fn((token) => Promise.resolve({ sub: 'user123', email: 'test@example.com' })),
    decode: jest.fn((token) => ({ sub: 'user123', email: 'test@example.com' })),
  } as unknown as jest.Mocked<JwtService>;
}

/**
 * Create a mock config service
 */
export function createMockConfigService(config: Record<string, any> = {}): jest.Mocked<ConfigService> {
  const defaultConfig = {
    jwt: {
      accessToken: {
        secret: 'test-access-secret',
        expiresIn: '15m',
      },
      refreshToken: {
        secret: 'test-refresh-secret',
        expiresIn: '7d',
      },
    },
    oauth: {
      google: {
        clientId: 'test-google-client-id',
        clientSecret: 'test-google-client-secret',
        redirectUri: 'http://localhost:3000/auth/google/callback',
      },
      apple: {
        clientId: 'test-apple-client-id',
        teamId: 'test-apple-team-id',
        keyId: 'test-apple-key-id',
        privateKey: 'test-apple-private-key',
        redirectUri: 'http://localhost:3000/auth/apple/callback',
      },
    },
    security: {
      bcrypt: {
        saltRounds: 10,
      },
    },
    ...config,
  };

  return {
    get: jest.fn((key: string) => {
      const keys = key.split('.');
      let value = defaultConfig;
      for (const k of keys) {
        value = value[k];
        if (value === undefined) break;
      }
      return value;
    }),
  } as unknown as jest.Mocked<ConfigService>;
}

/**
 * Create a test module with common providers
 */
export async function createTestModule(
  moduleMetadata: {
    controllers?: any[];
    providers?: any[];
    imports?: any[];
  }
): Promise<TestingModule> {
  const module = await Test.createTestingModule({
    imports: [
      ConfigModule.forRoot({
        isGlobal: true,
        load: [],
      }),
      ...(moduleMetadata.imports || []),
    ],
    controllers: moduleMetadata.controllers || [],
    providers: [
      {
        provide: ConfigService,
        useValue: createMockConfigService(),
      },
      ...(moduleMetadata.providers || []),
    ],
  }).compile();

  return module;
}

/**
 * Mock HTTP request object
 */
export function createMockRequest(overrides?: any): any {
  return {
    headers: {
      'user-agent': 'Test-Agent/1.0',
      'x-forwarded-for': '192.168.1.1',
      ...overrides?.headers,
    },
    connection: {
      remoteAddress: '192.168.1.1',
    },
    user: overrides?.user,
    body: overrides?.body || {},
    params: overrides?.params || {},
    query: overrides?.query || {},
    ...overrides,
  };
}

/**
 * Mock HTTP response object
 */
export function createMockResponse(): any {
  const response = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    header: jest.fn().mockReturnThis(),
    setHeader: jest.fn().mockReturnThis(),
  };
  return response;
}

/**
 * Wait for a specific condition to be true
 */
export async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeout = 5000,
  interval = 100
): Promise<void> {
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    if (await condition()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, interval));
  }
  
  throw new Error(`Timeout waiting for condition after ${timeout}ms`);
}

/**
 * Generate a random email address
 */
export function generateRandomEmail(): string {
  return `test.${Date.now()}.${Math.random().toString(36).substr(2, 9)}@example.com`;
}

/**
 * Generate a valid JWT token for testing
 */
export function generateTestJwtToken(payload: any, secret = 'test-secret'): string {
  // This is a simplified mock JWT for testing
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64');
  const signature = Buffer.from(`signature.${secret}`).toString('base64');
  
  return `${header}.${body}.${signature}`;
}

/**
 * Create a mock repository with common operations
 */
export function createMockRepositoryWithDefaults<T>(entities: T[] = []): jest.Mocked<Repository<T>> {
  const repository = createMockRepository<T>();
  
  repository.find.mockResolvedValue(entities);
  repository.findOne.mockImplementation((options) => {
    if (options?.where?.id) {
      const entity = entities.find((e: any) => e.id === options.where.id);
      return Promise.resolve(entity || null);
    }
    return Promise.resolve(null);
  });
  
  repository.save.mockImplementation((entity) => {
    if (Array.isArray(entity)) {
      return Promise.resolve(entity);
    }
    return Promise.resolve({ ...entity, id: entity.id || uuidv4() });
  });
  
  repository.delete.mockResolvedValue({ affected: 1, raw: {} });
  
  return repository;
}

/**
 * Assert that a promise rejects with a specific error
 */
export async function expectRejectsWithError(
  promise: Promise<any>,
  errorType: any,
  errorMessage?: string
): Promise<void> {
  try {
    await promise;
    throw new Error('Expected promise to reject, but it resolved');
  } catch (error) {
    expect(error).toBeInstanceOf(errorType);
    if (errorMessage) {
      expect(error.message).toBe(errorMessage);
    }
  }
}