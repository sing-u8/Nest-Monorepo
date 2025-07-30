/**
 * Jest Setup Configuration
 * 
 * Global test setup and configuration for the authentication service.
 * This file is executed before all test files.
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_ACCESS_SECRET = 'test-access-secret-key-for-jest';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key-for-jest';
process.env.DB_HOST = 'localhost';
process.env.DB_PORT = '5432';
process.env.DB_USERNAME = 'test';
process.env.DB_PASSWORD = 'test';
process.env.DB_DATABASE = 'auth_test';

// Configure global test timeout
jest.setTimeout(30000);

// Mock external services globally
jest.mock('@nestjs/axios', () => ({
  HttpService: jest.fn(),
  HttpModule: jest.fn(() => ({
    module: 'HttpModule',
  })),
}));

// Global mocks for external dependencies
global.console = {
  ...console,
  // Uncomment to suppress console logs during tests
  // log: jest.fn(),
  // debug: jest.fn(),
  // info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Setup global test utilities
beforeAll(() => {
  // Global setup logic
});

afterAll(() => {
  // Global cleanup logic
});

// Setup for each test
beforeEach(() => {
  // Clear all mocks before each test
  jest.clearAllMocks();
});

afterEach(() => {
  // Cleanup after each test
  jest.restoreAllMocks();
});

// Custom matchers for better assertions
expect.extend({
  toBeValidUUID(received: string) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const pass = uuidRegex.test(received);
    
    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid UUID`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid UUID`,
        pass: false,
      };
    }
  },
  
  toBeWithinTimeRange(received: Date, expected: Date, toleranceMs = 1000) {
    const timeDiff = Math.abs(received.getTime() - expected.getTime());
    const pass = timeDiff <= toleranceMs;
    
    if (pass) {
      return {
        message: () => `expected ${received} not to be within ${toleranceMs}ms of ${expected}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be within ${toleranceMs}ms of ${expected}, but was ${timeDiff}ms different`,
        pass: false,
      };
    }
  },
  
  toHaveValidJWTStructure(received: string) {
    const jwtParts = received.split('.');
    const pass = jwtParts.length === 3;
    
    if (pass) {
      return {
        message: () => `expected ${received} not to have valid JWT structure`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to have valid JWT structure (3 parts separated by dots)`,
        pass: false,
      };
    }
  },
});

// Extend Jest matchers type definition
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidUUID(): R;
      toBeWithinTimeRange(expected: Date, toleranceMs?: number): R;
      toHaveValidJWTStructure(): R;
    }
  }
}