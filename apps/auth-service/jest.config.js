const { getJestConfig } = require('@nx/jest');

module.exports = {
  ...getJestConfig(),
  displayName: 'auth-service',
  preset: '../../jest.preset.js',
  testEnvironment: 'node',
  transform: {
    '^.+\\.[tj]s$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.spec.json' }],
  },
  moduleFileExtensions: ['ts', 'js', 'html'],
  coverageDirectory: '../../coverage/apps/auth-service',
  collectCoverageFrom: [
    'src/**/*.{ts,js}',
    '!src/**/*.spec.ts',
    '!src/**/*.e2e-spec.ts',
    '!src/**/*.integration.spec.ts',
    '!src/main.ts',
    '!src/test/**/*',
    '!src/**/*.interface.ts',
    '!src/**/*.module.ts',
    '!src/**/*.config.ts',
    '!src/infrastructure/database/migrations/**/*',
    '!src/infrastructure/database/data-source.ts',
  ],
  coverageReporters: ['html', 'text', 'text-summary', 'lcov', 'json'],
  coverageThreshold: {
    global: {
      branches: 85,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    // Individual file thresholds
    './src/domain/entities/*.ts': {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95,
    },
    './src/domain/use-cases/*.ts': {
      branches: 90,
      functions: 95,
      lines: 95,
      statements: 95,
    },
    './src/infrastructure/services/*.ts': {
      branches: 85,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    './src/infrastructure/repositories/*.ts': {
      branches: 85,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    './src/infrastructure/controllers/*.ts': {
      branches: 80,
      functions: 85,
      lines: 85,
      statements: 85,
    },
  },
  testMatch: [
    '<rootDir>/src/**/__tests__/**/*.(test|spec).{js,ts}',
    '<rootDir>/src/**/*.(test|spec).{js,ts}',
    '<rootDir>/test/**/*.(test|spec|e2e-spec).{js,ts}',
  ],
  setupFilesAfterEnv: ['<rootDir>/src/test/setup.ts'],
  testTimeout: 30000,
  maxWorkers: 4,
  // Separate test configurations for different test types
  projects: [
    {
      displayName: 'unit',
      testMatch: ['<rootDir>/src/**/*.spec.ts'],
      testEnvironment: 'node',
    },
    {
      displayName: 'integration',
      testMatch: ['<rootDir>/src/**/*.integration.spec.ts'],
      testEnvironment: 'node',
      testTimeout: 60000,
    },
    {
      displayName: 'e2e',
      testMatch: ['<rootDir>/test/**/*.e2e-spec.ts'],
      testEnvironment: 'node',
      testTimeout: 120000,
    },
  ],
  // Global test configuration
  globals: {
    'ts-jest': {
      tsconfig: '<rootDir>/tsconfig.spec.json',
    },
  },
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@domain/(.*)$': '<rootDir>/src/domain/$1',
    '^@infrastructure/(.*)$': '<rootDir>/src/infrastructure/$1',
    '^@shared/(.*)$': '<rootDir>/src/shared/$1',
  },
};