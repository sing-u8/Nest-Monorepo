import { config } from 'dotenv';
import { join } from 'path';

// Load test environment variables
config({ path: join(__dirname, '../../.env.test') });

// Global test setup
beforeAll(() => {
  // Set global test timeout
  jest.setTimeout(60000);
});

// Global test teardown
afterAll(async () => {
  // Clean up any global resources
  await new Promise(resolve => setTimeout(resolve, 1000));
});

// Suppress console output during tests unless needed
const originalConsole = console;
if (process.env.TEST_VERBOSE !== 'true') {
  console.log = jest.fn();
  console.info = jest.fn();
  console.warn = jest.fn();
  console.error = originalConsole.error; // Keep error logs
}