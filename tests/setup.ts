import { jest } from '@jest/globals';

// Global test setup
beforeAll(() => {
  // Set test environment variables
  process.env.NODE_ENV = 'test';
  process.env.LOG_LEVEL = 'error';
  process.env.SECURITY_STRICT_MODE = 'true';
  
  // Mock API credentials for testing
  process.env.SONARQUBE_TOKEN = 'test-sonar-token';
  process.env.SNYK_TOKEN = 'test-snyk-token';
  process.env.ZAP_API_KEY = 'test-zap-key';
  process.env.VERACODE_API_ID = 'test-veracode-id';
  process.env.VERACODE_API_KEY = 'test-veracode-key';
});

// Global test cleanup
afterAll(() => {
  // Clean up any resources if needed
});

// Mock external dependencies
jest.mock('axios');
jest.mock('child_process');
jest.mock('winston', () => ({
  createLogger: jest.fn(() => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  })),
  format: {
    combine: jest.fn(),
    timestamp: jest.fn(),
    errors: jest.fn(),
    json: jest.fn()
  },
  transports: {
    Console: jest.fn(),
    File: jest.fn()
  }
}));

// Increase timeout for integration tests
jest.setTimeout(30000);