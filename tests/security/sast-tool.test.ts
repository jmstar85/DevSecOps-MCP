import { jest } from '@jest/globals';
import { SASTTool } from '../../src/mcp/tools/sast-tool';
import * as childProcess from 'child_process';

// Mock dependencies
jest.mock('child_process');
jest.mock('../../src/mcp/connectors/sonarqube');

const mockSpawn = childProcess.spawn as jest.MockedFunction<typeof childProcess.spawn>;

describe('SASTTool', () => {
  let sastTool: SASTTool;

  beforeEach(() => {
    sastTool = new SASTTool();
    jest.clearAllMocks();
  });

  describe('executeScan', () => {
    it('should validate required parameters', async () => {
      const invalidParams = {};
      
      const result = await sastTool.executeScan(invalidParams as any);
      
      expect(result.content[0].text).toContain('Invalid parameters');
      expect(result.content[0].text).toContain('target');
    });

    it('should execute semgrep scan successfully', async () => {
      const params = {
        target: '/test/project',
        tool: 'semgrep' as const
      };

      // Mock semgrep process
      const mockProcess = {
        stdout: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback(JSON.stringify({
                results: [
                  {
                    check_id: 'test-rule-1',
                    message: 'Test vulnerability',
                    path: '/test/file.js',
                    start: { line: 10 },
                    extra: {
                      severity: 'ERROR',
                      message: 'SQL injection vulnerability',
                      metadata: { category: 'security' }
                    }
                  }
                ]
              }));
            }
          })
        },
        stderr: {
          on: jest.fn()
        },
        on: jest.fn((event, callback) => {
          if (event === 'close') {
            callback(0);
          }
        })
      };

      mockSpawn.mockReturnValue(mockProcess as any);

      const result = await sastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.tool).toBe('Semgrep');
      expect(scanResult.status).toBe('completed');
      expect(scanResult.vulnerabilities).toHaveLength(1);
      expect(scanResult.vulnerabilities[0].id).toBe('test-rule-1');
      expect(scanResult.vulnerabilities[0].severity).toBe('high');
    });

    it('should handle semgrep scan failure', async () => {
      const params = {
        target: '/test/project',
        tool: 'semgrep' as const
      };

      const mockProcess = {
        stdout: { on: jest.fn() },
        stderr: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback('Semgrep error');
            }
          })
        },
        on: jest.fn((event, callback) => {
          if (event === 'close') {
            callback(2); // Non-zero exit code
          }
        })
      };

      mockSpawn.mockReturnValue(mockProcess as any);

      const result = await sastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.error).toBe('SAST scan failed');
    });

    it('should filter vulnerabilities by severity threshold', async () => {
      const params = {
        target: '/test/project',
        tool: 'semgrep' as const,
        severity_threshold: 'high' as const
      };

      const mockProcess = {
        stdout: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback(JSON.stringify({
                results: [
                  {
                    check_id: 'high-severity',
                    path: '/test/file.js',
                    start: { line: 10 },
                    extra: { severity: 'ERROR', message: 'High severity issue' }
                  },
                  {
                    check_id: 'medium-severity',
                    path: '/test/file.js',
                    start: { line: 20 },
                    extra: { severity: 'WARNING', message: 'Medium severity issue' }
                  },
                  {
                    check_id: 'low-severity',
                    path: '/test/file.js',
                    start: { line: 30 },
                    extra: { severity: 'INFO', message: 'Low severity issue' }
                  }
                ]
              }));
            }
          })
        },
        stderr: { on: jest.fn() },
        on: jest.fn((event, callback) => {
          if (event === 'close') {
            callback(0);
          }
        })
      };

      mockSpawn.mockReturnValue(mockProcess as any);

      const result = await sastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      // Should only include high severity vulnerabilities
      expect(scanResult.vulnerabilities).toHaveLength(1);
      expect(scanResult.vulnerabilities[0].severity).toBe('high');
      expect(scanResult.summary.total).toBe(1);
    });

    it('should validate target path exists', async () => {
      const params = {
        target: '/nonexistent/path'
      };

      const result = await sastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.message).toContain('Invalid target');
    });

    it('should detect best tool automatically', async () => {
      const params = {
        target: '/test/project'
      };

      // Mock file system to simulate package.json
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['package.json'])
        }
      }));

      const mockProcess = {
        stdout: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback(JSON.stringify({ results: [] }));
            }
          })
        },
        stderr: { on: jest.fn() },
        on: jest.fn((event, callback) => {
          if (event === 'close') {
            callback(0);
          }
        })
      };

      mockSpawn.mockReturnValue(mockProcess as any);

      const result = await sastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.tool).toBe('Semgrep');
    });
  });

  describe('vulnerability mapping', () => {
    it('should correctly map semgrep severity levels', () => {
      const tool = new SASTTool();
      
      // Access private method for testing
      const mapSeverity = (tool as any).mapSemgrepSeverity.bind(tool);
      
      expect(mapSeverity('ERROR')).toBe('high');
      expect(mapSeverity('WARNING')).toBe('medium');
      expect(mapSeverity('INFO')).toBe('low');
      expect(mapSeverity('UNKNOWN')).toBe('medium');
    });

    it('should generate vulnerability summary correctly', () => {
      const vulnerabilities = [
        { severity: 'critical' },
        { severity: 'high' },
        { severity: 'high' },
        { severity: 'medium' },
        { severity: 'low' }
      ];

      const tool = new SASTTool();
      const summary = (tool as any).calculateSummaryFromVulnerabilities(vulnerabilities);

      expect(summary.total).toBe(5);
      expect(summary.critical).toBe(1);
      expect(summary.high).toBe(2);
      expect(summary.medium).toBe(1);
      expect(summary.low).toBe(1);
    });
  });

  describe('error handling', () => {
    it('should handle JSON parsing errors gracefully', async () => {
      const params = {
        target: '/test/project',
        tool: 'semgrep' as const
      };

      const mockProcess = {
        stdout: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback('invalid json');
            }
          })
        },
        stderr: { on: jest.fn() },
        on: jest.fn((event, callback) => {
          if (event === 'close') {
            callback(0);
          }
        })
      };

      mockSpawn.mockReturnValue(mockProcess as any);

      const result = await sastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.message).toContain('parse');
    });

    it('should handle process spawn errors', async () => {
      const params = {
        target: '/test/project',
        tool: 'semgrep' as const
      };

      mockSpawn.mockImplementation(() => {
        throw new Error('spawn failed');
      });

      const result = await sastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.message).toContain('spawn failed');
    });
  });
});