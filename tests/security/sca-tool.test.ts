import { jest } from '@jest/globals';
import { SCATool } from '../../src/mcp/tools/sca-tool';
import * as childProcess from 'child_process';

// Mock dependencies
jest.mock('child_process');
jest.mock('../../src/mcp/connectors/snyk');

const mockSpawn = childProcess.spawn as jest.MockedFunction<typeof childProcess.spawn>;

describe('SCATool', () => {
  let scaTool: SCATool;

  beforeEach(() => {
    scaTool = new SCATool();
    jest.clearAllMocks();
  });

  describe('executeScan', () => {
    it('should validate required parameters', async () => {
      const invalidParams = {};
      
      const result = await scaTool.executeScan(invalidParams as any);
      
      expect(result.content[0].text).toContain('Invalid parameters');
      expect(result.content[0].text).toContain('project_path');
    });

    it('should detect package manager automatically', async () => {
      const params = {
        project_path: '/test/project'
      };

      // Mock file system
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['package.json', 'package-lock.json'])
        }
      }));

      const mockSnykResult = {
        ok: false,
        vulnerabilities: [
          {
            id: 'SNYK-JS-LODASH-567746',
            title: 'Prototype Pollution',
            severity: 'high',
            packageName: 'lodash',
            version: '4.17.15',
            from: ['test@1.0.0', 'lodash@4.17.15'],
            upgradePath: ['false'],
            isUpgradable: false,
            isPatchable: false
          }
        ],
        dependencyCount: 100,
        uniqueCount: 1
      };

      const mockSnykConnector = {
        executeScan: jest.fn().mockResolvedValue(mockSnykResult)
      };

      (scaTool as any).snykConnector = mockSnykConnector;

      const result = await scaTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.tool).toBe('Snyk');
      expect(scanResult.package_manager).toBe('npm');
      expect(scanResult.vulnerabilities).toHaveLength(1);
    });

    it('should execute npm audit scan', async () => {
      const params = {
        project_path: '/test/project',
        package_manager: 'npm' as const,
        tool: 'npm-audit' as const
      };

      // Mock file system
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true })
        }
      }));

      const mockAuditOutput = {
        vulnerabilities: {
          'lodash': {
            name: 'lodash',
            severity: 'high',
            via: [{
              url: 'https://npmjs.com/advisories/1065',
              title: 'Prototype Pollution',
              range: '<4.17.19'
            }],
            fixAvailable: {
              name: 'lodash',
              version: '4.17.21'
            }
          }
        },
        metadata: {
          dependencies: 100,
          devDependencies: 50
        }
      };

      const mockProcess = {
        stdout: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback(JSON.stringify(mockAuditOutput));
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

      const result = await scaTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.tool).toBe('npm audit');
      expect(scanResult.status).toBe('completed');
      expect(scanResult.vulnerabilities).toHaveLength(1);
      expect(scanResult.vulnerabilities[0].fix_available).toBe(true);
    });

    it('should filter vulnerabilities by severity threshold', async () => {
      const params = {
        project_path: '/test/project',
        severity_threshold: 'high' as const
      };

      const mockSnykResult = {
        ok: false,
        vulnerabilities: [
          {
            id: 'critical-vuln',
            severity: 'critical',
            packageName: 'test-package-1'
          },
          {
            id: 'high-vuln',
            severity: 'high',
            packageName: 'test-package-2'
          },
          {
            id: 'medium-vuln',
            severity: 'medium',
            packageName: 'test-package-3'
          },
          {
            id: 'low-vuln',
            severity: 'low',
            packageName: 'test-package-4'
          }
        ],
        dependencyCount: 50,
        uniqueCount: 4
      };

      const mockSnykConnector = {
        executeScan: jest.fn().mockResolvedValue(mockSnykResult)
      };

      (scaTool as any).snykConnector = mockSnykConnector;

      // Mock file system
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['package.json'])
        }
      }));

      const result = await scaTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      // Should only include critical and high severity vulnerabilities
      expect(scanResult.vulnerabilities).toHaveLength(2);
      expect(scanResult.vulnerabilities.every((v: any) => 
        v.severity === 'critical' || v.severity === 'high'
      )).toBe(true);
    });

    it('should apply automatic fixes when enabled', async () => {
      const params = {
        project_path: '/test/project',
        fix_vulnerabilities: true,
        package_manager: 'npm' as const
      };

      const mockSnykResult = {
        ok: false,
        vulnerabilities: [
          {
            id: 'fixable-vuln',
            severity: 'medium',
            packageName: 'test-package',
            isUpgradable: true,
            fixedIn: ['1.2.3']
          }
        ],
        dependencyCount: 10,
        uniqueCount: 1
      };

      const mockSnykConnector = {
        executeScan: jest.fn().mockResolvedValue(mockSnykResult)
      };

      (scaTool as any).snykConnector = mockSnykConnector;

      // Mock file system
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['package.json'])
        }
      }));

      // Mock npm audit fix
      const mockFixProcess = {
        on: jest.fn((event, callback) => {
          if (event === 'close') {
            callback(0); // Success
          }
        })
      };

      mockSpawn
        .mockReturnValueOnce(mockFixProcess as any); // For fix command

      const result = await scaTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.status).toBe('completed');
      expect(mockSpawn).toHaveBeenCalledWith(
        'npm',
        expect.arrayContaining(['audit', 'fix', '--force']),
        expect.any(Object)
      );
    });

    it('should generate SBOM when requested', async () => {
      const params = {
        project_path: '/test/project',
        generate_sbom: true
      };

      const mockSnykResult = {
        ok: true,
        vulnerabilities: [],
        dependencyCount: 25,
        sbom: {
          components: [
            {
              name: 'lodash',
              version: '4.17.21',
              purl: 'pkg:npm/lodash@4.17.21',
              licenses: ['MIT']
            }
          ]
        }
      };

      const mockSnykConnector = {
        executeScan: jest.fn().mockResolvedValue(mockSnykResult)
      };

      (scaTool as any).snykConnector = mockSnykConnector;

      // Mock file system
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['package.json'])
        }
      }));

      const result = await scaTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.sbom).toBeDefined();
      expect(scanResult.sbom.components).toHaveLength(1);
      expect(scanResult.sbom.components[0].name).toBe('lodash');
    });

    it('should check license compliance', async () => {
      const params = {
        project_path: '/test/project',
        license_check: true
      };

      const mockSnykResult = {
        ok: true,
        vulnerabilities: [],
        licenseIssues: [
          {
            id: 'license-violation-1',
            packageName: 'gpl-package',
            version: '1.0.0',
            license: 'GPL-3.0',
            severity: 'high',
            policyViolation: 'Copyleft license not allowed'
          }
        ],
        dependencyCount: 10
      };

      const mockSnykConnector = {
        executeScan: jest.fn().mockResolvedValue(mockSnykResult)
      };

      (scaTool as any).snykConnector = mockSnykConnector;

      // Mock file system
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['package.json'])
        }
      }));

      const result = await scaTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.license_issues).toHaveLength(1);
      expect(scanResult.summary.license_violations).toBe(1);
      expect(scanResult.license_issues[0].license).toBe('GPL-3.0');
    });
  });

  describe('package manager detection', () => {
    it('should detect Maven projects', async () => {
      // Mock file system to simulate Maven project
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['pom.xml'])
        }
      }));

      const tool = new SCATool();
      const packageManager = await (tool as any).detectPackageManager('/test/maven-project');

      expect(packageManager).toBe('maven');
    });

    it('should detect Gradle projects', async () => {
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['build.gradle'])
        }
      }));

      const tool = new SCATool();
      const packageManager = await (tool as any).detectPackageManager('/test/gradle-project');

      expect(packageManager).toBe('gradle');
    });

    it('should detect Python projects', async () => {
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['requirements.txt'])
        }
      }));

      const tool = new SCATool();
      const packageManager = await (tool as any).detectPackageManager('/test/python-project');

      expect(packageManager).toBe('pip');
    });

    it('should prefer yarn over npm when both lockfiles exist', async () => {
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['package.json', 'yarn.lock', 'package-lock.json'])
        }
      }));

      const tool = new SCATool();
      const packageManager = await (tool as any).detectPackageManager('/test/js-project');

      expect(packageManager).toBe('yarn');
    });
  });

  describe('error handling', () => {
    it('should handle invalid project path', async () => {
      const params = {
        project_path: '/nonexistent/path'
      };

      const result = await scaTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.message).toContain('Invalid project path');
    });

    it('should handle Snyk connector failures', async () => {
      const params = {
        project_path: '/test/project'
      };

      const mockSnykConnector = {
        executeScan: jest.fn().mockRejectedValue(new Error('Snyk API error'))
      };

      (scaTool as any).snykConnector = mockSnykConnector;

      // Mock file system
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['package.json'])
        }
      }));

      const result = await scaTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.message).toContain('Snyk API error');
    });

    it('should handle npm audit failures gracefully', async () => {
      const params = {
        project_path: '/test/project',
        package_manager: 'npm' as const,
        tool: 'npm-audit' as const
      };

      // Mock file system
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true })
        }
      }));

      const mockProcess = {
        stdout: { on: jest.fn() },
        stderr: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback('npm audit failed');
            }
          })
        },
        on: jest.fn((event, callback) => {
          if (event === 'close') {
            callback(1); // Error exit code
          }
        })
      };

      mockSpawn.mockReturnValue(mockProcess as any);

      const result = await scaTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
    });

    it('should handle package manager detection failure', async () => {
      const params = {
        project_path: '/test/unknown-project'
      };

      // Mock file system with no recognizable files
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['README.md'])
        }
      }));

      const result = await scaTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.message).toContain('Unable to detect package manager');
    });
  });

  describe('vulnerability remediation', () => {
    it('should provide upgrade recommendations', async () => {
      const params = {
        project_path: '/test/project'
      };

      const mockSnykResult = {
        ok: false,
        vulnerabilities: [
          {
            id: 'upgradable-vuln',
            severity: 'medium',
            packageName: 'old-package',
            version: '1.0.0',
            isUpgradable: true,
            upgradePath: ['old-package@2.0.0']
          }
        ],
        remediation: {
          upgrades: [
            {
              package_name: 'old-package',
              from: '1.0.0',
              to: '2.0.0',
              fixes: ['upgradable-vuln']
            }
          ],
          patches: []
        },
        dependencyCount: 5
      };

      const mockSnykConnector = {
        executeScan: jest.fn().mockResolvedValue(mockSnykResult)
      };

      (scaTool as any).snykConnector = mockSnykConnector;

      // Mock file system
      jest.doMock('fs', () => ({
        promises: {
          stat: jest.fn().mockResolvedValue({ isDirectory: () => true }),
          readdir: jest.fn().mockResolvedValue(['package.json'])
        }
      }));

      const result = await scaTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.remediation.upgrades).toHaveLength(1);
      expect(scanResult.remediation.upgrades[0].to).toBe('2.0.0');
      expect(scanResult.summary.fixable).toBe(1);
    });
  });
});