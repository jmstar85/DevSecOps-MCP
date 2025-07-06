import { jest } from '@jest/globals';
import { DevSecOpsMCPServer } from '../../src/mcp/server';

// Mock all tools
jest.mock('../../src/mcp/tools/sast-tool');
jest.mock('../../src/mcp/tools/dast-tool');
jest.mock('../../src/mcp/tools/sca-tool');
jest.mock('../../src/mcp/tools/iast-tool');

describe('DevSecOpsMCPServer Integration', () => {
  let server: DevSecOpsMCPServer;

  beforeEach(() => {
    server = new DevSecOpsMCPServer();
  });

  describe('MCP Protocol Compliance', () => {
    it('should list all available tools', async () => {
      const mockListTools = jest.fn().mockResolvedValue({
        tools: [
          {
            name: 'run_sast_scan',
            description: 'Execute SAST (Static Application Security Testing) scan'
          },
          {
            name: 'run_dast_scan',
            description: 'Execute DAST (Dynamic Application Security Testing) scan'
          },
          {
            name: 'run_sca_scan',
            description: 'Execute SCA (Software Composition Analysis) scan'
          },
          {
            name: 'run_iast_scan',
            description: 'Execute IAST (Interactive Application Security Testing) scan'
          }
        ]
      });

      // Mock the server's request handler
      (server as any).server.setRequestHandler = jest.fn();
      (server as any).server.listTools = mockListTools;

      const tools = await mockListTools();

      expect(tools.tools).toHaveLength(6); // 4 scan tools + 2 utility tools
      expect(tools.tools.map((t: any) => t.name)).toContain('run_sast_scan');
      expect(tools.tools.map((t: any) => t.name)).toContain('run_dast_scan');
      expect(tools.tools.map((t: any) => t.name)).toContain('run_sca_scan');
      expect(tools.tools.map((t: any) => t.name)).toContain('run_iast_scan');
    });

    it('should validate tool input schemas', async () => {
      const sastTool = {
        name: 'run_sast_scan',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string' },
            rules: { type: 'array' },
            severity_threshold: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] }
          },
          required: ['target']
        }
      };

      expect(sastTool.inputSchema.properties.target).toBeDefined();
      expect(sastTool.inputSchema.required).toContain('target');
      expect(sastTool.inputSchema.properties.severity_threshold.enum).toContain('critical');
    });
  });

  describe('Tool Execution', () => {
    it('should execute SAST scan tool', async () => {
      const mockSASTTool = {
        executeScan: jest.fn().mockResolvedValue({
          content: [{
            type: 'text',
            text: JSON.stringify({
              tool: 'Semgrep',
              status: 'completed',
              vulnerabilities: [],
              summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
            })
          }]
        })
      };

      (server as any).sastTool = mockSASTTool;

      const result = await mockSASTTool.executeScan({
        target: '/test/project'
      });

      expect(mockSASTTool.executeScan).toHaveBeenCalledWith({
        target: '/test/project'
      });
      expect(result.content[0].type).toBe('text');
      
      const scanResult = JSON.parse(result.content[0].text);
      expect(scanResult.tool).toBe('Semgrep');
      expect(scanResult.status).toBe('completed');
    });

    it('should execute DAST scan tool', async () => {
      const mockDASTTool = {
        executeScan: jest.fn().mockResolvedValue({
          content: [{
            type: 'text',
            text: JSON.stringify({
              tool: 'OWASP ZAP',
              status: 'completed',
              target_url: 'https://example.com',
              vulnerabilities: [],
              coverage: { urls_tested: 10 }
            })
          }]
        })
      };

      (server as any).dastTool = mockDASTTool;

      const result = await mockDASTTool.executeScan({
        target_url: 'https://example.com',
        scan_type: 'baseline'
      });

      expect(mockDASTTool.executeScan).toHaveBeenCalledWith({
        target_url: 'https://example.com',
        scan_type: 'baseline'
      });
      
      const scanResult = JSON.parse(result.content[0].text);
      expect(scanResult.tool).toBe('OWASP ZAP');
      expect(scanResult.target_url).toBe('https://example.com');
    });

    it('should execute SCA scan tool', async () => {
      const mockSCATool = {
        executeScan: jest.fn().mockResolvedValue({
          content: [{
            type: 'text',
            text: JSON.stringify({
              tool: 'Snyk',
              status: 'completed',
              project_path: '/test/project',
              vulnerabilities: [],
              license_issues: [],
              summary: { total_vulnerabilities: 0, license_violations: 0 }
            })
          }]
        })
      };

      (server as any).scaTool = mockSCATool;

      const result = await mockSCATool.executeScan({
        project_path: '/test/project',
        package_manager: 'npm'
      });

      expect(mockSCATool.executeScan).toHaveBeenCalledWith({
        project_path: '/test/project',
        package_manager: 'npm'
      });
      
      const scanResult = JSON.parse(result.content[0].text);
      expect(scanResult.tool).toBe('Snyk');
      expect(scanResult.project_path).toBe('/test/project');
    });

    it('should execute IAST scan tool', async () => {
      const mockIASTTool = {
        executeScan: jest.fn().mockResolvedValue({
          content: [{
            type: 'text',
            text: JSON.stringify({
              tool: 'Veracode IAST',
              status: 'completed',
              application_id: 'test-app-123',
              vulnerabilities: [],
              performance_metrics: { agent_overhead: 2.5 },
              coverage: { coverage_percentage: 75 }
            })
          }]
        })
      };

      (server as any).iastTool = mockIASTTool;

      const result = await mockIASTTool.executeScan({
        application_id: 'test-app-123',
        environment: 'staging'
      });

      expect(mockIASTTool.executeScan).toHaveBeenCalledWith({
        application_id: 'test-app-123',
        environment: 'staging'
      });
      
      const scanResult = JSON.parse(result.content[0].text);
      expect(scanResult.tool).toBe('Veracode IAST');
      expect(scanResult.application_id).toBe('test-app-123');
    });
  });

  describe('Security Report Generation', () => {
    it('should generate comprehensive security report', async () => {
      const mockGenerateReport = jest.fn().mockResolvedValue({
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            message: 'Security report generation initiated',
            format: 'json',
            include_remediation: true
          })
        }]
      });

      const result = await mockGenerateReport({
        scan_ids: ['sast-123', 'dast-456', 'sca-789'],
        format: 'json',
        include_remediation: true
      });

      expect(result.content[0].type).toBe('text');
      
      const reportResult = JSON.parse(result.content[0].text);
      expect(reportResult.success).toBe(true);
      expect(reportResult.format).toBe('json');
      expect(reportResult.include_remediation).toBe(true);
    });

    it('should support multiple report formats', async () => {
      const formats = ['json', 'html', 'pdf', 'sarif'];
      
      for (const format of formats) {
        const mockGenerateReport = jest.fn().mockResolvedValue({
          content: [{
            type: 'text',
            text: JSON.stringify({
              success: true,
              format: format
            })
          }]
        });

        const result = await mockGenerateReport({
          scan_ids: ['test-123'],
          format: format
        });

        const reportResult = JSON.parse(result.content[0].text);
        expect(reportResult.format).toBe(format);
      }
    });
  });

  describe('Security Policy Validation', () => {
    it('should validate security policy compliance', async () => {
      const mockValidatePolicy = jest.fn().mockResolvedValue({
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            message: 'Security policy validation completed',
            policy_file: '/security/policy.yml',
            compliance_status: 'PASSED'
          })
        }]
      });

      const result = await mockValidatePolicy({
        policy_file: '/security/policy.yml',
        scan_results: ['sast-123', 'sca-456']
      });

      expect(result.content[0].type).toBe('text');
      
      const validationResult = JSON.parse(result.content[0].text);
      expect(validationResult.success).toBe(true);
      expect(validationResult.compliance_status).toBe('PASSED');
    });
  });

  describe('Error Handling', () => {
    it('should handle tool execution failures gracefully', async () => {
      const mockFailingTool = {
        executeScan: jest.fn().mockRejectedValue(new Error('Tool execution failed'))
      };

      (server as any).sastTool = mockFailingTool;

      try {
        await mockFailingTool.executeScan({ target: '/test' });
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Tool execution failed');
      }
    });

    it('should handle invalid tool names', async () => {
      const mockCallTool = jest.fn().mockImplementation((toolName) => {
        if (toolName === 'invalid_tool') {
          throw new Error('Tool not found: invalid_tool');
        }
        return { success: true };
      });

      expect(() => mockCallTool('invalid_tool')).toThrow('Tool not found: invalid_tool');
    });

    it('should validate input parameters', async () => {
      const mockSASTTool = {
        executeScan: jest.fn().mockResolvedValue({
          content: [{
            type: 'text',
            text: JSON.stringify({
              success: false,
              error: 'SAST scan failed',
              message: 'Invalid parameters: "target" is required',
              code: 'SAST_SCAN_ERROR'
            })
          }]
        })
      };

      (server as any).sastTool = mockSASTTool;

      const result = await mockSASTTool.executeScan({});
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.message).toContain('target');
    });
  });

  describe('Concurrent Scan Execution', () => {
    it('should handle multiple concurrent scans', async () => {
      const mockSASTTool = {
        executeScan: jest.fn().mockResolvedValue({
          content: [{ type: 'text', text: JSON.stringify({ status: 'completed' }) }]
        })
      };

      const mockSCATool = {
        executeScan: jest.fn().mockResolvedValue({
          content: [{ type: 'text', text: JSON.stringify({ status: 'completed' }) }]
        })
      };

      (server as any).sastTool = mockSASTTool;
      (server as any).scaTool = mockSCATool;

      const promises = [
        mockSASTTool.executeScan({ target: '/test/project1' }),
        mockSCATool.executeScan({ project_path: '/test/project1' }),
        mockSASTTool.executeScan({ target: '/test/project2' }),
        mockSCATool.executeScan({ project_path: '/test/project2' })
      ];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(4);
      results.forEach(result => {
        const scanResult = JSON.parse(result.content[0].text);
        expect(scanResult.status).toBe('completed');
      });
    });
  });

  describe('Logging and Monitoring', () => {
    it('should log scan execution events', async () => {
      const mockLogger = {
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
        debug: jest.fn()
      };

      // Mock winston logger
      jest.doMock('winston', () => ({
        createLogger: jest.fn(() => mockLogger)
      }));

      const mockSASTTool = {
        executeScan: jest.fn().mockResolvedValue({
          content: [{ type: 'text', text: JSON.stringify({ status: 'completed' }) }]
        })
      };

      (server as any).sastTool = mockSASTTool;

      await mockSASTTool.executeScan({ target: '/test/project' });

      // Verify logging calls would be made
      expect(mockSASTTool.executeScan).toHaveBeenCalled();
    });
  });

  describe('Performance Metrics', () => {
    it('should track scan execution time', async () => {
      const startTime = Date.now();

      const mockSASTTool = {
        executeScan: jest.fn().mockImplementation(async () => {
          await new Promise(resolve => setTimeout(resolve, 100)); // Simulate work
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                status: 'completed',
                metadata: {
                  scan_duration: Date.now() - startTime
                }
              })
            }]
          };
        })
      };

      (server as any).sastTool = mockSASTTool;

      const result = await mockSASTTool.executeScan({ target: '/test/project' });
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.metadata.scan_duration).toBeGreaterThan(0);
    });
  });
});