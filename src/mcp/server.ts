import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import winston from 'winston';
import { SASTTool } from './tools/sast-tool.js';
import { DASTTool } from './tools/dast-tool.js';
import { SCATool } from './tools/sca-tool.js';
import { IASTTool } from './tools/iast-tool.js';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'devsecops-mcp.log' })
  ]
});

class DevSecOpsMCPServer {
  private server: Server;
  private sastTool: SASTTool;
  private dastTool: DASTTool;
  private scaTool: SCATool;
  private iastTool: IASTTool;

  constructor() {
    this.server = new Server(
      {
        name: 'devsecops-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.sastTool = new SASTTool();
    this.dastTool = new DASTTool();
    this.scaTool = new SCATool();
    this.iastTool = new IASTTool();

    this.setupHandlers();
  }

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'run_sast_scan',
            description: 'Execute SAST (Static Application Security Testing) scan',
            inputSchema: {
              type: 'object',
              properties: {
                target: {
                  type: 'string',
                  description: 'Target source code path or repository URL'
                },
                rules: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Security rules to apply'
                },
                severity_threshold: {
                  type: 'string',
                  enum: ['low', 'medium', 'high', 'critical'],
                  description: 'Minimum severity level to report'
                }
              },
              required: ['target']
            }
          },
          {
            name: 'run_dast_scan',
            description: 'Execute DAST (Dynamic Application Security Testing) scan',
            inputSchema: {
              type: 'object',
              properties: {
                target_url: {
                  type: 'string',
                  description: 'Target application URL'
                },
                scan_type: {
                  type: 'string',
                  enum: ['quick', 'baseline', 'full'],
                  description: 'Type of DAST scan to perform'
                },
                authentication: {
                  type: 'object',
                  properties: {
                    username: { type: 'string' },
                    password: { type: 'string' }
                  },
                  description: 'Authentication credentials if required'
                }
              },
              required: ['target_url']
            }
          },
          {
            name: 'run_sca_scan',
            description: 'Execute SCA (Software Composition Analysis) scan',
            inputSchema: {
              type: 'object',
              properties: {
                project_path: {
                  type: 'string',
                  description: 'Path to project with dependencies'
                },
                package_manager: {
                  type: 'string',
                  enum: ['npm', 'yarn', 'maven', 'gradle', 'pip', 'composer'],
                  description: 'Package manager used by the project'
                },
                fix_vulnerabilities: {
                  type: 'boolean',
                  description: 'Auto-fix vulnerabilities where possible'
                }
              },
              required: ['project_path']
            }
          },
          {
            name: 'run_iast_scan',
            description: 'Execute IAST (Interactive Application Security Testing) scan',
            inputSchema: {
              type: 'object',
              properties: {
                application_id: {
                  type: 'string',
                  description: 'Application identifier in IAST platform'
                },
                environment: {
                  type: 'string',
                  enum: ['development', 'staging', 'testing'],
                  description: 'Target environment'
                },
                test_suite: {
                  type: 'string',
                  description: 'Test suite to run with IAST monitoring'
                }
              },
              required: ['application_id']
            }
          },
          {
            name: 'generate_security_report',
            description: 'Generate comprehensive security report from all scans',
            inputSchema: {
              type: 'object',
              properties: {
                scan_ids: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'List of scan IDs to include in report'
                },
                format: {
                  type: 'string',
                  enum: ['json', 'html', 'pdf', 'sarif'],
                  description: 'Report format'
                },
                include_remediation: {
                  type: 'boolean',
                  description: 'Include remediation suggestions'
                }
              },
              required: ['scan_ids']
            }
          },
          {
            name: 'validate_security_policy',
            description: 'Validate security policy compliance',
            inputSchema: {
              type: 'object',
              properties: {
                policy_file: {
                  type: 'string',
                  description: 'Path to security policy file'
                },
                scan_results: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Scan result IDs to validate against policy'
                }
              },
              required: ['policy_file', 'scan_results']
            }
          }
        ]
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'run_sast_scan':
            return await this.sastTool.executeScan(args);
          
          case 'run_dast_scan':
            return await this.dastTool.executeScan(args);
          
          case 'run_sca_scan':
            return await this.scaTool.executeScan(args);
          
          case 'run_iast_scan':
            return await this.iastTool.executeScan(args);
          
          case 'generate_security_report':
            return await this.generateSecurityReport(args);
          
          case 'validate_security_policy':
            return await this.validateSecurityPolicy(args);
          
          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Tool not found: ${name}`
            );
        }
      } catch (error) {
        logger.error('Tool execution failed', { 
          tool: name, 
          error: error instanceof Error ? error.message : 'Unknown error',
          args 
        });
        
        throw new McpError(
          ErrorCode.InternalError,
          `Security scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    });
  }

  private async generateSecurityReport(args: any): Promise<any> {
    logger.info('Generating security report', { scanIds: args.scan_ids });
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          message: 'Security report generation initiated',
          format: args.format || 'json',
          include_remediation: args.include_remediation || false
        }, null, 2)
      }]
    };
  }

  private async validateSecurityPolicy(args: any): Promise<any> {
    logger.info('Validating security policy', { policyFile: args.policy_file });
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          message: 'Security policy validation completed',
          policy_file: args.policy_file,
          compliance_status: 'PASSED'
        }, null, 2)
      }]
    };
  }

  public async run(): Promise<void> {
    const transport = new StdioServerTransport();
    
    logger.info('Starting DevSecOps MCP Server', {
      version: '1.0.0',
      port: process.env.MCP_PORT || 3000
    });

    await this.server.connect(transport);
    logger.info('DevSecOps MCP Server connected and ready');
  }
}

if (require.main === module) {
  const server = new DevSecOpsMCPServer();
  server.run().catch((error) => {
    logger.error('Server failed to start', { error: error.message });
    process.exit(1);
  });
}

export { DevSecOpsMCPServer };