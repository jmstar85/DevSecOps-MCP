#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { AdvancedSASTTool } from './tools/advanced-sast.js';
import { SCAAnalyzer } from './tools/sca.js';
import { AdvancedDASTScanner } from './tools/advanced-dast.js';

const server = new Server(
  {
    name: 'devsecops-server',
    version: '2.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

const advancedSASTTool = new AdvancedSASTTool();
const scaAnalyzer = new SCAAnalyzer();
const advancedDASTScanner = new AdvancedDASTScanner();

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'advanced_sast_scan',
        description: 'Perform enterprise-grade Static Application Security Testing with SonarQube-level analysis',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Path to the source code directory or file to scan',
            },
            language: {
              type: 'string',
              description: 'Programming language (optional, auto-detected if not provided)',
              enum: ['javascript', 'typescript', 'python', 'java', 'csharp', 'go', 'php', 'ruby'],
            },
            include_metrics: {
              type: 'boolean',
              description: 'Include code quality metrics analysis',
              default: true,
            },
            quality_gate: {
              type: 'boolean',
              description: 'Apply quality gate evaluation',
              default: true,
            },
            exclude_patterns: {
              type: 'array',
              description: 'Patterns to exclude from scanning',
              items: { type: 'string' },
              default: [],
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'sca_analysis',
        description: 'Perform Software Composition Analysis with BlackDuck-level dependency scanning',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Path to the project directory to analyze',
            },
            ecosystem: {
              type: 'string',
              description: 'Package ecosystem (optional, auto-detected if not provided)',
              enum: ['npm', 'pypi', 'maven', 'nuget', 'rubygems', 'go', 'cargo'],
            },
            include_transitive: {
              type: 'boolean',
              description: 'Include transitive dependencies',
              default: true,
            },
            policy_file: {
              type: 'string',
              description: 'Path to policy configuration file',
            },
            check_licenses: {
              type: 'boolean',
              description: 'Perform license analysis',
              default: true,
            },
            check_vulnerabilities: {
              type: 'boolean',
              description: 'Check for known vulnerabilities',
              default: true,
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'advanced_dast_scan',
        description: 'Perform enterprise-grade Dynamic Application Security Testing with OWASP ZAP-level capabilities',
        inputSchema: {
          type: 'object',
          properties: {
            target_url: {
              type: 'string',
              description: 'URL of the running application to scan',
            },
            scan_type: {
              type: 'string',
              description: 'Type of DAST scan to perform',
              enum: ['passive', 'active', 'full', 'api', 'ajax_spider'],
              default: 'passive',
            },
            max_depth: {
              type: 'number',
              description: 'Maximum crawling depth',
              default: 5,
            },
            max_duration: {
              type: 'number',
              description: 'Maximum scan duration in minutes',
              default: 30,
            },
            authentication: {
              type: 'object',
              description: 'Authentication configuration',
              properties: {
                type: {
                  type: 'string',
                  enum: ['form', 'http_basic', 'http_digest', 'oauth2', 'jwt', 'session'],
                },
                credentials: {
                  type: 'object',
                  description: 'Authentication credentials',
                },
                login_url: { type: 'string' },
                username_field: { type: 'string' },
                password_field: { type: 'string' },
              },
            },
            scan_policy: {
              type: 'object',
              description: 'Scan policy configuration',
              properties: {
                injection_tests: { type: 'boolean', default: true },
                xss_tests: { type: 'boolean', default: true },
                path_traversal_tests: { type: 'boolean', default: true },
                sql_injection_tests: { type: 'boolean', default: true },
                command_injection_tests: { type: 'boolean', default: true },
                xxe_tests: { type: 'boolean', default: true },
                ssrf_tests: { type: 'boolean', default: true },
                file_inclusion_tests: { type: 'boolean', default: true },
              },
            },
            exclude_urls: {
              type: 'array',
              description: 'URLs to exclude from scanning',
              items: { type: 'string' },
            },
            custom_headers: {
              type: 'object',
              description: 'Custom HTTP headers',
            },
          },
          required: ['target_url'],
        },
      },
      {
        name: 'vulnerability_report',
        description: 'Generate comprehensive vulnerability report from scan results',
        inputSchema: {
          type: 'object',
          properties: {
            scan_results: {
              type: 'array',
              description: 'Array of scan result objects',
            },
            format: {
              type: 'string',
              description: 'Output format for the report',
              enum: ['json', 'html', 'pdf', 'csv', 'sarif'],
              default: 'json',
            },
            include_remediation: {
              type: 'boolean',
              description: 'Include remediation guidance',
              default: true,
            },
            risk_assessment: {
              type: 'boolean',
              description: 'Include risk assessment',
              default: true,
            },
          },
          required: ['scan_results'],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'advanced_sast_scan':
        const sastResults = await advancedSASTTool.performAdvancedScan(args);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              scan_type: 'Advanced SAST',
              timestamp: new Date().toISOString(),
              ...sastResults
            }, null, 2)
          }]
        };
      
      case 'sca_analysis':
        const scaResults = await scaAnalyzer.performSCAAnalysis(args);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              scan_type: 'SCA Analysis',
              timestamp: new Date().toISOString(),
              ...scaResults
            }, null, 2)
          }]
        };
      
      case 'advanced_dast_scan':
        const dastResults = await advancedDASTScanner.performAdvancedScan(args);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              scan_type: 'Advanced DAST',
              timestamp: new Date().toISOString(),
              ...dastResults
            }, null, 2)
          }]
        };
      
      case 'vulnerability_report':
        return await generateVulnerabilityReport(args);
      
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    return {
      content: [
        {
          type: 'text',
          text: `Error executing ${name}: ${error.message}`,
        },
      ],
      isError: true,
    };
  }
});

async function generateVulnerabilityReport(args: any) {
  const { scan_results, format = 'json', include_remediation = true, risk_assessment = true } = args;
  
  const vulnerabilities = Array.isArray(scan_results) ? scan_results : 
    (scan_results.issues || scan_results.results || scan_results.vulnerabilities || []);
  
  const report = {
    metadata: {
      timestamp: new Date().toISOString(),
      format,
      generator: 'DevSecOps MCP Server v2.0.0',
      schema_version: '2.1.0'
    },
    summary: {
      total_vulnerabilities: vulnerabilities.length,
      blocker: vulnerabilities.filter((v: any) => v.severity === 'blocker').length,
      critical: vulnerabilities.filter((v: any) => v.severity === 'critical').length,
      high: vulnerabilities.filter((v: any) => v.severity === 'high').length,
      major: vulnerabilities.filter((v: any) => v.severity === 'major').length,
      medium: vulnerabilities.filter((v: any) => v.severity === 'medium').length,
      minor: vulnerabilities.filter((v: any) => v.severity === 'minor').length,
      low: vulnerabilities.filter((v: any) => v.severity === 'low').length,
      info: vulnerabilities.filter((v: any) => v.severity === 'info').length,
    },
    risk_score: calculateOverallRiskScore(vulnerabilities),
    vulnerabilities: vulnerabilities.map((vuln: any) => ({
      ...vuln,
      remediation: include_remediation ? generateRemediation(vuln) : undefined,
      business_impact: risk_assessment ? assessBusinessImpact(vuln) : undefined
    })),
    recommendations: generateRecommendations(vulnerabilities),
    compliance: {
      owasp_top_10_2021: mapToOWASP(vulnerabilities),
      cwe_categories: mapToCWE(vulnerabilities),
      pci_dss_relevance: assessPCIRelevance(vulnerabilities),
      gdpr_relevance: assessGDPRRelevance(vulnerabilities)
    }
  };

  if (format === 'sarif') {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(convertToSARIF(report), null, 2)
      }]
    };
  }

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(report, null, 2),
      },
    ],
  };
}

function calculateOverallRiskScore(vulnerabilities: any[]): number {
  if (!vulnerabilities.length) return 0;
  
  const severityWeights = {
    blocker: 100,
    critical: 90,
    high: 70,
    major: 50,
    medium: 30,
    minor: 15,
    low: 10,
    info: 5
  };
  
  const totalScore = vulnerabilities.reduce((sum, vuln) => {
    const weight = severityWeights[vuln.severity as keyof typeof severityWeights] || 5;
    return sum + weight;
  }, 0);
  
  return Math.min(100, Math.round(totalScore / vulnerabilities.length));
}

function generateRemediation(vulnerability: any): string {
  const remediationMap: { [key: string]: string } = {
    'cross-site-scripting': 'Implement input validation, output encoding, and Content Security Policy (CSP)',
    'sql-injection': 'Use parameterized queries, input validation, and principle of least privilege',
    'command-injection': 'Avoid executing system commands with user input, use allow-lists',
    'path-traversal': 'Implement proper input validation and file access controls',
    'information-disclosure': 'Remove sensitive information from error messages and responses',
    'missing-security-header': 'Configure appropriate security headers in web server',
    'insecure-transport': 'Implement HTTPS with proper SSL/TLS configuration',
    'hardcoded-credentials': 'Use secure credential management and environment variables'
  };
  
  const category = vulnerability.category || vulnerability.vulnerability?.toLowerCase();
  return remediationMap[category] || 'Review code and apply security best practices';
}

function assessBusinessImpact(vulnerability: any): string {
  const severityImpactMap: { [key: string]: string } = {
    blocker: 'Critical business impact - immediate action required',
    critical: 'High business impact - severe security risk',
    high: 'Significant business impact - major security concern',
    major: 'Moderate business impact - important security issue',
    medium: 'Limited business impact - security concern',
    minor: 'Low business impact - minor security issue',
    low: 'Minimal business impact - informational',
    info: 'No direct business impact - informational'
  };
  
  return severityImpactMap[vulnerability.severity] || 'Unknown business impact';
}

function generateRecommendations(vulnerabilities: any[]): string[] {
  const recommendations: string[] = [];
  
  const criticalCount = vulnerabilities.filter(v => v.severity === 'critical' || v.severity === 'blocker').length;
  if (criticalCount > 0) {
    recommendations.push(`Address ${criticalCount} critical/blocker vulnerabilities immediately`);
  }
  
  const injectionVulns = vulnerabilities.filter(v => 
    v.category === 'injection' || 
    v.vulnerability?.toLowerCase().includes('injection')
  ).length;
  if (injectionVulns > 0) {
    recommendations.push('Implement comprehensive input validation and sanitization');
  }
  
  const headerIssues = vulnerabilities.filter(v => 
    v.vulnerability?.toLowerCase().includes('header')
  ).length;
  if (headerIssues > 0) {
    recommendations.push('Configure security headers for defense in depth');
  }
  
  recommendations.push('Conduct regular security testing and code reviews');
  recommendations.push('Implement security training for development team');
  recommendations.push('Establish secure coding standards and guidelines');
  
  return recommendations;
}

function mapToOWASP(vulnerabilities: any[]): { [key: string]: number } {
  const owaspMapping: { [key: string]: number } = {
    'A01:2021': 0, // Broken Access Control
    'A02:2021': 0, // Cryptographic Failures
    'A03:2021': 0, // Injection
    'A04:2021': 0, // Insecure Design
    'A05:2021': 0, // Security Misconfiguration
    'A06:2021': 0, // Vulnerable and Outdated Components
    'A07:2021': 0, // Identification and Authentication Failures
    'A08:2021': 0, // Software and Data Integrity Failures
    'A09:2021': 0, // Security Logging and Monitoring Failures
    'A10:2021': 0  // Server-Side Request Forgery (SSRF)
  };
  
  vulnerabilities.forEach(vuln => {
    const owasp = vuln.owasp;
    if (owasp && owaspMapping.hasOwnProperty(owasp)) {
      owaspMapping[owasp]++;
    }
  });
  
  return owaspMapping;
}

function mapToCWE(vulnerabilities: any[]): { [key: string]: number } {
  const cweMapping: { [key: string]: number } = {};
  
  vulnerabilities.forEach(vuln => {
    const cwe = vuln.cwe;
    if (cwe) {
      cweMapping[cwe] = (cweMapping[cwe] || 0) + 1;
    }
  });
  
  return cweMapping;
}

function assessPCIRelevance(vulnerabilities: any[]): string {
  const pciRelevantVulns = vulnerabilities.filter(v => 
    v.category === 'sensitive_data' || 
    v.vulnerability?.toLowerCase().includes('encryption') ||
    v.vulnerability?.toLowerCase().includes('transport')
  ).length;
  
  if (pciRelevantVulns > 0) {
    return `${pciRelevantVulns} vulnerabilities may impact PCI DSS compliance`;
  }
  return 'No direct PCI DSS compliance impact identified';
}

function assessGDPRRelevance(vulnerabilities: any[]): string {
  const gdprRelevantVulns = vulnerabilities.filter(v => 
    v.category === 'sensitive_data' || 
    v.vulnerability?.toLowerCase().includes('disclosure') ||
    v.vulnerability?.toLowerCase().includes('privacy')
  ).length;
  
  if (gdprRelevantVulns > 0) {
    return `${gdprRelevantVulns} vulnerabilities may impact GDPR compliance`;
  }
  return 'No direct GDPR compliance impact identified';
}

function convertToSARIF(report: any): any {
  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'DevSecOps MCP Server',
          version: '2.0.0',
          informationUri: 'https://github.com/username/devsecops-mcp-server'
        }
      },
      results: report.vulnerabilities.map((vuln: any) => ({
        ruleId: vuln.rule || vuln.id,
        message: {
          text: vuln.message || vuln.description
        },
        level: mapSeverityToSARIF(vuln.severity),
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: vuln.file || vuln.url
            },
            region: {
              startLine: vuln.line || 1,
              startColumn: vuln.column || 1
            }
          }
        }]
      }))
    }]
  };
}

function mapSeverityToSARIF(severity: string): string {
  const mapping: { [key: string]: string } = {
    blocker: 'error',
    critical: 'error',
    high: 'error',
    major: 'warning',
    medium: 'warning',
    minor: 'note',
    low: 'note',
    info: 'note'
  };
  
  return mapping[severity] || 'note';
}

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Enterprise DevSecOps MCP Server v2.0.0 running on stdio');
}

if (require.main === module) {
  main().catch(console.error);
}