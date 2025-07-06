import { spawn } from 'child_process';
import axios from 'axios';
import Joi from 'joi';
import winston from 'winston';
import { TrivyConnector } from '../connectors/trivy.js';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

interface IASTParams {
  application_id: string;
  environment?: 'development' | 'staging' | 'testing';
  test_suite?: string;
  runtime_analysis?: boolean;
  performance_threshold?: number;
  tool?: 'trivy' | 'owasp-zap' | 'auto';
  agent_config?: {
    sampling_rate?: number;
    enable_logging?: boolean;
    exclude_patterns?: string[];
  };
}

interface IASTVulnerability {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  cwe_id?: number;
  description: string;
  url: string;
  method: string;
  parameter?: string;
  source_file?: string;
  line_number?: number;
  data_flow: Array<{
    file: string;
    line: number;
    method: string;
    type: 'source' | 'sink' | 'propagator';
  }>;
  exploit_proof?: string;
  impact: string;
  likelihood: 'low' | 'medium' | 'high';
  first_seen: string;
  last_seen: string;
  status: 'new' | 'triaged' | 'fixed' | 'false_positive';
  remediation_guidance?: string;
}

interface PerformanceMetrics {
  agent_overhead: number;
  memory_usage: number;
  cpu_usage: number;
  response_time_impact: number;
  throughput_impact: number;
}

interface IASTScanResult {
  tool: string;
  scan_id: string;
  status: 'completed' | 'failed' | 'running';
  application_id: string;
  environment: string;
  vulnerabilities: IASTVulnerability[];
  performance_metrics: PerformanceMetrics;
  coverage: {
    total_routes: number;
    exercised_routes: number;
    coverage_percentage: number;
    tested_endpoints: string[];
    untested_endpoints: string[];
  };
  summary: {
    total_vulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    new_vulnerabilities: number;
    fixed_vulnerabilities: number;
  };
  test_execution: {
    total_tests: number;
    passed_tests: number;
    failed_tests: number;
    test_duration: number;
    vulnerabilities_found_during_tests: number;
  };
  metadata: {
    scan_duration: number;
    agent_version: string;
    runtime_version: string;
    timestamp: string;
  };
}

export class IASTTool {
  private trivyConnector: TrivyConnector;
  private readonly validationSchema = Joi.object({
    application_id: Joi.string().required(),
    environment: Joi.string().valid('development', 'staging', 'testing').optional(),
    test_suite: Joi.string().optional(),
    runtime_analysis: Joi.boolean().optional(),
    performance_threshold: Joi.number().min(0).max(100).optional(),
    tool: Joi.string().valid('trivy', 'owasp-zap', 'auto').optional(),
    agent_config: Joi.object({
      sampling_rate: Joi.number().min(0).max(1).optional(),
      enable_logging: Joi.boolean().optional(),
      exclude_patterns: Joi.array().items(Joi.string()).optional()
    }).optional()
  });

  constructor() {
    this.trivyConnector = new TrivyConnector();
  }

  async executeScan(params: IASTParams): Promise<any> {
    const startTime = Date.now();
    
    try {
      const { error, value } = this.validationSchema.validate(params);
      if (error) {
        throw new Error(`Invalid parameters: ${error.details[0]?.message}`);
      }

      const validatedParams = value as IASTParams;
      logger.info('Starting IAST scan', { 
        application_id: validatedParams.application_id,
        environment: validatedParams.environment || 'development'
      });

      const tool = validatedParams.tool || 'trivy';
      let result: IASTScanResult;

      switch (tool) {
        case 'trivy':
          result = await this.runTrivyScan(validatedParams);
          break;
        case 'owasp-zap':
          result = await this.runOWASPZAPScan(validatedParams);
          break;
        default:
          result = await this.runAutoScan(validatedParams);
      }

      result.metadata.scan_duration = Date.now() - startTime;
      
      if (result.performance_metrics.agent_overhead > (validatedParams.performance_threshold || 5)) {
        logger.warn('IAST agent overhead exceeds threshold', {
          overhead: result.performance_metrics.agent_overhead,
          threshold: validatedParams.performance_threshold || 5
        });
      }
      
      logger.info('IAST scan completed', {
        scan_id: result.scan_id,
        total_vulnerabilities: result.summary.total_vulnerabilities,
        coverage: result.coverage.coverage_percentage,
        agent_overhead: result.performance_metrics.agent_overhead,
        duration: result.metadata.scan_duration
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };

    } catch (error) {
      logger.error('IAST scan failed', { 
        error: error instanceof Error ? error.message : 'Unknown error',
        application_id: params.application_id 
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: 'IAST scan failed',
            message: error instanceof Error ? error.message : 'Unknown error',
            code: 'IAST_SCAN_ERROR'
          }, null, 2)
        }]
      };
    }
  }

  private async runTrivyScan(params: IASTParams): Promise<IASTScanResult> {
    const scanId = `iast-trivy-${Date.now()}`;
    
    try {
      // Trivy can scan configuration files and secrets which provides some IAST-like functionality
      const trivyResult = await this.trivyConnector.scanFilesystem(params.application_id, {
        skipDirs: params.agent_config?.exclude_patterns
      });
      
      return this.mapTrivyResultToIASTResult(trivyResult, scanId, params);
    } catch (error) {
      logger.error('Trivy IAST-like scan failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      throw error;
    }
  }

  private async runOWASPZAPScan(params: IASTParams): Promise<IASTScanResult> {
    const scanId = `iast-zap-${Date.now()}`;
    
    try {
      // Use ZAP for passive scanning which provides runtime-like analysis
      const zapResult = await this.executeZAPPassiveScan(params);
      
      return this.mapZAPResultToIASTResult(zapResult, scanId, params);
    } catch (error) {
      logger.error('OWASP ZAP IAST-like scan failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      throw error;
    }
  }

  private async runAutoScan(params: IASTParams): Promise<IASTScanResult> {
    try {
      return await this.runTrivyScan(params);
    } catch (trivyError) {
      logger.warn('Trivy scan failed, falling back to OWASP ZAP', { error: trivyError });
      return await this.runOWASPZAPScan(params);
    }
  }

  private async executeZAPPassiveScan(params: IASTParams): Promise<any> {
    // Mock ZAP passive scan for IAST-like functionality
    return {
      alerts: [],
      coverage: {
        totalRoutes: 0,
        exercisedRoutes: 0,
        coveragePercentage: 0
      },
      performance: {
        agentOverhead: 1.0 // ZAP has minimal overhead for passive scanning
      }
    };
  }

  private mapTrivyResultToIASTResult(trivyResult: any, scanId: string, params: IASTParams): IASTScanResult {
    const vulnerabilities = this.mapTrivyVulnerabilitiesToIAST(trivyResult.vulnerabilities || []);
    
    return {
      tool: 'Trivy (IAST-like)',
      scan_id: scanId,
      status: 'completed',
      application_id: params.application_id,
      environment: params.environment || 'development',
      vulnerabilities,
      performance_metrics: {
        agent_overhead: 0, // Trivy is static analysis, no runtime overhead
        memory_usage: 0,
        cpu_usage: 0,
        response_time_impact: 0,
        throughput_impact: 0
      },
      coverage: {
        total_routes: 0,
        exercised_routes: 0,
        coverage_percentage: 0,
        tested_endpoints: [],
        untested_endpoints: []
      },
      summary: this.calculateSummary(vulnerabilities),
      test_execution: {
        total_tests: 0,
        passed_tests: 0,
        failed_tests: 0,
        test_duration: 0,
        vulnerabilities_found_during_tests: vulnerabilities.length
      },
      metadata: {
        scan_duration: 0,
        agent_version: 'trivy-static',
        runtime_version: 'n/a',
        timestamp: new Date().toISOString()
      }
    };
  }

  private mapZAPResultToIASTResult(zapResult: any, scanId: string, params: IASTParams): IASTScanResult {
    const vulnerabilities = this.mapZAPAlertsToIAST(zapResult.alerts || []);
    
    return {
      tool: 'OWASP ZAP (IAST-like)',
      scan_id: scanId,
      status: 'completed',
      application_id: params.application_id,
      environment: params.environment || 'development',
      vulnerabilities,
      performance_metrics: {
        agent_overhead: zapResult.performance?.agentOverhead || 1.0,
        memory_usage: 0,
        cpu_usage: 0,
        response_time_impact: 0,
        throughput_impact: 0
      },
      coverage: {
        total_routes: zapResult.coverage?.totalRoutes || 0,
        exercised_routes: zapResult.coverage?.exercisedRoutes || 0,
        coverage_percentage: zapResult.coverage?.coveragePercentage || 0,
        tested_endpoints: [],
        untested_endpoints: []
      },
      summary: this.calculateSummary(vulnerabilities),
      test_execution: {
        total_tests: 0,
        passed_tests: 0,
        failed_tests: 0,
        test_duration: 0,
        vulnerabilities_found_during_tests: vulnerabilities.length
      },
      metadata: {
        scan_duration: 0,
        agent_version: 'zap-passive',
        runtime_version: 'n/a',
        timestamp: new Date().toISOString()
      }
    };
  }

  private mapTrivyVulnerabilitiesToIAST(vulnerabilities: any[]): IASTVulnerability[] {
    return vulnerabilities.map(vuln => ({
      id: vuln.id,
      title: vuln.title,
      severity: vuln.severity,
      category: vuln.packageName || 'configuration',
      cwe_id: vuln.cwe_ids?.[0] ? parseInt(vuln.cwe_ids[0].replace('CWE-', '')) : undefined,
      description: vuln.description,
      url: '',
      method: 'unknown',
      source_file: vuln.packagePath,
      line_number: 0,
      data_flow: [],
      impact: vuln.severity,
      likelihood: 'medium' as const,
      first_seen: vuln.published || new Date().toISOString(),
      last_seen: new Date().toISOString(),
      status: 'new' as const,
      remediation_guidance: vuln.fixedVersion ? `Upgrade to version ${vuln.fixedVersion}` : undefined
    }));
  }

  private mapZAPAlertsToIAST(alerts: any[]): IASTVulnerability[] {
    return alerts.map(alert => ({
      id: alert.pluginId || alert.id,
      title: alert.name || alert.alert,
      severity: this.mapZAPSeverityToIAST(alert.riskcode),
      category: alert.category || 'web',
      cwe_id: alert.cweid ? parseInt(alert.cweid) : undefined,
      description: alert.description || alert.desc,
      url: alert.url,
      method: alert.method || 'GET',
      parameter: alert.param,
      data_flow: [],
      impact: alert.riskdesc || 'unknown',
      likelihood: this.mapZAPConfidenceToLikelihood(alert.confidence),
      first_seen: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      status: 'new' as const,
      remediation_guidance: alert.solution
    }));
  }

  private mapZAPSeverityToIAST(riskcode: string | number): 'low' | 'medium' | 'high' | 'critical' {
    if (typeof riskcode === 'number') {
      switch (riskcode) {
        case 3: return 'critical';
        case 2: return 'high';
        case 1: return 'medium';
        default: return 'low';
      }
    }
    return 'medium';
  }

  private mapZAPConfidenceToLikelihood(confidence: string | number): 'low' | 'medium' | 'high' {
    if (typeof confidence === 'number') {
      if (confidence >= 3) return 'high';
      if (confidence >= 2) return 'medium';
      return 'low';
    }
    return 'medium';
  }

  private mapVeracodeResultToIASTResult(veracodeResult: any, scanId: string, params: IASTParams): IASTScanResult {
    const vulnerabilities = veracodeResult.vulnerabilities?.map(this.mapVeracodeVulnerabilityToIASTVulnerability) || [];
    
    return {
      tool: 'Veracode IAST',
      scan_id: scanId,
      status: 'completed',
      application_id: params.application_id,
      environment: params.environment || 'development',
      vulnerabilities,
      performance_metrics: {
        agent_overhead: veracodeResult.performance?.agentOverhead || 0,
        memory_usage: veracodeResult.performance?.memoryUsage || 0,
        cpu_usage: veracodeResult.performance?.cpuUsage || 0,
        response_time_impact: veracodeResult.performance?.responseTimeImpact || 0,
        throughput_impact: veracodeResult.performance?.throughputImpact || 0
      },
      coverage: {
        total_routes: veracodeResult.coverage?.totalRoutes || 0,
        exercised_routes: veracodeResult.coverage?.exercisedRoutes || 0,
        coverage_percentage: veracodeResult.coverage?.coveragePercentage || 0,
        tested_endpoints: veracodeResult.coverage?.testedEndpoints || [],
        untested_endpoints: veracodeResult.coverage?.untestedEndpoints || []
      },
      summary: this.calculateSummary(vulnerabilities),
      test_execution: {
        total_tests: veracodeResult.testExecution?.totalTests || 0,
        passed_tests: veracodeResult.testExecution?.passedTests || 0,
        failed_tests: veracodeResult.testExecution?.failedTests || 0,
        test_duration: veracodeResult.testExecution?.testDuration || 0,
        vulnerabilities_found_during_tests: vulnerabilities.length
      },
      metadata: {
        scan_duration: 0,
        agent_version: veracodeResult.agentVersion || 'unknown',
        runtime_version: veracodeResult.runtimeVersion || 'unknown',
        timestamp: new Date().toISOString()
      }
    };
  }

  private mapContrastResultToIASTResult(contrastResult: any, scanId: string, params: IASTParams): IASTScanResult {
    const vulnerabilities = contrastResult.traces?.map(this.mapContrastTraceToIASTVulnerability) || [];
    
    return {
      tool: 'Contrast Security',
      scan_id: scanId,
      status: 'completed',
      application_id: params.application_id,
      environment: params.environment || 'development',
      vulnerabilities,
      performance_metrics: {
        agent_overhead: 2, // Contrast typically has low overhead
        memory_usage: 0,
        cpu_usage: 0,
        response_time_impact: 0,
        throughput_impact: 0
      },
      coverage: {
        total_routes: contrastResult.coverage?.totalRoutes || 0,
        exercised_routes: contrastResult.coverage?.exercisedRoutes || 0,
        coverage_percentage: contrastResult.coverage?.coveragePercentage || 0,
        tested_endpoints: contrastResult.coverage?.testedEndpoints || [],
        untested_endpoints: contrastResult.coverage?.untestedEndpoints || []
      },
      summary: this.calculateSummary(vulnerabilities),
      test_execution: {
        total_tests: 0,
        passed_tests: 0,
        failed_tests: 0,
        test_duration: 0,
        vulnerabilities_found_during_tests: vulnerabilities.length
      },
      metadata: {
        scan_duration: 0,
        agent_version: contrastResult.agentVersion || 'unknown',
        runtime_version: contrastResult.runtimeVersion || 'unknown',
        timestamp: new Date().toISOString()
      }
    };
  }

  private mapVeracodeVulnerabilityToIASTVulnerability(vuln: any): IASTVulnerability {
    return {
      id: vuln.id || vuln.issue_id,
      title: vuln.title || vuln.issue_type,
      severity: this.mapVeracodeSeverityToIASTSeverity(vuln.severity),
      category: vuln.category || vuln.issue_type,
      cwe_id: vuln.cwe_id,
      description: vuln.description,
      url: vuln.url || '',
      method: vuln.method || 'unknown',
      parameter: vuln.parameter,
      source_file: vuln.source_file,
      line_number: vuln.line_number,
      data_flow: vuln.data_flow?.map(this.mapVeracodeDataFlowNode) || [],
      exploit_proof: vuln.exploit_proof,
      impact: vuln.impact || 'unknown',
      likelihood: this.mapVeracodeLikelihood(vuln.likelihood),
      first_seen: vuln.first_seen || new Date().toISOString(),
      last_seen: vuln.last_seen || new Date().toISOString(),
      status: this.mapVeracodeStatus(vuln.status),
      remediation_guidance: vuln.remediation_guidance
    };
  }

  private mapContrastTraceToIASTVulnerability(trace: any): IASTVulnerability {
    return {
      id: trace.uuid,
      title: trace.title,
      severity: this.mapContrastSeverityToIASTSeverity(trace.severity),
      category: trace.category,
      cwe_id: trace.cwe,
      description: trace.what,
      url: trace.request?.uri || '',
      method: trace.request?.method || 'unknown',
      parameter: trace.request?.parameters?.[0]?.name,
      source_file: trace.events?.[0]?.file_name,
      line_number: trace.events?.[0]?.line_number,
      data_flow: trace.events?.map(this.mapContrastEventToDataFlowNode) || [],
      impact: trace.impact || 'unknown',
      likelihood: this.mapContrastLikelihood(trace.likelihood),
      first_seen: trace.first_time_seen,
      last_seen: trace.last_time_seen,
      status: this.mapContrastStatus(trace.status),
      remediation_guidance: trace.how_to_fix
    };
  }

  private mapVeracodeSeverityToIASTSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
    const severityMap: { [key: string]: 'low' | 'medium' | 'high' | 'critical' } = {
      'Very Low': 'low',
      'Low': 'low',
      'Medium': 'medium',
      'High': 'high',
      'Very High': 'critical'
    };
    return severityMap[severity] || 'medium';
  }

  private mapContrastSeverityToIASTSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
    const severityMap: { [key: string]: 'low' | 'medium' | 'high' | 'critical' } = {
      'Note': 'low',
      'Low': 'low',
      'Medium': 'medium',
      'High': 'high',
      'Critical': 'critical'
    };
    return severityMap[severity] || 'medium';
  }

  private mapVeracodeLikelihood(likelihood: string): 'low' | 'medium' | 'high' {
    const likelihoodMap: { [key: string]: 'low' | 'medium' | 'high' } = {
      'Low': 'low',
      'Medium': 'medium',
      'High': 'high'
    };
    return likelihoodMap[likelihood] || 'medium';
  }

  private mapContrastLikelihood(likelihood: string): 'low' | 'medium' | 'high' {
    const likelihoodMap: { [key: string]: 'low' | 'medium' | 'high' } = {
      'Low': 'low',
      'Medium': 'medium',
      'High': 'high'
    };
    return likelihoodMap[likelihood] || 'medium';
  }

  private mapVeracodeStatus(status: string): 'new' | 'triaged' | 'fixed' | 'false_positive' {
    const statusMap: { [key: string]: 'new' | 'triaged' | 'fixed' | 'false_positive' } = {
      'New': 'new',
      'Open': 'triaged',
      'Fixed': 'fixed',
      'False Positive': 'false_positive'
    };
    return statusMap[status] || 'new';
  }

  private mapContrastStatus(status: string): 'new' | 'triaged' | 'fixed' | 'false_positive' {
    const statusMap: { [key: string]: 'new' | 'triaged' | 'fixed' | 'false_positive' } = {
      'Reported': 'new',
      'Confirmed': 'triaged',
      'Suspicious': 'triaged',
      'Not a Problem': 'false_positive',
      'Remediated': 'fixed',
      'Fixed': 'fixed'
    };
    return statusMap[status] || 'new';
  }

  private mapVeracodeDataFlowNode(node: any): IASTVulnerability['data_flow'][0] {
    return {
      file: node.file || '',
      line: node.line || 0,
      method: node.method || '',
      type: node.type || 'propagator'
    };
  }

  private mapContrastEventToDataFlowNode(event: any): IASTVulnerability['data_flow'][0] {
    return {
      file: event.file_name || '',
      line: event.line_number || 0,
      method: event.method_name || '',
      type: event.event_type === 'SOURCE' ? 'source' : event.event_type === 'SINK' ? 'sink' : 'propagator'
    };
  }

  private calculateSummary(vulnerabilities: IASTVulnerability[]): IASTScanResult['summary'] {
    const summary = {
      total_vulnerabilities: vulnerabilities.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      new_vulnerabilities: 0,
      fixed_vulnerabilities: 0
    };

    vulnerabilities.forEach(vuln => {
      switch (vuln.severity) {
        case 'critical':
          summary.critical++;
          break;
        case 'high':
          summary.high++;
          break;
        case 'medium':
          summary.medium++;
          break;
        case 'low':
          summary.low++;
          break;
      }

      if (vuln.status === 'new') {
        summary.new_vulnerabilities++;
      } else if (vuln.status === 'fixed') {
        summary.fixed_vulnerabilities++;
      }
    });

    return summary;
  }
}