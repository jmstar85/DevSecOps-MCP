import { spawn } from 'child_process';
import axios from 'axios';
import Joi from 'joi';
import winston from 'winston';
import { ZAPConnector } from '../connectors/zap.js';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

interface DASTParams {
  target_url: string;
  scan_type?: 'quick' | 'baseline' | 'full';
  authentication?: {
    username: string;
    password: string;
  };
  spider_options?: {
    max_depth?: number;
    max_children?: number;
    exclude_patterns?: string[];
  };
  active_scan_policy?: string;
  tool?: 'zap' | 'auto';
}

interface DASTVulnerability {
  id: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: 'low' | 'medium' | 'high';
  description: string;
  url: string;
  method: string;
  parameter?: string;
  attack: string;
  evidence?: string;
  reference: string;
  solution?: string;
  cwe_id?: number;
  wasc_id?: number;
}

interface DASTScanResult {
  tool: string;
  scan_id: string;
  status: 'completed' | 'failed' | 'running';
  target_url: string;
  vulnerabilities: DASTVulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  coverage: {
    urls_found: number;
    urls_tested: number;
    forms_found: number;
    parameters_tested: number;
  };
  metadata: {
    scan_duration: number;
    scan_type: string;
    timestamp: string;
  };
}

export class DASTTool {
  private zapConnector: ZAPConnector;
  private readonly validationSchema = Joi.object({
    target_url: Joi.string().uri().required(),
    scan_type: Joi.string().valid('quick', 'baseline', 'full').optional(),
    authentication: Joi.object({
      username: Joi.string().required(),
      password: Joi.string().required()
    }).optional(),
    spider_options: Joi.object({
      max_depth: Joi.number().min(1).max(10).optional(),
      max_children: Joi.number().min(1).max(100).optional(),
      exclude_patterns: Joi.array().items(Joi.string()).optional()
    }).optional(),
    active_scan_policy: Joi.string().optional(),
    tool: Joi.string().valid('zap', 'auto').optional()
  });

  constructor() {
    this.zapConnector = new ZAPConnector();
  }

  async executeScan(params: DASTParams): Promise<any> {
    const startTime = Date.now();
    
    try {
      const { error, value } = this.validationSchema.validate(params);
      if (error) {
        throw new Error(`Invalid parameters: ${error.details[0]?.message}`);
      }

      const validatedParams = value as DASTParams;
      logger.info('Starting DAST scan', { 
        target: validatedParams.target_url,
        scan_type: validatedParams.scan_type || 'baseline'
      });

      await this.validateTarget(validatedParams.target_url);

      const tool = validatedParams.tool || 'zap';
      let result: DASTScanResult;

      switch (tool) {
        case 'zap':
          result = await this.runZAPScan(validatedParams);
          break;
        default:
          result = await this.runZAPScan(validatedParams);
      }

      result.metadata.scan_duration = Date.now() - startTime;
      
      logger.info('DAST scan completed', {
        scan_id: result.scan_id,
        total_vulnerabilities: result.summary.total,
        duration: result.metadata.scan_duration,
        urls_tested: result.coverage.urls_tested
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };

    } catch (error) {
      logger.error('DAST scan failed', { 
        error: error instanceof Error ? error.message : 'Unknown error',
        target: params.target_url 
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: 'DAST scan failed',
            message: error instanceof Error ? error.message : 'Unknown error',
            code: 'DAST_SCAN_ERROR'
          }, null, 2)
        }]
      };
    }
  }

  private async validateTarget(targetUrl: string): Promise<void> {
    try {
      const response = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true
      });
      
      if (response.status >= 500) {
        throw new Error(`Target returned server error: ${response.status}`);
      }
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.code === 'ECONNREFUSED') {
          throw new Error('Target URL is not accessible');
        }
        if (error.code === 'ENOTFOUND') {
          throw new Error('Target URL domain not found');
        }
      }
      throw new Error(`Target validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async runZAPScan(params: DASTParams): Promise<DASTScanResult> {
    const scanId = `dast-zap-${Date.now()}`;
    const scanType = params.scan_type || 'baseline';
    
    try {
      let scanResult;
      
      switch (scanType) {
        case 'quick':
          scanResult = await this.runZAPQuickScan(params, scanId);
          break;
        case 'baseline':
          scanResult = await this.runZAPBaselineScan(params, scanId);
          break;
        case 'full':
          scanResult = await this.runZAPFullScan(params, scanId);
          break;
        default:
          scanResult = await this.runZAPBaselineScan(params, scanId);
      }

      return scanResult;
    } catch (error) {
      logger.error('ZAP scan failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      throw error;
    }
  }

  private async runZAPQuickScan(params: DASTParams, scanId: string): Promise<DASTScanResult> {
    return new Promise((resolve, reject) => {
      const zapArgs = [
        '-cmd',
        '-quickurl', params.target_url,
        '-quickout', `/tmp/zap-report-${scanId}.json`,
        '-quickprogress'
      ];

      const zap = spawn('zap-baseline.py', zapArgs);
      let output = '';
      let errorOutput = '';

      zap.stdout.on('data', (data) => {
        output += data.toString();
      });

      zap.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      zap.on('close', async (code) => {
        try {
          const result = await this.parseZAPResults(scanId, params, 'quick');
          resolve(result);
        } catch (parseError) {
          reject(new Error(`Failed to parse ZAP results: ${parseError instanceof Error ? parseError.message : 'Unknown error'}`));
        }
      });
    });
  }

  private async runZAPBaselineScan(params: DASTParams, scanId: string): Promise<DASTScanResult> {
    const zapScanParams = {
      targetUrl: params.target_url,
      scanId: scanId,
      spiderOptions: params.spider_options || {},
      authentication: params.authentication
    };

    const zapResult = await this.zapConnector.executeBaselineScan(zapScanParams);
    
    return this.mapZAPResultToDASTResult(zapResult, scanId, params, 'baseline');
  }

  private async runZAPFullScan(params: DASTParams, scanId: string): Promise<DASTScanResult> {
    const zapScanParams = {
      targetUrl: params.target_url,
      scanId: scanId,
      spiderOptions: params.spider_options || {},
      authentication: params.authentication,
      activeScanPolicy: params.active_scan_policy || 'Default Policy'
    };

    const zapResult = await this.zapConnector.executeFullScan(zapScanParams);
    
    return this.mapZAPResultToDASTResult(zapResult, scanId, params, 'full');
  }

  private async parseZAPResults(scanId: string, params: DASTParams, scanType: string): Promise<DASTScanResult> {
    const vulnerabilities: DASTVulnerability[] = [];
    const coverage = {
      urls_found: 0,
      urls_tested: 0,
      forms_found: 0,
      parameters_tested: 0
    };

    return {
      tool: 'OWASP ZAP',
      scan_id: scanId,
      status: 'completed',
      target_url: params.target_url,
      vulnerabilities,
      summary: this.calculateSummary(vulnerabilities),
      coverage,
      metadata: {
        scan_duration: 0,
        scan_type: scanType,
        timestamp: new Date().toISOString()
      }
    };
  }

  private mapZAPResultToDASTResult(zapResult: any, scanId: string, params: DASTParams, scanType: string): DASTScanResult {
    const vulnerabilities = zapResult.alerts?.map(this.mapZAPAlertToVulnerability) || [];
    
    return {
      tool: 'OWASP ZAP',
      scan_id: scanId,
      status: 'completed',
      target_url: params.target_url,
      vulnerabilities,
      summary: this.calculateSummary(vulnerabilities),
      coverage: {
        urls_found: zapResult.spider?.urlsFound || 0,
        urls_tested: zapResult.spider?.urlsProcessed || 0,
        forms_found: zapResult.spider?.formsFound || 0,
        parameters_tested: zapResult.activeScan?.parametersProcessed || 0
      },
      metadata: {
        scan_duration: zapResult.scanDuration || 0,
        scan_type: scanType,
        timestamp: new Date().toISOString()
      }
    };
  }

  private mapZAPAlertToVulnerability(alert: any): DASTVulnerability {
    return {
      id: alert.pluginId || alert.id,
      name: alert.name || alert.title,
      severity: this.mapZAPRiskToSeverity(alert.riskcode || alert.risk),
      confidence: this.mapZAPConfidence(alert.confidence),
      description: alert.description || alert.desc,
      url: alert.url,
      method: alert.method || 'GET',
      parameter: alert.param,
      attack: alert.attack || alert.evidence,
      evidence: alert.evidence,
      reference: alert.reference || alert.ref,
      solution: alert.solution,
      cwe_id: parseInt(alert.cweid) || undefined,
      wasc_id: parseInt(alert.wascid) || undefined
    };
  }

  private mapZAPRiskToSeverity(risk: string | number): 'low' | 'medium' | 'high' | 'critical' {
    if (typeof risk === 'number') {
      switch (risk) {
        case 3: return 'critical';
        case 2: return 'high';
        case 1: return 'medium';
        default: return 'low';
      }
    }
    
    const riskLower = risk.toLowerCase();
    if (riskLower.includes('high')) return 'high';
    if (riskLower.includes('medium')) return 'medium';
    if (riskLower.includes('low')) return 'low';
    return 'medium';
  }

  private mapZAPConfidence(confidence: string | number): 'low' | 'medium' | 'high' {
    if (typeof confidence === 'number') {
      if (confidence >= 3) return 'high';
      if (confidence >= 2) return 'medium';
      return 'low';
    }
    
    const confLower = confidence.toLowerCase();
    if (confLower.includes('high')) return 'high';
    if (confLower.includes('medium')) return 'medium';
    return 'low';
  }

  private calculateSummary(vulnerabilities: DASTVulnerability[]): DASTScanResult['summary'] {
    const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
    
    vulnerabilities.forEach(vuln => {
      summary.total++;
      
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
    });

    return summary;
  }
}