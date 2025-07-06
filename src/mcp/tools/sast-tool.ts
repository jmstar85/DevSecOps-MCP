import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import Joi from 'joi';
import winston from 'winston';
import { SonarQubeConnector } from '../connectors/sonarqube.js';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

interface SASTParams {
  target: string;
  rules?: string[];
  severity_threshold?: 'low' | 'medium' | 'high' | 'critical';
  tool?: 'sonarqube' | 'semgrep' | 'auto';
}

interface Vulnerability {
  id: string;
  severity: string;
  type: string;
  description: string;
  file: string;
  line: number;
  remediation?: string;
}

interface ScanResult {
  tool: string;
  scan_id: string;
  status: 'completed' | 'failed' | 'running';
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  metadata: {
    scan_duration: number;
    target: string;
    timestamp: string;
  };
}

export class SASTTool {
  private sonarQubeConnector: SonarQubeConnector;
  private readonly validationSchema = Joi.object({
    target: Joi.string().required(),
    rules: Joi.array().items(Joi.string()).optional(),
    severity_threshold: Joi.string().valid('low', 'medium', 'high', 'critical').optional(),
    tool: Joi.string().valid('sonarqube', 'semgrep', 'auto').optional()
  });

  constructor() {
    this.sonarQubeConnector = new SonarQubeConnector();
  }

  async executeScan(params: SASTParams): Promise<any> {
    const startTime = Date.now();
    
    try {
      const { error, value } = this.validationSchema.validate(params);
      if (error) {
        throw new Error(`Invalid parameters: ${error.details[0]?.message}`);
      }

      const validatedParams = value as SASTParams;
      logger.info('Starting SAST scan', { target: validatedParams.target });

      await this.validateTarget(validatedParams.target);

      const tool = validatedParams.tool || await this.detectBestTool(validatedParams.target);
      let result: ScanResult;

      switch (tool) {
        case 'sonarqube':
          result = await this.runSonarQubeScan(validatedParams);
          break;
        case 'semgrep':
          result = await this.runSemgrepScan(validatedParams);
          break;
        default:
          result = await this.runAutoScan(validatedParams);
      }

      result.metadata.scan_duration = Date.now() - startTime;
      
      const filteredResult = this.filterBySeverity(result, validatedParams.severity_threshold);
      
      logger.info('SAST scan completed', {
        scan_id: result.scan_id,
        total_vulnerabilities: filteredResult.summary.total,
        duration: result.metadata.scan_duration
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(filteredResult, null, 2)
        }]
      };

    } catch (error) {
      logger.error('SAST scan failed', { 
        error: error instanceof Error ? error.message : 'Unknown error',
        target: params.target 
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: 'SAST scan failed',
            message: error instanceof Error ? error.message : 'Unknown error',
            code: 'SAST_SCAN_ERROR'
          }, null, 2)
        }]
      };
    }
  }

  private async validateTarget(target: string): Promise<void> {
    try {
      if (target.startsWith('http')) {
        return;
      }

      const resolvedPath = path.resolve(target);
      const stats = await fs.stat(resolvedPath);
      
      if (!stats.isDirectory() && !stats.isFile()) {
        throw new Error('Target must be a valid file or directory');
      }
    } catch (error) {
      throw new Error(`Invalid target: ${target}`);
    }
  }

  private async detectBestTool(target: string): Promise<string> {
    try {
      if (target.startsWith('http')) {
        return 'sonarqube';
      }

      const resolvedPath = path.resolve(target);
      const files = await fs.readdir(resolvedPath);
      
      if (files.includes('pom.xml') || files.includes('build.gradle')) {
        return 'sonarqube';
      }
      
      if (files.includes('package.json') || files.includes('requirements.txt')) {
        return 'semgrep';
      }
      
      return 'semgrep';
    } catch {
      return 'semgrep';
    }
  }

  private async runSonarQubeScan(params: SASTParams): Promise<ScanResult> {
    const scanId = `sast-sonar-${Date.now()}`;
    
    try {
      const sonarResult = await this.sonarQubeConnector.executeScan({
        projectKey: `project-${scanId}`,
        projectName: `SAST Scan ${scanId}`,
        sources: params.target,
        qualityGate: 'Sonar way'
      });

      return {
        tool: 'SonarQube',
        scan_id: scanId,
        status: 'completed',
        vulnerabilities: sonarResult.issues.map(this.mapSonarIssueToVulnerability),
        summary: this.calculateSummary(sonarResult.issues),
        metadata: {
          scan_duration: 0,
          target: params.target,
          timestamp: new Date().toISOString()
        }
      };
    } catch (error) {
      logger.error('SonarQube scan failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      throw error;
    }
  }

  private async runSemgrepScan(params: SASTParams): Promise<ScanResult> {
    const scanId = `sast-semgrep-${Date.now()}`;
    
    return new Promise((resolve, reject) => {
      const semgrepArgs = [
        '--config=auto',
        '--json',
        '--no-git-ignore',
        params.target
      ];

      if (params.rules && params.rules.length > 0) {
        semgrepArgs.splice(1, 1, `--config=${params.rules.join(',')}`);
      }

      const semgrep = spawn('semgrep', semgrepArgs);
      let output = '';
      let errorOutput = '';

      semgrep.stdout.on('data', (data) => {
        output += data.toString();
      });

      semgrep.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      semgrep.on('close', (code) => {
        if (code !== 0 && code !== 1) {
          reject(new Error(`Semgrep failed with code ${code}: ${errorOutput}`));
          return;
        }

        try {
          const results = JSON.parse(output);
          const vulnerabilities = results.results?.map(this.mapSemgrepResultToVulnerability) || [];

          resolve({
            tool: 'Semgrep',
            scan_id: scanId,
            status: 'completed',
            vulnerabilities,
            summary: this.calculateSummaryFromVulnerabilities(vulnerabilities),
            metadata: {
              scan_duration: 0,
              target: params.target,
              timestamp: new Date().toISOString()
            }
          });
        } catch (parseError) {
          reject(new Error(`Failed to parse Semgrep output: ${parseError instanceof Error ? parseError.message : 'Unknown error'}`));
        }
      });
    });
  }

  private async runAutoScan(params: SASTParams): Promise<ScanResult> {
    try {
      return await this.runSemgrepScan(params);
    } catch (semgrepError) {
      logger.warn('Semgrep scan failed, falling back to SonarQube', { error: semgrepError });
      return await this.runSonarQubeScan(params);
    }
  }

  private mapSonarIssueToVulnerability(issue: any): Vulnerability {
    return {
      id: issue.key,
      severity: issue.severity.toLowerCase(),
      type: issue.type,
      description: issue.message,
      file: issue.component,
      line: issue.textRange?.startLine || 0,
      remediation: issue.rule ? `Apply rule: ${issue.rule}` : undefined
    };
  }

  private mapSemgrepResultToVulnerability(result: any): Vulnerability {
    return {
      id: result.check_id,
      severity: this.mapSemgrepSeverity(result.extra?.severity),
      type: result.extra?.metadata?.category || 'security',
      description: result.extra?.message || result.message,
      file: result.path,
      line: result.start?.line || 0,
      remediation: result.extra?.fix ? 'Auto-fix available' : undefined
    };
  }

  private mapSemgrepSeverity(severity: string): string {
    const mapping: { [key: string]: string } = {
      'ERROR': 'high',
      'WARNING': 'medium',
      'INFO': 'low'
    };
    return mapping[severity] || 'medium';
  }

  private calculateSummary(issues: any[]): ScanResult['summary'] {
    const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
    
    issues.forEach(issue => {
      const severity = issue.severity?.toLowerCase() || 'medium';
      summary.total++;
      
      if (severity === 'critical') summary.critical++;
      else if (severity === 'high') summary.high++;
      else if (severity === 'medium') summary.medium++;
      else summary.low++;
    });

    return summary;
  }

  private calculateSummaryFromVulnerabilities(vulnerabilities: Vulnerability[]): ScanResult['summary'] {
    const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
    
    vulnerabilities.forEach(vuln => {
      summary.total++;
      
      if (vuln.severity === 'critical') summary.critical++;
      else if (vuln.severity === 'high') summary.high++;
      else if (vuln.severity === 'medium') summary.medium++;
      else summary.low++;
    });

    return summary;
  }

  private filterBySeverity(result: ScanResult, threshold?: string): ScanResult {
    if (!threshold) return result;

    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const thresholdIndex = severityOrder.indexOf(threshold);
    
    if (thresholdIndex === -1) return result;

    const filteredVulnerabilities = result.vulnerabilities.filter(vuln => {
      const vulnIndex = severityOrder.indexOf(vuln.severity);
      return vulnIndex >= thresholdIndex;
    });

    return {
      ...result,
      vulnerabilities: filteredVulnerabilities,
      summary: this.calculateSummaryFromVulnerabilities(filteredVulnerabilities)
    };
  }
}