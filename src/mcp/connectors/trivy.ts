import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

interface TrivyConfig {
  binPath?: string;
  timeout?: number;
  cacheDir?: string;
  dbPath?: string;
}

interface TrivyScanParams {
  target: string;
  scanType: 'fs' | 'image' | 'config' | 'repo';
  format: 'json' | 'table' | 'sarif' | 'template';
  severity: string[];
  vulnTypes: string[];
  securityChecks: string[];
  ignoreUnfixed?: boolean;
  skipUpdate?: boolean;
}

interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  PkgPath?: string;
  PkgID?: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Status?: string;
  Layer?: {
    Digest: string;
    DiffID: string;
  };
  SeveritySource?: string;
  PrimaryURL?: string;
  DataSource?: {
    ID: string;
    Name: string;
    URL: string;
  };
  Title: string;
  Description: string;
  Severity: string;
  CweIDs?: string[];
  CVSS?: {
    [vendor: string]: {
      V2Vector?: string;
      V3Vector?: string;
      V2Score?: number;
      V3Score?: number;
    };
  };
  References?: string[];
  PublishedDate?: string;
  LastModifiedDate?: string;
}

interface TrivyMisconfiguration {
  Type: string;
  ID: string;
  AVDID: string;
  Title: string;
  Description: string;
  Message: string;
  Namespace: string;
  Query: string;
  Resolution: string;
  Severity: string;
  PrimaryURL: string;
  References?: string[];
  Status: string;
  Layer?: {
    Digest: string;
    DiffID: string;
  };
  CauseMetadata: {
    Resource: string;
    Provider: string;
    Service: string;
    StartLine?: number;
    EndLine?: number;
    Code?: {
      Lines: Array<{
        Number: number;
        Content: string;
        IsCause: boolean;
        Annotation: string;
        Truncated: boolean;
        FirstCause: boolean;
        LastCause: boolean;
      }>;
    };
  };
}

interface TrivySecret {
  RuleID: string;
  Category: string;
  Severity: string;
  Title: string;
  StartLine: number;
  EndLine: number;
  Code: {
    Lines: Array<{
      Number: number;
      Content: string;
      IsCause: boolean;
      Annotation: string;
      Truncated: boolean;
      FirstCause: boolean;
      LastCause: boolean;
    }>;
  };
  Match: string;
  Layer?: {
    Digest: string;
    DiffID: string;
  };
}

interface TrivyResult {
  Target: string;
  Class: string;
  Type: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
  Secrets?: TrivySecret[];
}

interface TrivyScanResult {
  SchemaVersion: number;
  ArtifactName: string;
  ArtifactType: string;
  Metadata?: {
    OS?: {
      Family: string;
      Name: string;
      EOSL?: boolean;
    };
    ImageID?: string;
    DiffIDs?: string[];
    RepoTags?: string[];
    RepoDigests?: string[];
    ImageConfig?: any;
  };
  Results?: TrivyResult[];
}

export class TrivyConnector {
  private config: TrivyConfig;

  constructor(config?: TrivyConfig) {
    this.config = config || {
      binPath: process.env.TRIVY_PATH || 'trivy',
      timeout: 300000,
      cacheDir: process.env.TRIVY_CACHE_DIR || '/tmp/trivy-cache',
      dbPath: process.env.TRIVY_DB_PATH
    };
  }

  async executeScan(params: TrivyScanParams): Promise<any> {
    try {
      logger.info('Starting Trivy scan', {
        target: params.target,
        scanType: params.scanType
      });

      const scanResult = await this.runTrivy(params);
      
      return {
        ok: !this.hasHighSeverityIssues(scanResult),
        target: params.target,
        scanType: params.scanType,
        vulnerabilities: this.extractVulnerabilities(scanResult),
        misconfigurations: this.extractMisconfigurations(scanResult),
        secrets: this.extractSecrets(scanResult),
        summary: this.generateSummary(scanResult),
        metadata: {
          scanner: 'Trivy',
          timestamp: new Date().toISOString(),
          artifactName: scanResult.ArtifactName,
          artifactType: scanResult.ArtifactType,
          os: scanResult.Metadata?.OS
        }
      };

    } catch (error) {
      logger.error('Trivy scan failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        target: params.target
      });
      throw error;
    }
  }

  private async runTrivy(params: TrivyScanParams): Promise<TrivyScanResult> {
    return new Promise((resolve, reject) => {
      const args = [
        params.scanType,
        '--format', params.format,
        '--cache-dir', this.config.cacheDir!
      ];

      // Add severity filters
      if (params.severity.length > 0) {
        args.push('--severity', params.severity.join(','));
      }

      // Add vulnerability types
      if (params.vulnTypes.length > 0) {
        args.push('--vuln-type', params.vulnTypes.join(','));
      }

      // Add security checks
      if (params.securityChecks.length > 0) {
        args.push('--security-checks', params.securityChecks.join(','));
      }

      // Add other options
      if (params.ignoreUnfixed) {
        args.push('--ignore-unfixed');
      }

      if (params.skipUpdate) {
        args.push('--skip-update');
      }

      // Add DB path if specified
      if (this.config.dbPath) {
        args.push('--cache-dir', this.config.dbPath);
      }

      // Add target
      args.push(params.target);

      const trivy = spawn(this.config.binPath!, args, {
        timeout: this.config.timeout
      });

      let output = '';
      let errorOutput = '';

      trivy.stdout.on('data', (data) => {
        output += data.toString();
      });

      trivy.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      trivy.on('close', (code) => {
        if (code !== 0) {
          reject(new Error(`Trivy scan failed with code ${code}: ${errorOutput}`));
          return;
        }

        try {
          if (params.format === 'json') {
            const result = JSON.parse(output);
            resolve(result);
          } else {
            // For non-JSON formats, create a minimal result structure
            resolve({
              SchemaVersion: 2,
              ArtifactName: params.target,
              ArtifactType: params.scanType,
              Results: []
            });
          }
        } catch (parseError) {
          reject(new Error(`Failed to parse Trivy output: ${parseError instanceof Error ? parseError.message : 'Unknown error'}`));
        }
      });

      trivy.on('error', (error) => {
        reject(new Error(`Failed to start Trivy: ${error.message}`));
      });
    });
  }

  private hasHighSeverityIssues(scanResult: TrivyScanResult): boolean {
    if (!scanResult.Results) return false;

    return scanResult.Results.some(result => {
      const hasHighVulns = result.Vulnerabilities?.some(vuln => 
        vuln.Severity === 'HIGH' || vuln.Severity === 'CRITICAL'
      ) || false;

      const hasHighMisconfigs = result.Misconfigurations?.some(misc => 
        misc.Severity === 'HIGH' || misc.Severity === 'CRITICAL'
      ) || false;

      const hasHighSecrets = result.Secrets?.some(secret => 
        secret.Severity === 'HIGH' || secret.Severity === 'CRITICAL'
      ) || false;

      return hasHighVulns || hasHighMisconfigs || hasHighSecrets;
    });
  }

  private extractVulnerabilities(scanResult: TrivyScanResult): any[] {
    const vulnerabilities: any[] = [];

    scanResult.Results?.forEach(result => {
      result.Vulnerabilities?.forEach(vuln => {
        vulnerabilities.push({
          id: vuln.VulnerabilityID,
          title: vuln.Title,
          description: vuln.Description,
          severity: vuln.Severity.toLowerCase(),
          packageName: vuln.PkgName,
          installedVersion: vuln.InstalledVersion,
          fixedVersion: vuln.FixedVersion,
          packagePath: vuln.PkgPath,
          cwe_ids: vuln.CweIDs || [],
          cvss_scores: vuln.CVSS ? Object.values(vuln.CVSS).map(cvss => ({
            v2Score: cvss.V2Score,
            v3Score: cvss.V3Score,
            v2Vector: cvss.V2Vector,
            v3Vector: cvss.V3Vector
          })) : [],
          references: vuln.References || [],
          published: vuln.PublishedDate,
          lastModified: vuln.LastModifiedDate,
          primaryUrl: vuln.PrimaryURL,
          dataSource: vuln.DataSource,
          layer: vuln.Layer
        });
      });
    });

    return vulnerabilities;
  }

  private extractMisconfigurations(scanResult: TrivyScanResult): any[] {
    const misconfigurations: any[] = [];

    scanResult.Results?.forEach(result => {
      result.Misconfigurations?.forEach(misc => {
        misconfigurations.push({
          id: misc.ID,
          avdId: misc.AVDID,
          type: misc.Type,
          title: misc.Title,
          description: misc.Description,
          message: misc.Message,
          severity: misc.Severity.toLowerCase(),
          namespace: misc.Namespace,
          query: misc.Query,
          resolution: misc.Resolution,
          primaryUrl: misc.PrimaryURL,
          references: misc.References || [],
          status: misc.Status,
          resource: misc.CauseMetadata.Resource,
          provider: misc.CauseMetadata.Provider,
          service: misc.CauseMetadata.Service,
          startLine: misc.CauseMetadata.StartLine,
          endLine: misc.CauseMetadata.EndLine,
          code: misc.CauseMetadata.Code,
          layer: misc.Layer
        });
      });
    });

    return misconfigurations;
  }

  private extractSecrets(scanResult: TrivyScanResult): any[] {
    const secrets: any[] = [];

    scanResult.Results?.forEach(result => {
      result.Secrets?.forEach(secret => {
        secrets.push({
          ruleId: secret.RuleID,
          category: secret.Category,
          severity: secret.Severity.toLowerCase(),
          title: secret.Title,
          startLine: secret.StartLine,
          endLine: secret.EndLine,
          match: secret.Match,
          code: secret.Code,
          layer: secret.Layer
        });
      });
    });

    return secrets;
  }

  private generateSummary(scanResult: TrivyScanResult): any {
    const vulnerabilities = this.extractVulnerabilities(scanResult);
    const misconfigurations = this.extractMisconfigurations(scanResult);
    const secrets = this.extractSecrets(scanResult);

    return {
      vulnerabilities: {
        total: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length
      },
      misconfigurations: {
        total: misconfigurations.length,
        critical: misconfigurations.filter(m => m.severity === 'critical').length,
        high: misconfigurations.filter(m => m.severity === 'high').length,
        medium: misconfigurations.filter(m => m.severity === 'medium').length,
        low: misconfigurations.filter(m => m.severity === 'low').length
      },
      secrets: {
        total: secrets.length,
        critical: secrets.filter(s => s.severity === 'critical').length,
        high: secrets.filter(s => s.severity === 'high').length,
        medium: secrets.filter(s => s.severity === 'medium').length,
        low: secrets.filter(s => s.severity === 'low').length
      }
    };
  }

  async scanFilesystem(targetPath: string, options?: {
    skipDirs?: string[];
    skipFiles?: string[];
  }): Promise<any> {
    const params: TrivyScanParams = {
      target: targetPath,
      scanType: 'fs',
      format: 'json',
      severity: ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      vulnTypes: ['os', 'library'],
      securityChecks: ['vuln', 'config', 'secret']
    };

    return this.executeScan(params);
  }

  async scanImage(imageName: string, options?: {
    removeContainers?: boolean;
    skipUpdate?: boolean;
  }): Promise<any> {
    const params: TrivyScanParams = {
      target: imageName,
      scanType: 'image',
      format: 'json',
      severity: ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      vulnTypes: ['os', 'library'],
      securityChecks: ['vuln', 'config', 'secret'],
      skipUpdate: options?.skipUpdate
    };

    return this.executeScan(params);
  }

  async scanRepository(repoUrl: string, options?: {
    branch?: string;
    commit?: string;
  }): Promise<any> {
    let target = repoUrl;
    if (options?.branch) {
      target += `#${options.branch}`;
    } else if (options?.commit) {
      target += `#${options.commit}`;
    }

    const params: TrivyScanParams = {
      target: target,
      scanType: 'repo',
      format: 'json',
      severity: ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      vulnTypes: ['os', 'library'],
      securityChecks: ['vuln', 'config', 'secret']
    };

    return this.executeScan(params);
  }

  async updateDatabase(): Promise<void> {
    return new Promise((resolve, reject) => {
      logger.info('Updating Trivy vulnerability database');
      
      const args = ['image', '--download-db-only'];

      const trivy = spawn(this.config.binPath!, args);

      trivy.on('close', (code) => {
        if (code === 0) {
          logger.info('Trivy database updated successfully');
          resolve();
        } else {
          reject(new Error(`Failed to update Trivy database, exit code: ${code}`));
        }
      });

      trivy.on('error', (error) => {
        reject(new Error(`Failed to update Trivy database: ${error.message}`));
      });
    });
  }

  async checkInstallation(): Promise<boolean> {
    return new Promise((resolve) => {
      const trivy = spawn(this.config.binPath!, ['--version']);
      
      trivy.on('close', (code) => {
        resolve(code === 0);
      });

      trivy.on('error', () => {
        resolve(false);
      });
    });
  }
}