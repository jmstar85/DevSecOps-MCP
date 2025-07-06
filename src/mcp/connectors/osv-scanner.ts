import { spawn } from 'child_process';
// import { promises as fs } from 'fs';
import path from 'path';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

interface OSVScannerConfig {
  binPath?: string;
  timeout?: number;
  dbPath?: string;
}

interface OSVScanParams {
  projectPath: string;
  packageManager: string;
  severity: string;
  includeDev: boolean;
  format: 'json' | 'table' | 'sarif';
  recursive?: boolean;
}

interface OSVVulnerability {
  id: string;
  summary: string;
  details: string;
  severity: string;
  affected: Array<{
    package: {
      ecosystem: string;
      name: string;
    };
    ranges: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
      }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{
    type: string;
    url: string;
  }>;
  aliases?: string[];
  database_specific?: {
    cwe_ids?: string[];
    github_reviewed?: boolean;
    severity?: string;
  };
  published?: string;
  modified?: string;
}

interface OSVScanResult {
  results: Array<{
    source: {
      path: string;
      type: string;
    };
    packages: Array<{
      package: {
        name: string;
        version: string;
        ecosystem: string;
      };
      vulnerabilities?: OSVVulnerability[];
      groups?: Array<{
        ids: string[];
        aliases?: string[];
      }>;
    }>;
  }>;
  experimental_config?: any;
}

export class OSVScannerConnector {
  private config: OSVScannerConfig;

  constructor(config?: OSVScannerConfig) {
    this.config = config || {
      binPath: process.env['OSV_SCANNER_PATH'] || 'osv-scanner',
      timeout: 300000,
      dbPath: process.env['OSV_DB_PATH']
    };
  }

  async executeScan(params: OSVScanParams): Promise<any> {
    try {
      logger.info('Starting OSV Scanner scan', {
        projectPath: params.projectPath,
        packageManager: params.packageManager
      });

      const scanResult = await this.runOSVScanner(params);
      
      return {
        ok: scanResult.results.length === 0 || !this.hasHighSeverityVulns(scanResult),
        vulnerabilities: this.extractVulnerabilities(scanResult),
        dependencyCount: this.countDependencies(scanResult),
        summary: this.generateSummary(scanResult),
        remediation: this.generateRemediation(scanResult),
        metadata: {
          scanner: 'OSV Scanner',
          timestamp: new Date().toISOString(),
          projectPath: params.projectPath,
          format: params.format
        }
      };

    } catch (error) {
      logger.error('OSV Scanner scan failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        projectPath: params.projectPath
      });
      throw error;
    }
  }

  private async runOSVScanner(params: OSVScanParams): Promise<OSVScanResult> {
    return new Promise((resolve, reject) => {
      const args = [
        '--format', params.format,
        '--output', '-'
      ];

      if (params.recursive) {
        args.push('--recursive');
      }

      // Add lockfile-specific scanning
      if (params.packageManager === 'npm') {
        args.push('--lockfile', path.join(params.projectPath, 'package-lock.json'));
      } else if (params.packageManager === 'yarn') {
        args.push('--lockfile', path.join(params.projectPath, 'yarn.lock'));
      } else if (params.packageManager === 'pip') {
        args.push('--lockfile', path.join(params.projectPath, 'requirements.txt'));
      } else if (params.packageManager === 'maven') {
        args.push('--lockfile', path.join(params.projectPath, 'pom.xml'));
      } else if (params.packageManager === 'gradle') {
        args.push('--lockfile', path.join(params.projectPath, 'build.gradle'));
      } else {
        // Scan entire directory
        args.push(params.projectPath);
      }

      const osvScanner = spawn(this.config.binPath!, args, {
        cwd: params.projectPath,
        timeout: this.config.timeout
      });

      let output = '';
      let errorOutput = '';

      osvScanner.stdout.on('data', (data) => {
        output += data.toString();
      });

      osvScanner.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      osvScanner.on('close', (code) => {
        if (code !== 0 && code !== 1) { // 1 means vulnerabilities found
          reject(new Error(`OSV Scanner failed with code ${code}: ${errorOutput}`));
          return;
        }

        try {
          if (params.format === 'json') {
            const result = JSON.parse(output);
            resolve(result);
          } else {
            // For non-JSON formats, create a minimal result structure
            resolve({
              results: [],
              experimental_config: null
            });
          }
        } catch (parseError) {
          reject(new Error(`Failed to parse OSV Scanner output: ${parseError instanceof Error ? parseError.message : 'Unknown error'}`));
        }
      });

      osvScanner.on('error', (error) => {
        reject(new Error(`Failed to start OSV Scanner: ${error.message}`));
      });
    });
  }

  private hasHighSeverityVulns(scanResult: OSVScanResult): boolean {
    return scanResult.results.some(result =>
      result.packages.some(pkg =>
        pkg.vulnerabilities?.some(vuln =>
          this.mapSeverity(vuln.database_specific?.severity || '') === 'high' ||
          this.mapSeverity(vuln.database_specific?.severity || '') === 'critical'
        )
      )
    );
  }

  private extractVulnerabilities(scanResult: OSVScanResult): any[] {
    const vulnerabilities: any[] = [];

    scanResult.results.forEach(result => {
      result.packages.forEach(pkg => {
        pkg.vulnerabilities?.forEach(vuln => {
          vulnerabilities.push({
            id: vuln.id,
            title: vuln.summary,
            description: vuln.details,
            severity: this.mapSeverity(vuln.database_specific?.severity || 'medium'),
            packageName: pkg.package.name,
            version: pkg.package.version,
            ecosystem: pkg.package.ecosystem,
            aliases: vuln.aliases || [],
            references: vuln.references || [],
            cwe_ids: vuln.database_specific?.cwe_ids || [],
            published: vuln.published,
            modified: vuln.modified,
            affected_ranges: vuln.affected.map(affected => ({
              ecosystem: affected.package.ecosystem,
              name: affected.package.name,
              ranges: affected.ranges
            }))
          });
        });
      });
    });

    return vulnerabilities;
  }

  private mapSeverity(severity: string): string {
    const severityMap: { [key: string]: string } = {
      'CRITICAL': 'critical',
      'HIGH': 'high',
      'MODERATE': 'medium',
      'MEDIUM': 'medium',
      'LOW': 'low',
      'UNKNOWN': 'medium'
    };

    return severityMap[severity.toUpperCase()] || 'medium';
  }

  private countDependencies(scanResult: OSVScanResult): number {
    let total = 0;
    scanResult.results.forEach(result => {
      total += result.packages.length;
    });
    return total;
  }

  private generateSummary(scanResult: OSVScanResult): any {
    const vulnerabilities = this.extractVulnerabilities(scanResult);
    
    return {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length
    };
  }

  private generateRemediation(scanResult: OSVScanResult): any {
    const upgrades: any[] = [];
    const vulnerabilities = this.extractVulnerabilities(scanResult);

    vulnerabilities.forEach(vuln => {
      vuln.affected_ranges.forEach((affected: any) => {
        affected.ranges.forEach((range: any) => {
          range.events.forEach((event: any) => {
            if (event.fixed) {
              upgrades.push({
                package_name: affected.name,
                from: vuln.version,
                to: event.fixed,
                fixes: [vuln.id]
              });
            }
          });
        });
      });
    });

    return {
      upgrades: upgrades,
      patches: [] // OSV Scanner doesn't provide patch information
    };
  }

  async checkInstallation(): Promise<boolean> {
    return new Promise((resolve) => {
      const osvScanner = spawn(this.config.binPath!, ['--version']);
      
      osvScanner.on('close', (code) => {
        resolve(code === 0);
      });

      osvScanner.on('error', () => {
        resolve(false);
      });
    });
  }

  async updateDatabase(): Promise<void> {
    return new Promise((resolve, reject) => {
      logger.info('Updating OSV vulnerability database');
      
      const args = ['--update'];
      if (this.config.dbPath) {
        args.push('--db', this.config.dbPath);
      }

      const osvScanner = spawn(this.config.binPath!, args);

      osvScanner.on('close', (code) => {
        if (code === 0) {
          logger.info('OSV database updated successfully');
          resolve();
        } else {
          reject(new Error(`Failed to update OSV database, exit code: ${code}`));
        }
      });

      osvScanner.on('error', (error) => {
        reject(new Error(`Failed to update OSV database: ${error.message}`));
      });
    });
  }

  async scanSBOM(sbomPath: string): Promise<OSVScanResult> {
    return new Promise((resolve, reject) => {
      const args = ['--sbom', sbomPath, '--format', 'json'];

      const osvScanner = spawn(this.config.binPath!, args);
      let output = '';
      let errorOutput = '';

      osvScanner.stdout.on('data', (data) => {
        output += data.toString();
      });

      osvScanner.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      osvScanner.on('close', (code) => {
        if (code !== 0 && code !== 1) {
          reject(new Error(`OSV Scanner SBOM scan failed: ${errorOutput}`));
          return;
        }

        try {
          const result = JSON.parse(output);
          resolve(result);
        } catch (parseError) {
          reject(new Error(`Failed to parse OSV Scanner SBOM output: ${parseError instanceof Error ? parseError.message : 'Unknown error'}`));
        }
      });
    });
  }
}