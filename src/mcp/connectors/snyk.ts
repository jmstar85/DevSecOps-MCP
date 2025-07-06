import axios, { AxiosInstance } from 'axios';
import { spawn } from 'child_process';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

interface SnykConfig {
  token: string;
  apiUrl?: string;
  timeout?: number;
}

interface SnykScanParams {
  projectPath: string;
  packageManager: string;
  severity: string;
  includeDev: boolean;
  generateSBOM: boolean;
  orgId?: string;
}

interface SnykVulnerability {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  packageName: string;
  version: string;
  semver: {
    vulnerable: string;
    patched?: string;
  };
  from: string[];
  upgradePath: string[];
  isUpgradable: boolean;
  isPatchable: boolean;
  isPinnable: boolean;
  identifiers: {
    CVE: string[];
    CWE: string[];
    ALTERNATIVE: string[];
  };
  credit: string[];
  CVSSv3: string;
  cvssScore: number;
  patches: any[];
  references: any[];
  publicationTime: string;
  disclosureTime: string;
  exploitMaturity: string;
  language: string;
  packageManager: string;
}

interface SnykLicenseIssue {
  id: string;
  packageName: string;
  version: string;
  license: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  policyViolation: string;
}

interface SnykScanResult {
  ok: boolean;
  dependenciesCount: number;
  directDependencies: number;
  transitiveDependencies: number;
  vulnerabilities: SnykVulnerability[];
  licenseIssues: SnykLicenseIssue[];
  summary: {
    total: number;
    high: number;
    medium: number;
    low: number;
  };
  remediation: {
    unresolved: any[];
    upgrade: any[];
    patch: any[];
    ignore: any[];
    pin: any[];
  };
  sbom?: {
    components: any[];
    dependencies: any[];
  };
}

export class SnykConnector {
  private client: AxiosInstance;
  private config: SnykConfig;

  constructor(config?: SnykConfig) {
    this.config = config || {
      token: process.env.SNYK_TOKEN || '',
      apiUrl: process.env.SNYK_API_URL || 'https://api.snyk.io/v1',
      timeout: 300000
    };

    if (!this.config.token) {
      throw new Error('Snyk token is required');
    }

    this.client = axios.create({
      baseURL: this.config.apiUrl,
      timeout: this.config.timeout,
      headers: {
        'Authorization': `token ${this.config.token}`,
        'Content-Type': 'application/json'
      }
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    this.client.interceptors.request.use(
      (config) => {
        logger.debug('Snyk API request', {
          method: config.method,
          url: config.url,
          params: config.params
        });
        return config;
      },
      (error) => {
        logger.error('Snyk API request error', { error: error.message });
        return Promise.reject(error);
      }
    );

    this.client.interceptors.response.use(
      (response) => {
        logger.debug('Snyk API response', {
          status: response.status,
          url: response.config.url
        });
        return response;
      },
      (error) => {
        logger.error('Snyk API response error', {
          status: error.response?.status,
          message: error.message,
          url: error.config?.url
        });
        return Promise.reject(error);
      }
    );
  }

  async executeScan(params: SnykScanParams): Promise<SnykScanResult> {
    try {
      logger.info('Starting Snyk scan', {
        projectPath: params.projectPath,
        packageManager: params.packageManager
      });

      // Use CLI for scanning as it provides more comprehensive results
      const cliResult = await this.runSnykCLI(params);
      
      // Enhance with API data if needed
      if (params.generateSBOM && params.orgId) {
        const sbomData = await this.generateSBOM(params.orgId, params.projectPath);
        cliResult.sbom = sbomData;
      }

      return cliResult;

    } catch (error) {
      logger.error('Snyk scan failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        projectPath: params.projectPath
      });
      
      return {
        ok: false,
        dependenciesCount: 0,
        directDependencies: 0,
        transitiveDependencies: 0,
        vulnerabilities: [],
        licenseIssues: [],
        summary: { total: 0, high: 0, medium: 0, low: 0 },
        remediation: {
          unresolved: [],
          upgrade: [],
          patch: [],
          ignore: [],
          pin: []
        }
      };
    }
  }

  private async runSnykCLI(params: SnykScanParams): Promise<SnykScanResult> {
    return new Promise((resolve, reject) => {
      const snykArgs = [
        'test',
        '--json',
        `--severity-threshold=${params.severity}`,
        `--package-manager=${params.packageManager}`
      ];

      if (params.includeDev) {
        snykArgs.push('--dev');
      }

      if (process.env.SNYK_TOKEN) {
        snykArgs.unshift('auth', process.env.SNYK_TOKEN, '&&', 'snyk');
      }

      const snyk = spawn('snyk', snykArgs, {
        cwd: params.projectPath,
        env: { ...process.env, SNYK_TOKEN: this.config.token }
      });

      let output = '';
      let errorOutput = '';

      snyk.stdout.on('data', (data) => {
        output += data.toString();
      });

      snyk.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      snyk.on('close', async (code) => {
        try {
          // Snyk CLI returns exit code 1 when vulnerabilities are found
          if (code !== 0 && code !== 1) {
            reject(new Error(`Snyk CLI failed with code ${code}: ${errorOutput}`));
            return;
          }

          const result = JSON.parse(output);
          const snykResult = this.parseSnykCLIResult(result);
          
          // Get license issues separately
          const licenseIssues = await this.getLicenseIssues(params);
          snykResult.licenseIssues = licenseIssues;

          resolve(snykResult);
        } catch (parseError) {
          reject(new Error(`Failed to parse Snyk CLI output: ${parseError instanceof Error ? parseError.message : 'Unknown error'}`));
        }
      });
    });
  }

  private parseSnykCLIResult(result: any): SnykScanResult {
    const vulnerabilities = result.vulnerabilities || [];
    
    return {
      ok: result.ok || false,
      dependenciesCount: result.dependencyCount || 0,
      directDependencies: result.packageManager?.directDependencies || 0,
      transitiveDependencies: result.packageManager?.transitiveDependencies || 0,
      vulnerabilities: vulnerabilities.map(this.mapSnykVulnerability),
      licenseIssues: [],
      summary: {
        total: result.uniqueCount || 0,
        high: vulnerabilities.filter((v: any) => v.severity === 'high').length,
        medium: vulnerabilities.filter((v: any) => v.severity === 'medium').length,
        low: vulnerabilities.filter((v: any) => v.severity === 'low').length
      },
      remediation: result.remediation || {
        unresolved: [],
        upgrade: [],
        patch: [],
        ignore: [],
        pin: []
      }
    };
  }

  private mapSnykVulnerability(vuln: any): SnykVulnerability {
    return {
      id: vuln.id,
      title: vuln.title,
      description: vuln.description,
      severity: vuln.severity,
      packageName: vuln.packageName,
      version: vuln.version,
      semver: vuln.semver || { vulnerable: '', patched: '' },
      from: vuln.from || [],
      upgradePath: vuln.upgradePath || [],
      isUpgradable: vuln.isUpgradable || false,
      isPatchable: vuln.isPatchable || false,
      isPinnable: vuln.isPinnable || false,
      identifiers: vuln.identifiers || { CVE: [], CWE: [], ALTERNATIVE: [] },
      credit: vuln.credit || [],
      CVSSv3: vuln.CVSSv3 || '',
      cvssScore: vuln.cvssScore || 0,
      patches: vuln.patches || [],
      references: vuln.references || [],
      publicationTime: vuln.publicationTime || '',
      disclosureTime: vuln.disclosureTime || '',
      exploitMaturity: vuln.exploitMaturity || '',
      language: vuln.language || '',
      packageManager: vuln.packageManager || ''
    };
  }

  private async getLicenseIssues(params: SnykScanParams): Promise<SnykLicenseIssue[]> {
    return new Promise((resolve) => {
      const snykArgs = [
        'test',
        '--json',
        '--print-deps',
        `--package-manager=${params.packageManager}`
      ];

      const snyk = spawn('snyk', snykArgs, {
        cwd: params.projectPath,
        env: { ...process.env, SNYK_TOKEN: this.config.token }
      });

      let output = '';

      snyk.stdout.on('data', (data) => {
        output += data.toString();
      });

      snyk.on('close', () => {
        try {
          const result = JSON.parse(output);
          const licenseIssues: SnykLicenseIssue[] = [];
          
          // Parse license information from dependencies
          if (result.dependencies) {
            Object.entries(result.dependencies).forEach(([name, dep]: [string, any]) => {
              if (dep.licenses && this.isLicenseViolation(dep.licenses)) {
                licenseIssues.push({
                  id: `license-${name}`,
                  packageName: name,
                  version: dep.version || '',
                  license: dep.licenses.join(', '),
                  severity: this.getLicenseSeverity(dep.licenses),
                  policyViolation: 'Unapproved license'
                });
              }
            });
          }
          
          resolve(licenseIssues);
        } catch {
          resolve([]);
        }
      });
    });
  }

  private isLicenseViolation(licenses: string[]): boolean {
    const approvedLicenses = ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC'];
    return !licenses.some(license => approvedLicenses.includes(license));
  }

  private getLicenseSeverity(licenses: string[]): 'low' | 'medium' | 'high' | 'critical' {
    const highRiskLicenses = ['GPL-3.0', 'AGPL-3.0', 'LGPL-3.0'];
    const mediumRiskLicenses = ['GPL-2.0', 'LGPL-2.1'];
    
    if (licenses.some(license => highRiskLicenses.includes(license))) {
      return 'high';
    }
    if (licenses.some(license => mediumRiskLicenses.includes(license))) {
      return 'medium';
    }
    return 'low';
  }

  private async generateSBOM(orgId: string, projectPath: string): Promise<any> {
    try {
      // Use Snyk CLI to generate SBOM
      return new Promise((resolve, reject) => {
        const snykArgs = [
          'sbom',
          '--format=spdx2.3+json',
          '--org', orgId
        ];

        const snyk = spawn('snyk', snykArgs, {
          cwd: projectPath,
          env: { ...process.env, SNYK_TOKEN: this.config.token }
        });

        let output = '';
        let errorOutput = '';

        snyk.stdout.on('data', (data) => {
          output += data.toString();
        });

        snyk.stderr.on('data', (data) => {
          errorOutput += data.toString();
        });

        snyk.on('close', (code) => {
          if (code === 0) {
            try {
              const sbom = JSON.parse(output);
              resolve({
                components: sbom.packages || [],
                dependencies: sbom.relationships || []
              });
            } catch (parseError) {
              reject(new Error(`Failed to parse SBOM: ${parseError instanceof Error ? parseError.message : 'Unknown error'}`));
            }
          } else {
            reject(new Error(`SBOM generation failed: ${errorOutput}`));
          }
        });
      });
    } catch (error) {
      logger.warn('Failed to generate SBOM', { error: error instanceof Error ? error.message : 'Unknown error' });
      return undefined;
    }
  }

  async getOrganizations(): Promise<any[]> {
    try {
      const response = await this.client.get('/orgs');
      return response.data.orgs || [];
    } catch (error) {
      throw new Error(`Failed to get organizations: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getProjects(orgId: string): Promise<any[]> {
    try {
      const response = await this.client.get(`/org/${orgId}/projects`);
      return response.data.projects || [];
    } catch (error) {
      throw new Error(`Failed to get projects: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getVulnerabilities(orgId: string, projectId: string): Promise<any[]> {
    try {
      const response = await this.client.post(`/org/${orgId}/project/${projectId}/issues`, {
        filters: {
          severities: ['high', 'medium', 'low'],
          types: ['vuln'],
          ignored: false,
          patched: false
        }
      });
      return response.data.issues || [];
    } catch (error) {
      throw new Error(`Failed to get vulnerabilities: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async ignoreVulnerability(orgId: string, projectId: string, issueId: string, reason: string): Promise<void> {
    try {
      await this.client.post(`/org/${orgId}/project/${projectId}/ignore/${issueId}`, {
        ignorePath: '*',
        reasonType: 'not-vulnerable',
        reason: reason,
        expires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString() // 1 year
      });
      
      logger.info('Vulnerability ignored', { orgId, projectId, issueId });
    } catch (error) {
      throw new Error(`Failed to ignore vulnerability: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async monitorProject(projectPath: string, orgId?: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const snykArgs = ['monitor'];
      
      if (orgId) {
        snykArgs.push('--org', orgId);
      }

      const snyk = spawn('snyk', snykArgs, {
        cwd: projectPath,
        env: { ...process.env, SNYK_TOKEN: this.config.token }
      });

      let output = '';
      let errorOutput = '';

      snyk.stdout.on('data', (data) => {
        output += data.toString();
      });

      snyk.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      snyk.on('close', (code) => {
        if (code === 0) {
          resolve({ success: true, output });
        } else {
          reject(new Error(`Project monitoring failed: ${errorOutput}`));
        }
      });
    });
  }
}