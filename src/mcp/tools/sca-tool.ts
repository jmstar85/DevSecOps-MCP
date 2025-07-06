import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import Joi from 'joi';
import winston from 'winston';
import { OSVScannerConnector } from '../connectors/osv-scanner.js';
import { TrivyConnector } from '../connectors/trivy.js';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

interface SCAParams {
  project_path: string;
  package_manager?: 'npm' | 'yarn' | 'maven' | 'gradle' | 'pip' | 'composer' | 'auto';
  fix_vulnerabilities?: boolean;
  severity_threshold?: 'low' | 'medium' | 'high' | 'critical';
  include_dev_dependencies?: boolean;
  tool?: 'osv-scanner' | 'trivy' | 'npm-audit' | 'auto';
  license_check?: boolean;
  generate_sbom?: boolean;
}

interface SCAVulnerability {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  package_name: string;
  package_version: string;
  vulnerable_versions: string;
  patched_versions?: string;
  description: string;
  references: string[];
  cve_ids?: string[];
  cwe_ids?: string[];
  cvss_score?: number;
  exploitability?: string;
  fix_available?: boolean;
  fix_version?: string;
  upgrade_path?: string[];
}

interface LicenseIssue {
  package_name: string;
  package_version: string;
  license: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  policy_violation: string;
}

interface SBOMComponent {
  name: string;
  version: string;
  purl: string;
  licenses: string[];
  hashes?: string[];
  supplier?: string;
  dependencies?: string[];
}

interface SCAScanResult {
  tool: string;
  scan_id: string;
  status: 'completed' | 'failed' | 'running';
  project_path: string;
  package_manager: string;
  vulnerabilities: SCAVulnerability[];
  license_issues: LicenseIssue[];
  sbom?: {
    components: SBOMComponent[];
    dependencies_count: number;
    direct_dependencies: number;
    transitive_dependencies: number;
  };
  summary: {
    total_vulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    fixable: number;
    license_violations: number;
  };
  remediation: {
    upgrades: Array<{
      package_name: string;
      from: string;
      to: string;
      fixes: string[];
    }>;
    patches: Array<{
      package_name: string;
      patch_id: string;
      fixes: string[];
    }>;
  };
  metadata: {
    scan_duration: number;
    total_dependencies: number;
    direct_dependencies: number;
    timestamp: string;
  };
}

export class SCATool {
  private osvScannerConnector: OSVScannerConnector;
  private trivyConnector: TrivyConnector;
  private readonly validationSchema = Joi.object({
    project_path: Joi.string().required(),
    package_manager: Joi.string().valid('npm', 'yarn', 'maven', 'gradle', 'pip', 'composer', 'auto').optional(),
    fix_vulnerabilities: Joi.boolean().optional(),
    severity_threshold: Joi.string().valid('low', 'medium', 'high', 'critical').optional(),
    include_dev_dependencies: Joi.boolean().optional(),
    tool: Joi.string().valid('osv-scanner', 'trivy', 'npm-audit', 'auto').optional(),
    license_check: Joi.boolean().optional(),
    generate_sbom: Joi.boolean().optional()
  });

  constructor() {
    this.osvScannerConnector = new OSVScannerConnector();
    this.trivyConnector = new TrivyConnector();
  }

  async executeScan(params: SCAParams): Promise<any> {
    const startTime = Date.now();
    
    try {
      const { error, value } = this.validationSchema.validate(params);
      if (error) {
        throw new Error(`Invalid parameters: ${error.details[0]?.message}`);
      }

      const validatedParams = value as SCAParams;
      logger.info('Starting SCA scan', { 
        project_path: validatedParams.project_path,
        package_manager: validatedParams.package_manager || 'auto'
      });

      await this.validateProjectPath(validatedParams.project_path);

      const packageManager = validatedParams.package_manager || 
                           await this.detectPackageManager(validatedParams.project_path);
      
      const tool = validatedParams.tool || await this.selectBestTool(packageManager);
      let result: SCAScanResult;

      switch (tool) {
        case 'osv-scanner':
          result = await this.runOSVScannerScan(validatedParams, packageManager);
          break;
        case 'trivy':
          result = await this.runTrivyScan(validatedParams, packageManager);
          break;
        case 'npm-audit':
          result = await this.runNpmAuditScan(validatedParams, packageManager);
          break;
        default:
          result = await this.runAutoScan(validatedParams, packageManager);
      }

      result.metadata.scan_duration = Date.now() - startTime;
      
      if (validatedParams.fix_vulnerabilities) {
        await this.applyAutomaticFixes(result, validatedParams.project_path);
      }

      const filteredResult = this.filterBySeverity(result, validatedParams.severity_threshold);
      
      logger.info('SCA scan completed', {
        scan_id: result.scan_id,
        total_vulnerabilities: filteredResult.summary.total_vulnerabilities,
        fixable: filteredResult.summary.fixable,
        duration: result.metadata.scan_duration
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(filteredResult, null, 2)
        }]
      };

    } catch (error) {
      logger.error('SCA scan failed', { 
        error: error instanceof Error ? error.message : 'Unknown error',
        project_path: params.project_path 
      });
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: 'SCA scan failed',
            message: error instanceof Error ? error.message : 'Unknown error',
            code: 'SCA_SCAN_ERROR'
          }, null, 2)
        }]
      };
    }
  }

  private async validateProjectPath(projectPath: string): Promise<void> {
    try {
      const resolvedPath = path.resolve(projectPath);
      const stats = await fs.stat(resolvedPath);
      
      if (!stats.isDirectory()) {
        throw new Error('Project path must be a directory');
      }
    } catch (error) {
      throw new Error(`Invalid project path: ${projectPath}`);
    }
  }

  private async detectPackageManager(projectPath: string): Promise<string> {
    try {
      const files = await fs.readdir(projectPath);
      
      if (files.includes('package.json')) {
        if (files.includes('yarn.lock')) return 'yarn';
        if (files.includes('package-lock.json')) return 'npm';
        return 'npm';
      }
      
      if (files.includes('pom.xml')) return 'maven';
      if (files.includes('build.gradle') || files.includes('build.gradle.kts')) return 'gradle';
      if (files.includes('requirements.txt') || files.includes('setup.py')) return 'pip';
      if (files.includes('composer.json')) return 'composer';
      
      throw new Error('Unable to detect package manager');
    } catch (error) {
      throw new Error(`Failed to detect package manager: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async selectBestTool(packageManager: string): Promise<string> {
    // Check if OSV Scanner is available
    const osvAvailable = await this.osvScannerConnector.checkInstallation();
    if (osvAvailable) {
      return 'osv-scanner';
    }

    // Check if Trivy is available
    const trivyAvailable = await this.trivyConnector.checkInstallation();
    if (trivyAvailable) {
      return 'trivy';
    }

    // Fall back to npm audit for Node.js projects
    if (packageManager === 'npm' || packageManager === 'yarn') {
      return 'npm-audit';
    }

    // Default to OSV Scanner
    return 'osv-scanner';
  }

  private async runOSVScannerScan(params: SCAParams, packageManager: string): Promise<SCAScanResult> {
    const scanId = `sca-osv-${Date.now()}`;
    
    try {
      const osvParams = {
        projectPath: params.project_path,
        packageManager: packageManager,
        severity: params.severity_threshold || 'low',
        includeDev: params.include_dev_dependencies || false,
        format: 'json' as const,
        recursive: true
      };

      const osvResult = await this.osvScannerConnector.executeScan(osvParams);
      
      return this.mapOSVResultToSCAResult(osvResult, scanId, params, packageManager);
    } catch (error) {
      logger.error('OSV Scanner scan failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      throw error;
    }
  }

  private async runTrivyScan(params: SCAParams, packageManager: string): Promise<SCAScanResult> {
    const scanId = `sca-trivy-${Date.now()}`;
    
    try {
      const trivyResult = await this.trivyConnector.scanFilesystem(params.project_path);
      
      return this.mapTrivyResultToSCAResult(trivyResult, scanId, params, packageManager);
    } catch (error) {
      logger.error('Trivy scan failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      throw error;
    }
  }

  private async runNpmAuditScan(params: SCAParams, packageManager: string): Promise<SCAScanResult> {
    const scanId = `sca-npm-audit-${Date.now()}`;
    
    if (packageManager !== 'npm' && packageManager !== 'yarn') {
      throw new Error('npm audit only supports npm/yarn projects');
    }

    return new Promise((resolve, reject) => {
      const auditArgs = ['audit', '--json'];
      
      if (params.severity_threshold) {
        auditArgs.push('--audit-level', params.severity_threshold);
      }

      const audit = spawn('npm', auditArgs, {
        cwd: params.project_path
      });

      let output = '';
      let errorOutput = '';

      audit.stdout.on('data', (data) => {
        output += data.toString();
      });

      audit.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      audit.on('close', async (code) => {
        try {
          const auditResult = JSON.parse(output);
          const result = await this.mapNpmAuditResultToSCAResult(auditResult, scanId, params, packageManager);
          resolve(result);
        } catch (parseError) {
          reject(new Error(`Failed to parse npm audit output: ${parseError instanceof Error ? parseError.message : 'Unknown error'}`));
        }
      });
    });
  }

  private async runAutoScan(params: SCAParams, packageManager: string): Promise<SCAScanResult> {
    try {
      return await this.runOSVScannerScan(params, packageManager);
    } catch (osvError) {
      logger.warn('OSV Scanner failed, falling back to Trivy', { error: osvError });
      
      try {
        return await this.runTrivyScan(params, packageManager);
      } catch (trivyError) {
        logger.warn('Trivy scan failed, falling back to npm audit', { error: trivyError });
        
        if (packageManager === 'npm' || packageManager === 'yarn') {
          return await this.runNpmAuditScan(params, packageManager);
        }
        
        throw osvError;
      }
    }
  }

  private mapOSVResultToSCAResult(osvResult: any, scanId: string, params: SCAParams, packageManager: string): SCAScanResult {
    const vulnerabilities = osvResult.vulnerabilities?.map(this.mapOSVVulnerabilityToSCAVulnerability) || [];
    
    return {
      tool: 'OSV Scanner',
      scan_id: scanId,
      status: 'completed',
      project_path: params.project_path,
      package_manager: packageManager,
      vulnerabilities,
      license_issues: [], // OSV Scanner doesn't provide license information
      summary: {
        total_vulnerabilities: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length,
        fixable: vulnerabilities.filter(v => v.fix_available).length,
        license_violations: 0
      },
      remediation: osvResult.remediation || { upgrades: [], patches: [] },
      metadata: {
        scan_duration: 0,
        total_dependencies: osvResult.dependencyCount || 0,
        direct_dependencies: 0,
        timestamp: new Date().toISOString()
      }
    };
  }

  private mapTrivyResultToSCAResult(trivyResult: any, scanId: string, params: SCAParams, packageManager: string): SCAScanResult {
    const vulnerabilities = trivyResult.vulnerabilities?.map(this.mapTrivyVulnerabilityToSCAVulnerability) || [];
    
    return {
      tool: 'Trivy',
      scan_id: scanId,
      status: 'completed',
      project_path: params.project_path,
      package_manager: packageManager,
      vulnerabilities,
      license_issues: [], // Trivy doesn't provide license information in this context
      summary: {
        total_vulnerabilities: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length,
        fixable: vulnerabilities.filter(v => v.fix_available).length,
        license_violations: 0
      },
      remediation: { upgrades: [], patches: [] },
      metadata: {
        scan_duration: 0,
        total_dependencies: 0,
        direct_dependencies: 0,
        timestamp: new Date().toISOString()
      }
    };
  }

  private mapSnykResultToSCAResult(snykResult: any, scanId: string, params: SCAParams, packageManager: string): SCAScanResult {
    const vulnerabilities = snykResult.vulnerabilities?.map(this.mapSnykVulnerabilityToSCAVulnerability) || [];
    const licenseIssues = snykResult.licenseIssues?.map(this.mapSnykLicenseIssue) || [];
    
    return {
      tool: 'Snyk',
      scan_id: scanId,
      status: 'completed',
      project_path: params.project_path,
      package_manager: packageManager,
      vulnerabilities,
      license_issues: licenseIssues,
      sbom: snykResult.sbom ? {
        components: snykResult.sbom.components || [],
        dependencies_count: snykResult.dependenciesCount || 0,
        direct_dependencies: snykResult.directDependencies || 0,
        transitive_dependencies: snykResult.transitiveDependencies || 0
      } : undefined,
      summary: {
        total_vulnerabilities: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length,
        fixable: vulnerabilities.filter(v => v.fix_available).length,
        license_violations: licenseIssues.length
      },
      remediation: {
        upgrades: snykResult.remediation?.upgrades || [],
        patches: snykResult.remediation?.patches || []
      },
      metadata: {
        scan_duration: 0,
        total_dependencies: snykResult.dependenciesCount || 0,
        direct_dependencies: snykResult.directDependencies || 0,
        timestamp: new Date().toISOString()
      }
    };
  }

  private async mapNpmAuditResultToSCAResult(auditResult: any, scanId: string, params: SCAParams, packageManager: string): Promise<SCAScanResult> {
    const vulnerabilities = Object.values(auditResult.vulnerabilities || {}).map(this.mapNpmVulnerabilityToSCAVulnerability);
    
    return {
      tool: 'npm audit',
      scan_id: scanId,
      status: 'completed',
      project_path: params.project_path,
      package_manager: packageManager,
      vulnerabilities,
      license_issues: [],
      summary: {
        total_vulnerabilities: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length,
        fixable: vulnerabilities.filter(v => v.fix_available).length,
        license_violations: 0
      },
      remediation: {
        upgrades: [],
        patches: []
      },
      metadata: {
        scan_duration: 0,
        total_dependencies: auditResult.metadata?.dependencies || 0,
        direct_dependencies: auditResult.metadata?.devDependencies || 0,
        timestamp: new Date().toISOString()
      }
    };
  }

  private mapOSVVulnerabilityToSCAVulnerability(vuln: any): SCAVulnerability {
    return {
      id: vuln.id,
      title: vuln.title || vuln.summary,
      severity: vuln.severity,
      package_name: vuln.packageName,
      package_version: vuln.version,
      vulnerable_versions: vuln.affected_ranges?.map((r: any) => r.ranges).join(', ') || '',
      description: vuln.description || vuln.details,
      references: vuln.references?.map((ref: any) => ref.url) || [],
      cve_ids: vuln.aliases?.filter((alias: string) => alias.startsWith('CVE-')) || [],
      published: vuln.published,
      fix_available: false, // OSV Scanner doesn't provide direct fix information
      ecosystem: vuln.ecosystem
    };
  }

  private mapTrivyVulnerabilityToSCAVulnerability(vuln: any): SCAVulnerability {
    return {
      id: vuln.id,
      title: vuln.title,
      severity: vuln.severity,
      package_name: vuln.packageName,
      package_version: vuln.installedVersion,
      vulnerable_versions: vuln.installedVersion,
      patched_versions: vuln.fixedVersion,
      description: vuln.description,
      references: vuln.references || [],
      cve_ids: [vuln.id].filter(id => id.startsWith('CVE-')),
      cwe_ids: vuln.cwe_ids || [],
      cvss_score: vuln.cvss_scores?.[0]?.v3Score || vuln.cvss_scores?.[0]?.v2Score,
      published: vuln.published,
      fix_available: !!vuln.fixedVersion,
      fix_version: vuln.fixedVersion
    };
  }

  private mapSnykVulnerabilityToSCAVulnerability(vuln: any): SCAVulnerability {
    return {
      id: vuln.id,
      title: vuln.title,
      severity: vuln.severity,
      package_name: vuln.packageName,
      package_version: vuln.version,
      vulnerable_versions: vuln.semver?.vulnerable || '',
      patched_versions: vuln.semver?.patched,
      description: vuln.description,
      references: vuln.references || [],
      cve_ids: vuln.identifiers?.CVE || [],
      cwe_ids: vuln.identifiers?.CWE || [],
      cvss_score: vuln.cvssScore,
      exploitability: vuln.exploitMaturity,
      fix_available: vuln.isUpgradable || vuln.isPatchable,
      fix_version: vuln.fixedIn?.[0],
      upgrade_path: vuln.upgradePath || []
    };
  }

  private mapNpmVulnerabilityToSCAVulnerability(vuln: any): SCAVulnerability {
    return {
      id: vuln.via?.[0]?.url || vuln.name,
      title: vuln.name,
      severity: vuln.severity,
      package_name: vuln.name,
      package_version: vuln.via?.[0]?.range || '',
      vulnerable_versions: vuln.via?.[0]?.range || '',
      description: vuln.via?.[0]?.title || '',
      references: vuln.via?.[0]?.url ? [vuln.via[0].url] : [],
      fix_available: vuln.fixAvailable !== false,
      fix_version: vuln.fixAvailable?.version
    };
  }

  private mapSnykLicenseIssue(issue: any): LicenseIssue {
    return {
      package_name: issue.packageName,
      package_version: issue.version,
      license: issue.license,
      severity: issue.severity,
      policy_violation: issue.policyViolation
    };
  }

  private async applyAutomaticFixes(result: SCAScanResult, projectPath: string): Promise<void> {
    logger.info('Applying automatic fixes', { fixable: result.summary.fixable });
    
    if (result.package_manager === 'npm' || result.package_manager === 'yarn') {
      await this.applyNpmFixes(result, projectPath);
    }
  }

  private async applyNpmFixes(result: SCAScanResult, projectPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const fixArgs = ['audit', 'fix', '--force'];
      
      const fix = spawn('npm', fixArgs, {
        cwd: projectPath
      });

      fix.on('close', (code) => {
        if (code === 0) {
          logger.info('Automatic fixes applied successfully');
          resolve();
        } else {
          logger.warn('Some fixes could not be applied automatically');
          resolve();
        }
      });

      fix.on('error', (error) => {
        logger.error('Failed to apply automatic fixes', { error: error.message });
        reject(error);
      });
    });
  }

  private filterBySeverity(result: SCAScanResult, threshold?: string): SCAScanResult {
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
      summary: {
        ...result.summary,
        total_vulnerabilities: filteredVulnerabilities.length,
        critical: filteredVulnerabilities.filter(v => v.severity === 'critical').length,
        high: filteredVulnerabilities.filter(v => v.severity === 'high').length,
        medium: filteredVulnerabilities.filter(v => v.severity === 'medium').length,
        low: filteredVulnerabilities.filter(v => v.severity === 'low').length,
        fixable: filteredVulnerabilities.filter(v => v.fix_available).length
      }
    };
  }
}