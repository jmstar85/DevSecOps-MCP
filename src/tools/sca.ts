import * as fs from 'fs-extra';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as semver from 'semver';
import axios from 'axios';
import * as tar from 'tar';
import * as crypto from 'crypto-js';

const execAsync = promisify(exec);

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss_score: number;
  cve?: string;
  cwe?: string;
  references: string[];
  affected_versions: string;
  patched_versions?: string;
  vulnerable_functions?: string[];
  exploit_maturity?: 'unproven' | 'proof-of-concept' | 'functional' | 'high';
  first_patched?: string;
  disclosed_date?: string;
  publication_date?: string;
}

export interface License {
  name: string;
  spdx_id?: string;
  url?: string;
  type: 'permissive' | 'copyleft' | 'proprietary' | 'unknown';
  commercial_use: boolean;
  distribution: boolean;
  modification: boolean;
  private_use: boolean;
  patent_use?: boolean;
  disclose_source?: boolean;
  include_copyright?: boolean;
  include_license?: boolean;
  same_license?: boolean;
  state_changes?: boolean;
  risk_level: 'low' | 'medium' | 'high';
}

export interface Dependency {
  name: string;
  version: string;
  latest_version?: string;
  type: 'direct' | 'transitive';
  ecosystem: 'npm' | 'pypi' | 'maven' | 'nuget' | 'rubygems' | 'other';
  file_path: string;
  licenses: License[];
  vulnerabilities: Vulnerability[];
  outdated: boolean;
  deprecated: boolean;
  health_score?: number;
  popularity_score?: number;
  maintenance_score?: number;
  dependencies?: Dependency[];
  size?: number;
  last_updated?: string;
}

export interface PolicyViolation {
  type: 'license' | 'vulnerability' | 'policy';
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  dependency: string;
  rule: string;
  action: 'block' | 'warn' | 'approve';
}

export interface SCAReport {
  scan_timestamp: string;
  project_name: string;
  total_dependencies: number;
  direct_dependencies: number;
  transitive_dependencies: number;
  dependencies: Dependency[];
  vulnerabilities_summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  license_summary: {
    total_licenses: number;
    risky_licenses: number;
    unknown_licenses: number;
    license_breakdown: { [key: string]: number };
  };
  policy_violations: PolicyViolation[];
  recommendations: string[];
  risk_score: number;
}

export class SCAAnalyzer {
  private readonly vulnerabilityDatabases = {
    npm: 'https://registry.npmjs.org/-/npm/v1/security/audits',
    osv: 'https://osv.dev/v1/query',
    nvd: 'https://services.nvd.nist.gov/rest/json/cves/2.0'
  };

  private readonly licenseDatabase: { [key: string]: License } = {
    'MIT': {
      name: 'MIT License',
      spdx_id: 'MIT',
      type: 'permissive',
      commercial_use: true,
      distribution: true,
      modification: true,
      private_use: true,
      patent_use: false,
      include_copyright: true,
      include_license: true,
      risk_level: 'low'
    },
    'Apache-2.0': {
      name: 'Apache License 2.0',
      spdx_id: 'Apache-2.0',
      type: 'permissive',
      commercial_use: true,
      distribution: true,
      modification: true,
      private_use: true,
      patent_use: true,
      include_copyright: true,
      include_license: true,
      state_changes: true,
      risk_level: 'low'
    },
    'GPL-3.0': {
      name: 'GNU General Public License v3.0',
      spdx_id: 'GPL-3.0',
      type: 'copyleft',
      commercial_use: true,
      distribution: true,
      modification: true,
      private_use: true,
      disclose_source: true,
      include_copyright: true,
      include_license: true,
      same_license: true,
      state_changes: true,
      risk_level: 'high'
    },
    'BSD-3-Clause': {
      name: 'BSD 3-Clause License',
      spdx_id: 'BSD-3-Clause',
      type: 'permissive',
      commercial_use: true,
      distribution: true,
      modification: true,
      private_use: true,
      include_copyright: true,
      include_license: true,
      risk_level: 'low'
    },
    'ISC': {
      name: 'ISC License',
      spdx_id: 'ISC',
      type: 'permissive',
      commercial_use: true,
      distribution: true,
      modification: true,
      private_use: true,
      include_copyright: true,
      include_license: true,
      risk_level: 'low'
    }
  };

  private readonly defaultPolicies = {
    blocked_licenses: ['GPL-3.0', 'AGPL-3.0', 'LGPL-3.0'],
    warning_licenses: ['GPL-2.0', 'LGPL-2.1'],
    max_vulnerability_score: 7.0,
    max_age_days: 730,
    require_license: true
  };

  async performSCAAnalysis(args: {
    path: string;
    ecosystem?: string;
    include_transitive?: boolean;
    policy_file?: string;
    check_licenses?: boolean;
    check_vulnerabilities?: boolean;
  }): Promise<SCAReport> {
    const {
      path: projectPath,
      ecosystem,
      include_transitive = true,
      policy_file,
      check_licenses = true,
      check_vulnerabilities = true
    } = args;

    if (!await fs.pathExists(projectPath)) {
      throw new Error(`Project path does not exist: ${projectPath}`);
    }

    console.log('Starting Software Composition Analysis...');

    const detectedEcosystem = ecosystem || await this.detectEcosystem(projectPath);
    console.log(`Detected ecosystem: ${detectedEcosystem}`);

    const dependencies = await this.analyzeDependencies(projectPath, detectedEcosystem, include_transitive);
    console.log(`Found ${dependencies.length} dependencies`);

    if (check_vulnerabilities) {
      console.log('Checking for vulnerabilities...');
      await this.enrichWithVulnerabilities(dependencies, detectedEcosystem);
    }

    if (check_licenses) {
      console.log('Analyzing licenses...');
      await this.enrichWithLicenses(dependencies, detectedEcosystem);
    }

    const policy = policy_file ? await this.loadPolicy(policy_file) : this.defaultPolicies;
    const policyViolations = this.checkPolicyViolations(dependencies, policy);

    const report = this.generateReport(projectPath, dependencies, policyViolations);
    
    console.log('SCA analysis completed');
    return report;
  }

  private async detectEcosystem(projectPath: string): Promise<string> {
    const files = await fs.readdir(projectPath);
    
    if (files.includes('package.json')) return 'npm';
    if (files.includes('requirements.txt') || files.includes('setup.py') || files.includes('pyproject.toml')) return 'pypi';
    if (files.includes('pom.xml') || files.includes('build.gradle')) return 'maven';
    if (files.includes('Gemfile')) return 'rubygems';
    if (files.some(f => f.endsWith('.csproj') || f.endsWith('.sln'))) return 'nuget';
    if (files.includes('go.mod')) return 'go';
    if (files.includes('Cargo.toml')) return 'cargo';
    
    return 'unknown';
  }

  private async analyzeDependencies(
    projectPath: string,
    ecosystem: string,
    includeTransitive: boolean
  ): Promise<Dependency[]> {
    switch (ecosystem) {
      case 'npm':
        return await this.analyzeNpmDependencies(projectPath, includeTransitive);
      case 'pypi':
        return await this.analyzePythonDependencies(projectPath, includeTransitive);
      case 'maven':
        return await this.analyzeMavenDependencies(projectPath, includeTransitive);
      default:
        throw new Error(`Unsupported ecosystem: ${ecosystem}`);
    }
  }

  private async analyzeNpmDependencies(projectPath: string, includeTransitive: boolean): Promise<Dependency[]> {
    const dependencies: Dependency[] = [];
    const packageJsonPath = path.join(projectPath, 'package.json');
    
    if (!await fs.pathExists(packageJsonPath)) {
      throw new Error('package.json not found');
    }

    const packageJson = await fs.readJson(packageJsonPath);
    const allDeps = {
      ...packageJson.dependencies || {},
      ...packageJson.devDependencies || {},
      ...packageJson.peerDependencies || {}
    };

    for (const [name, version] of Object.entries(allDeps)) {
      const dependency = await this.createNpmDependency(name, version as string, 'direct', packageJsonPath);
      dependencies.push(dependency);

      if (includeTransitive) {
        const transitiveDeps = await this.getNpmTransitiveDependencies(name, version as string);
        dependencies.push(...transitiveDeps);
      }
    }

    return dependencies;
  }

  private async createNpmDependency(name: string, version: string, type: 'direct' | 'transitive', filePath: string): Promise<Dependency> {
    try {
      const registryUrl = `https://registry.npmjs.org/${name}`;
      const response = await axios.get(registryUrl, { timeout: 10000 });
      const packageInfo = response.data;

      const latestVersion = packageInfo['dist-tags']?.latest;
      const currentVersion = this.resolveVersion(version, Object.keys(packageInfo.versions || {}));
      
      const versionInfo = packageInfo.versions?.[currentVersion];
      const license = this.parseLicense(versionInfo?.license);

      return {
        name,
        version: currentVersion,
        latest_version: latestVersion,
        type,
        ecosystem: 'npm',
        file_path: filePath,
        licenses: license ? [license] : [],
        vulnerabilities: [],
        outdated: currentVersion !== latestVersion,
        deprecated: packageInfo.deprecated || false,
        health_score: await this.calculateHealthScore(name, 'npm'),
        popularity_score: await this.calculatePopularityScore(name, 'npm'),
        maintenance_score: await this.calculateMaintenanceScore(name, 'npm'),
        size: versionInfo?.dist?.unpackedSize,
        last_updated: packageInfo.time?.[currentVersion]
      };
    } catch (error) {
      console.error(`Error fetching npm package ${name}:`, error.message);
      return {
        name,
        version: this.resolveVersion(version, []),
        type,
        ecosystem: 'npm',
        file_path: filePath,
        licenses: [],
        vulnerabilities: [],
        outdated: false,
        deprecated: false
      };
    }
  }

  private async getNpmTransitiveDependencies(packageName: string, version: string): Promise<Dependency[]> {
    const transitiveDeps: Dependency[] = [];
    
    try {
      const { stdout } = await execAsync(`npm list ${packageName} --depth=1 --json`, { 
        cwd: process.cwd(),
        timeout: 30000 
      });
      
      const result = JSON.parse(stdout);
      const dependencies = result.dependencies?.[packageName]?.dependencies || {};

      for (const [name, info] of Object.entries(dependencies)) {
        const depInfo = info as any;
        const dependency = await this.createNpmDependency(name, depInfo.version, 'transitive', '');
        transitiveDeps.push(dependency);
      }
    } catch (error) {
      console.error(`Error getting transitive dependencies for ${packageName}:`, error.message);
    }

    return transitiveDeps;
  }

  private async analyzePythonDependencies(projectPath: string, includeTransitive: boolean): Promise<Dependency[]> {
    const dependencies: Dependency[] = [];
    const requirementsPath = path.join(projectPath, 'requirements.txt');
    
    if (await fs.pathExists(requirementsPath)) {
      const content = await fs.readFile(requirementsPath, 'utf-8');
      const lines = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));

      for (const line of lines) {
        const match = line.match(/^([a-zA-Z0-9\-_.]+)\s*([>=<~!]+)\s*([0-9.]+.*)?/);
        if (match) {
          const [, name, operator, version] = match;
          const dependency = await this.createPythonDependency(name, version || 'latest', 'direct', requirementsPath);
          dependencies.push(dependency);
        }
      }
    }

    return dependencies;
  }

  private async createPythonDependency(name: string, version: string, type: 'direct' | 'transitive', filePath: string): Promise<Dependency> {
    try {
      const pypiUrl = `https://pypi.org/pypi/${name}/json`;
      const response = await axios.get(pypiUrl, { timeout: 10000 });
      const packageInfo = response.data;

      const latestVersion = packageInfo.info.version;
      const currentVersion = this.resolveVersion(version, Object.keys(packageInfo.releases || {}));
      
      const license = this.parseLicense(packageInfo.info.license);

      return {
        name,
        version: currentVersion,
        latest_version: latestVersion,
        type,
        ecosystem: 'pypi',
        file_path: filePath,
        licenses: license ? [license] : [],
        vulnerabilities: [],
        outdated: currentVersion !== latestVersion,
        deprecated: false,
        health_score: await this.calculateHealthScore(name, 'pypi'),
        popularity_score: await this.calculatePopularityScore(name, 'pypi'),
        maintenance_score: await this.calculateMaintenanceScore(name, 'pypi')
      };
    } catch (error) {
      console.error(`Error fetching Python package ${name}:`, error.message);
      return {
        name,
        version: this.resolveVersion(version, []),
        type,
        ecosystem: 'pypi',
        file_path: filePath,
        licenses: [],
        vulnerabilities: [],
        outdated: false,
        deprecated: false
      };
    }
  }

  private async analyzeMavenDependencies(projectPath: string, includeTransitive: boolean): Promise<Dependency[]> {
    const dependencies: Dependency[] = [];
    
    return dependencies;
  }

  private async enrichWithVulnerabilities(dependencies: Dependency[], ecosystem: string): Promise<void> {
    for (const dependency of dependencies) {
      try {
        const vulnerabilities = await this.getVulnerabilities(dependency.name, dependency.version, ecosystem);
        dependency.vulnerabilities = vulnerabilities;
      } catch (error) {
        console.error(`Error fetching vulnerabilities for ${dependency.name}:`, error.message);
      }
    }
  }

  private async getVulnerabilities(packageName: string, version: string, ecosystem: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    try {
      if (ecosystem === 'npm') {
        const osvVulns = await this.queryOSVDatabase(packageName, version, 'npm');
        vulnerabilities.push(...osvVulns);
      }

      const nvdVulns = await this.queryNVDDatabase(packageName);
      vulnerabilities.push(...nvdVulns);
    } catch (error) {
      console.error(`Error querying vulnerability databases:`, error.message);
    }

    return vulnerabilities;
  }

  private async queryOSVDatabase(packageName: string, version: string, ecosystem: string): Promise<Vulnerability[]> {
    try {
      const response = await axios.post(this.vulnerabilityDatabases.osv, {
        package: {
          name: packageName,
          ecosystem: ecosystem.toUpperCase()
        },
        version
      }, { timeout: 10000 });

      return response.data.vulns?.map((vuln: any) => ({
        id: vuln.id,
        title: vuln.summary || 'No title available',
        description: vuln.details || 'No description available',
        severity: this.mapSeverity(vuln.database_specific?.severity),
        cvss_score: this.extractCVSSScore(vuln),
        cve: vuln.aliases?.find((alias: string) => alias.startsWith('CVE-')),
        references: vuln.references?.map((ref: any) => ref.url) || [],
        affected_versions: vuln.affected?.map((a: any) => a.package?.name).join(', ') || version,
        disclosed_date: vuln.published,
        publication_date: vuln.modified
      })) || [];
    } catch (error) {
      console.error(`OSV query failed for ${packageName}:`, error.message);
      return [];
    }
  }

  private async queryNVDDatabase(packageName: string): Promise<Vulnerability[]> {
    try {
      const response = await axios.get(`${this.vulnerabilityDatabases.nvd}?keywordSearch=${packageName}`, {
        timeout: 10000
      });

      return response.data.vulnerabilities?.slice(0, 10).map((item: any) => {
        const vuln = item.cve;
        return {
          id: vuln.id,
          title: vuln.descriptions?.[0]?.value || 'No title available',
          description: vuln.descriptions?.[0]?.value || 'No description available',
          severity: this.mapCVSSSeverity(vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore),
          cvss_score: vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 0,
          cve: vuln.id,
          references: vuln.references?.map((ref: any) => ref.url) || [],
          affected_versions: 'Unknown',
          disclosed_date: vuln.published,
          publication_date: vuln.lastModified
        };
      }) || [];
    } catch (error) {
      console.error(`NVD query failed for ${packageName}:`, error.message);
      return [];
    }
  }

  private async enrichWithLicenses(dependencies: Dependency[], ecosystem: string): Promise<void> {
    for (const dependency of dependencies) {
      if (dependency.licenses.length === 0) {
        try {
          const licenses = await this.getLicenses(dependency.name, dependency.version, ecosystem);
          dependency.licenses = licenses;
        } catch (error) {
          console.error(`Error fetching licenses for ${dependency.name}:`, error.message);
        }
      }
    }
  }

  private async getLicenses(packageName: string, version: string, ecosystem: string): Promise<License[]> {
    const licenses: License[] = [];

    try {
      if (ecosystem === 'npm') {
        const response = await axios.get(`https://registry.npmjs.org/${packageName}/${version}`);
        const licenseString = response.data.license;
        const license = this.parseLicense(licenseString);
        if (license) licenses.push(license);
      }
    } catch (error) {
      console.error(`Error fetching license for ${packageName}:`, error.message);
    }

    return licenses;
  }

  private parseLicense(licenseString: string | any): License | null {
    if (!licenseString) return null;

    if (typeof licenseString === 'object') {
      licenseString = licenseString.type || licenseString.name || 'Unknown';
    }

    const licenseId = String(licenseString).trim();
    
    if (this.licenseDatabase[licenseId]) {
      return this.licenseDatabase[licenseId];
    }

    return {
      name: licenseId,
      type: 'unknown',
      commercial_use: false,
      distribution: false,
      modification: false,
      private_use: false,
      risk_level: 'medium'
    };
  }

  private checkPolicyViolations(dependencies: Dependency[], policy: any): PolicyViolation[] {
    const violations: PolicyViolation[] = [];

    for (const dependency of dependencies) {
      for (const license of dependency.licenses) {
        if (policy.blocked_licenses?.includes(license.spdx_id)) {
          violations.push({
            type: 'license',
            severity: 'critical',
            message: `Blocked license detected: ${license.name}`,
            dependency: dependency.name,
            rule: 'blocked-license',
            action: 'block'
          });
        } else if (policy.warning_licenses?.includes(license.spdx_id)) {
          violations.push({
            type: 'license',
            severity: 'medium',
            message: `Warning license detected: ${license.name}`,
            dependency: dependency.name,
            rule: 'warning-license',
            action: 'warn'
          });
        }
      }

      for (const vulnerability of dependency.vulnerabilities) {
        if (vulnerability.cvss_score >= policy.max_vulnerability_score) {
          violations.push({
            type: 'vulnerability',
            severity: vulnerability.severity as any,
            message: `High severity vulnerability: ${vulnerability.title}`,
            dependency: dependency.name,
            rule: 'high-severity-vulnerability',
            action: 'block'
          });
        }
      }

      if (dependency.outdated && dependency.last_updated) {
        const daysSinceUpdate = (Date.now() - new Date(dependency.last_updated).getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceUpdate > policy.max_age_days) {
          violations.push({
            type: 'policy',
            severity: 'medium',
            message: `Package is outdated (${Math.round(daysSinceUpdate)} days old)`,
            dependency: dependency.name,
            rule: 'outdated-package',
            action: 'warn'
          });
        }
      }
    }

    return violations;
  }

  private generateReport(projectPath: string, dependencies: Dependency[], violations: PolicyViolation[]): SCAReport {
    const totalVulns = dependencies.reduce((sum, dep) => sum + dep.vulnerabilities.length, 0);
    const vulnSummary = {
      total: totalVulns,
      critical: dependencies.reduce((sum, dep) => sum + dep.vulnerabilities.filter(v => v.severity === 'critical').length, 0),
      high: dependencies.reduce((sum, dep) => sum + dep.vulnerabilities.filter(v => v.severity === 'high').length, 0),
      medium: dependencies.reduce((sum, dep) => sum + dep.vulnerabilities.filter(v => v.severity === 'medium').length, 0),
      low: dependencies.reduce((sum, dep) => sum + dep.vulnerabilities.filter(v => v.severity === 'low').length, 0)
    };

    const allLicenses = dependencies.flatMap(dep => dep.licenses);
    const licenseBreakdown: { [key: string]: number } = {};
    allLicenses.forEach(license => {
      licenseBreakdown[license.name] = (licenseBreakdown[license.name] || 0) + 1;
    });

    const riskScore = this.calculateRiskScore(dependencies, violations);

    return {
      scan_timestamp: new Date().toISOString(),
      project_name: path.basename(projectPath),
      total_dependencies: dependencies.length,
      direct_dependencies: dependencies.filter(d => d.type === 'direct').length,
      transitive_dependencies: dependencies.filter(d => d.type === 'transitive').length,
      dependencies,
      vulnerabilities_summary: vulnSummary,
      license_summary: {
        total_licenses: allLicenses.length,
        risky_licenses: allLicenses.filter(l => l.risk_level === 'high').length,
        unknown_licenses: allLicenses.filter(l => l.type === 'unknown').length,
        license_breakdown: licenseBreakdown
      },
      policy_violations: violations,
      recommendations: this.generateRecommendations(dependencies, violations),
      risk_score: riskScore
    };
  }

  private calculateRiskScore(dependencies: Dependency[], violations: PolicyViolation[]): number {
    let score = 0;
    
    violations.forEach(violation => {
      switch (violation.severity) {
        case 'critical': score += 10; break;
        case 'high': score += 7; break;
        case 'medium': score += 4; break;
        case 'low': score += 1; break;
      }
    });

    const totalVulns = dependencies.reduce((sum, dep) => sum + dep.vulnerabilities.length, 0);
    score += totalVulns * 2;

    const outdatedDeps = dependencies.filter(d => d.outdated).length;
    score += outdatedDeps * 0.5;

    return Math.min(100, Math.round(score));
  }

  private generateRecommendations(dependencies: Dependency[], violations: PolicyViolation[]): string[] {
    const recommendations: string[] = [];

    const criticalViolations = violations.filter(v => v.severity === 'critical');
    if (criticalViolations.length > 0) {
      recommendations.push(`Address ${criticalViolations.length} critical policy violations immediately`);
    }

    const outdatedDeps = dependencies.filter(d => d.outdated);
    if (outdatedDeps.length > 0) {
      recommendations.push(`Update ${outdatedDeps.length} outdated dependencies`);
    }

    const vulnDeps = dependencies.filter(d => d.vulnerabilities.length > 0);
    if (vulnDeps.length > 0) {
      recommendations.push(`Review and patch ${vulnDeps.length} dependencies with known vulnerabilities`);
    }

    const unknownLicenses = dependencies.filter(d => d.licenses.some(l => l.type === 'unknown'));
    if (unknownLicenses.length > 0) {
      recommendations.push(`Investigate ${unknownLicenses.length} dependencies with unknown licenses`);
    }

    return recommendations;
  }

  private resolveVersion(versionSpec: string, availableVersions: string[]): string {
    if (!versionSpec || versionSpec === 'latest') {
      return availableVersions[0] || '0.0.0';
    }

    const cleanSpec = versionSpec.replace(/[^0-9.]/g, '');
    if (availableVersions.includes(cleanSpec)) {
      return cleanSpec;
    }

    try {
      const validVersions = availableVersions.filter(v => semver.valid(v));
      const maxSatisfying = semver.maxSatisfying(validVersions, versionSpec);
      return maxSatisfying || cleanSpec || '0.0.0';
    } catch {
      return cleanSpec || '0.0.0';
    }
  }

  private mapSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
    const severityMap: { [key: string]: 'critical' | 'high' | 'medium' | 'low' } = {
      'critical': 'critical',
      'high': 'high',
      'medium': 'medium',
      'low': 'low',
      'moderate': 'medium',
      'important': 'high'
    };
    
    return severityMap[severity?.toLowerCase()] || 'medium';
  }

  private mapCVSSSeverity(score: number): 'critical' | 'high' | 'medium' | 'low' {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
  }

  private extractCVSSScore(vulnerability: any): number {
    return vulnerability.database_specific?.cvss_score || 
           vulnerability.severity?.score || 
           0;
  }

  private async calculateHealthScore(packageName: string, ecosystem: string): Promise<number> {
    return 85;
  }

  private async calculatePopularityScore(packageName: string, ecosystem: string): Promise<number> {
    return 75;
  }

  private async calculateMaintenanceScore(packageName: string, ecosystem: string): Promise<number> {
    return 80;
  }

  private async loadPolicy(policyFile: string): Promise<any> {
    if (await fs.pathExists(policyFile)) {
      return await fs.readJson(policyFile);
    }
    return this.defaultPolicies;
  }
}