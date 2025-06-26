import * as fs from 'fs-extra';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface SASTResult {
  file: string;
  line: number;
  column?: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  rule: string;
  message: string;
  cwe?: string;
  owasp?: string;
}

export class SASTTool {
  private readonly supportedLanguages = {
    javascript: ['.js', '.jsx'],
    typescript: ['.ts', '.tsx'],
    python: ['.py'],
    java: ['.java'],
    csharp: ['.cs'],
    go: ['.go'],
    php: ['.php'],
    ruby: ['.rb'],
  };

  async scan(args: {
    path: string;
    language?: string;
    severity?: 'low' | 'medium' | 'high' | 'critical';
  }) {
    const { path: scanPath, language, severity = 'medium' } = args;

    if (!await fs.pathExists(scanPath)) {
      throw new Error(`Path does not exist: ${scanPath}`);
    }

    const detectedLanguage = language || await this.detectLanguage(scanPath);
    const results = await this.performScan(scanPath, detectedLanguage, severity);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            scan_type: 'SAST',
            target: scanPath,
            language: detectedLanguage,
            timestamp: new Date().toISOString(),
            results,
            summary: {
              total_issues: results.length,
              critical: results.filter(r => r.severity === 'critical').length,
              high: results.filter(r => r.severity === 'high').length,
              medium: results.filter(r => r.severity === 'medium').length,
              low: results.filter(r => r.severity === 'low').length,
            },
          }, null, 2),
        },
      ],
    };
  }

  private async detectLanguage(scanPath: string): Promise<string> {
    const stats = await fs.stat(scanPath);
    
    if (stats.isFile()) {
      const ext = path.extname(scanPath);
      for (const [lang, extensions] of Object.entries(this.supportedLanguages)) {
        if (extensions.includes(ext)) {
          return lang;
        }
      }
    } else {
      const files = await this.getAllFiles(scanPath);
      const extensionCounts: { [key: string]: number } = {};
      
      files.forEach(file => {
        const ext = path.extname(file);
        extensionCounts[ext] = (extensionCounts[ext] || 0) + 1;
      });

      const mostCommonExt = Object.keys(extensionCounts).reduce((a, b) =>
        extensionCounts[a] > extensionCounts[b] ? a : b
      );

      for (const [lang, extensions] of Object.entries(this.supportedLanguages)) {
        if (extensions.includes(mostCommonExt)) {
          return lang;
        }
      }
    }

    return 'javascript';
  }

  private async getAllFiles(dir: string): Promise<string[]> {
    const files: string[] = [];
    const items = await fs.readdir(dir);

    for (const item of items) {
      const itemPath = path.join(dir, item);
      const stats = await fs.stat(itemPath);
      
      if (stats.isDirectory()) {
        if (!item.startsWith('.') && item !== 'node_modules') {
          files.push(...await this.getAllFiles(itemPath));
        }
      } else {
        files.push(itemPath);
      }
    }

    return files;
  }

  private async performScan(
    scanPath: string,
    language: string,
    severity: string
  ): Promise<SASTResult[]> {
    const results: SASTResult[] = [];

    switch (language) {
      case 'javascript':
      case 'typescript':
        results.push(...await this.scanJavaScript(scanPath));
        break;
      case 'python':
        results.push(...await this.scanPython(scanPath));
        break;
      case 'java':
        results.push(...await this.scanJava(scanPath));
        break;
      default:
        results.push(...await this.scanGeneric(scanPath));
    }

    return results.filter(result => this.shouldIncludeBySeverity(result.severity, severity));
  }

  private async scanJavaScript(scanPath: string): Promise<SASTResult[]> {
    const results: SASTResult[] = [];
    
    try {
      const { stdout } = await execAsync(`npx eslint "${scanPath}" --format=json --no-eslintrc --config='{"extends":["eslint:recommended"],"parserOptions":{"ecmaVersion":2021},"rules":{"no-eval":2,"no-implied-eval":2,"no-new-func":2}}'`);
      const eslintResults = JSON.parse(stdout);
      
      for (const fileResult of eslintResults) {
        for (const message of fileResult.messages) {
          results.push({
            file: fileResult.filePath,
            line: message.line,
            column: message.column,
            severity: this.mapESLintSeverity(message.severity),
            rule: message.ruleId || 'unknown',
            message: message.message,
          });
        }
      }
    } catch (error) {
      console.error('ESLint scan failed:', error);
    }

    results.push(...await this.scanForCommonVulnerabilities(scanPath));
    return results;
  }

  private async scanPython(scanPath: string): Promise<SASTResult[]> {
    const results: SASTResult[] = [];
    
    try {
      const { stdout } = await execAsync(`bandit -r "${scanPath}" -f json`);
      const banditResults = JSON.parse(stdout);
      
      for (const result of banditResults.results) {
        results.push({
          file: result.filename,
          line: result.line_number,
          severity: this.mapBanditSeverity(result.issue_severity),
          rule: result.test_id,
          message: result.issue_text,
          cwe: result.issue_cwe?.id?.toString(),
        });
      }
    } catch (error) {
      console.error('Bandit scan failed, using fallback:', error);
    }

    results.push(...await this.scanForCommonVulnerabilities(scanPath));
    return results;
  }

  private async scanJava(scanPath: string): Promise<SASTResult[]> {
    return await this.scanForCommonVulnerabilities(scanPath);
  }

  private async scanGeneric(scanPath: string): Promise<SASTResult[]> {
    return await this.scanForCommonVulnerabilities(scanPath);
  }

  private async scanForCommonVulnerabilities(scanPath: string): Promise<SASTResult[]> {
    const results: SASTResult[] = [];
    const files = await this.getAllFiles(scanPath);

    const vulnerabilityPatterns = [
      {
        pattern: /password\s*=\s*['"]\w+['"]/gi,
        rule: 'hardcoded-password',
        message: 'Hardcoded password detected',
        severity: 'high' as const,
        cwe: 'CWE-798',
      },
      {
        pattern: /api_key\s*=\s*['"]\w+['"]/gi,
        rule: 'hardcoded-api-key',
        message: 'Hardcoded API key detected',
        severity: 'high' as const,
        cwe: 'CWE-798',
      },
      {
        pattern: /eval\s*\(/gi,
        rule: 'dangerous-eval',
        message: 'Use of eval() function detected',
        severity: 'high' as const,
        cwe: 'CWE-95',
      },
      {
        pattern: /innerHTML\s*=/gi,
        rule: 'xss-innerHTML',
        message: 'Potential XSS vulnerability via innerHTML',
        severity: 'medium' as const,
        cwe: 'CWE-79',
      },
      {
        pattern: /document\.write\s*\(/gi,
        rule: 'xss-document-write',
        message: 'Potential XSS vulnerability via document.write',
        severity: 'medium' as const,
        cwe: 'CWE-79',
      },
      {
        pattern: /(?:SELECT|INSERT|UPDATE|DELETE).*(?:WHERE|SET).*['"]?\s*\+\s*['"]?/gi,
        rule: 'sql-injection',
        message: 'Potential SQL injection vulnerability',
        severity: 'critical' as const,
        cwe: 'CWE-89',
      },
    ];

    for (const file of files) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');

        for (const { pattern, rule, message, severity, cwe } of vulnerabilityPatterns) {
          lines.forEach((line, index) => {
            const matches = line.matchAll(pattern);
            for (const match of matches) {
              results.push({
                file,
                line: index + 1,
                column: match.index || 0,
                severity,
                rule,
                message,
                cwe,
              });
            }
          });
        }
      } catch (error) {
        console.error(`Error reading file ${file}:`, error);
      }
    }

    return results;
  }

  private mapESLintSeverity(severity: number): 'low' | 'medium' | 'high' | 'critical' {
    switch (severity) {
      case 2: return 'high';
      case 1: return 'medium';
      default: return 'low';
    }
  }

  private mapBanditSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (severity.toLowerCase()) {
      case 'high': return 'critical';
      case 'medium': return 'high';
      case 'low': return 'medium';
      default: return 'low';
    }
  }

  private shouldIncludeBySeverity(
    resultSeverity: 'low' | 'medium' | 'high' | 'critical',
    minSeverity: string
  ): boolean {
    const severityLevels = { low: 1, medium: 2, high: 3, critical: 4 };
    return severityLevels[resultSeverity] >= severityLevels[minSeverity as keyof typeof severityLevels];
  }
}