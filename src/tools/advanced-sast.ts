import * as fs from 'fs-extra';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as glob from 'glob';
import * as crypto from 'crypto-js';
import { distance } from 'fastest-levenshtein';

const execAsync = promisify(exec);

export interface CodeQualityIssue {
  file: string;
  line: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  severity: 'blocker' | 'critical' | 'major' | 'minor' | 'info';
  type: 'bug' | 'vulnerability' | 'code_smell' | 'security_hotspot';
  rule: string;
  message: string;
  description: string;
  effort?: string;
  debt?: string;
  cwe?: string;
  owasp?: string;
  category: string;
  tags: string[];
  fixSuggestion?: string;
  codeContext?: string;
}

export interface QualityGate {
  passed: boolean;
  conditions: QualityCondition[];
}

export interface QualityCondition {
  metric: string;
  operator: string;
  threshold: string;
  actualValue: string;
  status: 'OK' | 'WARN' | 'ERROR';
}

export interface SonarQubeMetrics {
  lines: number;
  ncloc: number;
  complexity: number;
  cognitive_complexity: number;
  duplicated_lines_density: number;
  coverage: number;
  technical_debt: string;
  maintainability_rating: string;
  reliability_rating: string;
  security_rating: string;
  vulnerabilities: number;
  bugs: number;
  code_smells: number;
  security_hotspots: number;
}

export class AdvancedSASTTool {
  private readonly languagePatterns = {
    javascript: {
      extensions: ['.js', '.jsx', '.mjs', '.cjs'],
      complexityTokens: ['if', 'else', 'while', 'for', 'switch', 'case', 'catch', 'throw', '&&', '||', '?'],
      vulnerabilityPatterns: [
        {
          pattern: /eval\s*\(/gi,
          rule: 'javascript:S1523',
          message: 'Code should not be dynamically injected and executed',
          severity: 'critical' as const,
          type: 'vulnerability' as const,
          cwe: 'CWE-95',
          owasp: 'A03:2021'
        },
        {
          pattern: /document\.write\s*\(/gi,
          rule: 'javascript:S5247',
          message: 'Using document.write() can lead to XSS vulnerabilities',
          severity: 'major' as const,
          type: 'vulnerability' as const,
          cwe: 'CWE-79',
          owasp: 'A03:2021'
        },
        {
          pattern: /innerHTML\s*=(?!\s*['"][\w\s]*['"])/gi,
          rule: 'javascript:S5247',
          message: 'Dynamically setting innerHTML can lead to XSS',
          severity: 'major' as const,
          type: 'vulnerability' as const,
          cwe: 'CWE-79',
          owasp: 'A03:2021'
        },
        {
          pattern: /password\s*[=:]\s*['"][^'"]*['"]/gi,
          rule: 'javascript:S2068',
          message: 'Hard-coded credentials are security-sensitive',
          severity: 'blocker' as const,
          type: 'vulnerability' as const,
          cwe: 'CWE-798',
          owasp: 'A07:2021'
        }
      ]
    },
    typescript: {
      extensions: ['.ts', '.tsx'],
      complexityTokens: ['if', 'else', 'while', 'for', 'switch', 'case', 'catch', 'throw', '&&', '||', '?'],
      vulnerabilityPatterns: [
        {
          pattern: /any\s+\w+/gi,
          rule: 'typescript:S4322',
          message: 'TypeScript "any" defeats the purpose of static typing',
          severity: 'major' as const,
          type: 'code_smell' as const
        }
      ]
    },
    python: {
      extensions: ['.py', '.pyx', '.pyi'],
      complexityTokens: ['if', 'elif', 'else', 'while', 'for', 'try', 'except', 'and', 'or'],
      vulnerabilityPatterns: [
        {
          pattern: /exec\s*\(/gi,
          rule: 'python:S1523',
          message: 'Executing code dynamically is security-sensitive',
          severity: 'critical' as const,
          type: 'vulnerability' as const,
          cwe: 'CWE-95',
          owasp: 'A03:2021'
        },
        {
          pattern: /eval\s*\(/gi,
          rule: 'python:S1523',
          message: 'Executing code dynamically is security-sensitive',
          severity: 'critical' as const,
          type: 'vulnerability' as const,
          cwe: 'CWE-95',
          owasp: 'A03:2021'
        },
        {
          pattern: /subprocess\.(call|run|Popen).*shell\s*=\s*True/gi,
          rule: 'python:S4721',
          message: 'Using shell=True is security-sensitive',
          severity: 'critical' as const,
          type: 'security_hotspot' as const,
          cwe: 'CWE-78',
          owasp: 'A03:2021'
        }
      ]
    },
    java: {
      extensions: ['.java'],
      complexityTokens: ['if', 'else', 'while', 'for', 'switch', 'case', 'catch', 'throw', '&&', '||', '?'],
      vulnerabilityPatterns: [
        {
          pattern: /Runtime\.getRuntime\(\)\.exec/gi,
          rule: 'java:S4721',
          message: 'Using Runtime.exec() is security-sensitive',
          severity: 'critical' as const,
          type: 'security_hotspot' as const,
          cwe: 'CWE-78',
          owasp: 'A03:2021'
        },
        {
          pattern: /Class\.forName/gi,
          rule: 'java:S2658',
          message: 'Using reflection is security-sensitive',
          severity: 'major' as const,
          type: 'security_hotspot' as const,
          cwe: 'CWE-470',
          owasp: 'A08:2021'
        }
      ]
    }
  };

  private readonly qualityGateTemplate: QualityCondition[] = [
    { metric: 'new_coverage', operator: 'LT', threshold: '80', actualValue: '0', status: 'OK' },
    { metric: 'new_duplicated_lines_density', operator: 'GT', threshold: '3', actualValue: '0', status: 'OK' },
    { metric: 'new_maintainability_rating', operator: 'GT', threshold: '1', actualValue: '1', status: 'OK' },
    { metric: 'new_reliability_rating', operator: 'GT', threshold: '1', actualValue: '1', status: 'OK' },
    { metric: 'new_security_rating', operator: 'GT', threshold: '1', actualValue: '1', status: 'OK' },
    { metric: 'new_security_hotspots_reviewed', operator: 'LT', threshold: '100', actualValue: '100', status: 'OK' }
  ];

  async performAdvancedScan(args: {
    path: string;
    language?: string;
    includeMetrics?: boolean;
    qualityGate?: boolean;
    excludePatterns?: string[];
  }): Promise<{
    issues: CodeQualityIssue[];
    metrics: SonarQubeMetrics;
    qualityGate: QualityGate;
  }> {
    const { path: scanPath, language, includeMetrics = true, qualityGate = true, excludePatterns = [] } = args;

    if (!await fs.pathExists(scanPath)) {
      throw new Error(`Path does not exist: ${scanPath}`);
    }

    const detectedLanguage = language || await this.detectLanguage(scanPath);
    const files = await this.getAnalyzableFiles(scanPath, detectedLanguage, excludePatterns);
    
    console.log(`Starting advanced SAST scan for ${files.length} files in ${detectedLanguage}`);

    const issues: CodeQualityIssue[] = [];
    let metrics: SonarQubeMetrics = this.initializeMetrics();

    for (const file of files) {
      const fileIssues = await this.analyzeFile(file, detectedLanguage);
      issues.push(...fileIssues);

      if (includeMetrics) {
        const fileMetrics = await this.calculateFileMetrics(file, detectedLanguage);
        metrics = this.aggregateMetrics(metrics, fileMetrics);
      }
    }

    const duplicateIssues = await this.detectCodeDuplication(files);
    issues.push(...duplicateIssues);

    const complexityIssues = await this.analyzeComplexity(files, detectedLanguage);
    issues.push(...complexityIssues);

    const qualityGateResult = qualityGate ? this.evaluateQualityGate(issues, metrics) : { passed: true, conditions: [] };

    return {
      issues: this.sortAndPrioritizeIssues(issues),
      metrics,
      qualityGate: qualityGateResult
    };
  }

  private async detectLanguage(scanPath: string): Promise<string> {
    const stats = await fs.stat(scanPath);
    
    if (stats.isFile()) {
      const ext = path.extname(scanPath);
      for (const [lang, config] of Object.entries(this.languagePatterns)) {
        if (config.extensions.includes(ext)) {
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

      const mostCommonExt = Object.keys(extensionCounts)
        .reduce((a, b) => extensionCounts[a] > extensionCounts[b] ? a : b);

      for (const [lang, config] of Object.entries(this.languagePatterns)) {
        if (config.extensions.includes(mostCommonExt)) {
          return lang;
        }
      }
    }

    return 'javascript';
  }

  private async getAnalyzableFiles(scanPath: string, language: string, excludePatterns: string[]): Promise<string[]> {
    const config = this.languagePatterns[language as keyof typeof this.languagePatterns];
    if (!config) return [];

    const pattern = `**/*{${config.extensions.join(',')}}`;
    const allFiles = await glob.glob(pattern, { 
      cwd: scanPath,
      absolute: true,
      ignore: [
        '**/node_modules/**',
        '**/dist/**',
        '**/build/**',
        '**/coverage/**',
        '**/*.min.js',
        '**/*.bundle.js',
        ...excludePatterns
      ]
    });

    return allFiles;
  }

  private async getAllFiles(dir: string): Promise<string[]> {
    const files: string[] = [];
    const items = await fs.readdir(dir);

    for (const item of items) {
      if (item.startsWith('.') || item === 'node_modules') continue;
      
      const itemPath = path.join(dir, item);
      const stats = await fs.stat(itemPath);
      
      if (stats.isDirectory()) {
        files.push(...await this.getAllFiles(itemPath));
      } else {
        files.push(itemPath);
      }
    }

    return files;
  }

  private async analyzeFile(filePath: string, language: string): Promise<CodeQualityIssue[]> {
    const issues: CodeQualityIssue[] = [];
    const content = await fs.readFile(filePath, 'utf-8');
    const lines = content.split('\n');

    const config = this.languagePatterns[language as keyof typeof this.languagePatterns];
    if (!config) return issues;

    for (const vulnerabilityPattern of config.vulnerabilityPatterns) {
      lines.forEach((line, index) => {
        const matches = [...line.matchAll(vulnerabilityPattern.pattern)];
        matches.forEach(match => {
          issues.push({
            file: filePath,
            line: index + 1,
            column: match.index || 0,
            severity: vulnerabilityPattern.severity,
            type: vulnerabilityPattern.type,
            rule: vulnerabilityPattern.rule,
            message: vulnerabilityPattern.message,
            description: this.getDetailedDescription(vulnerabilityPattern.rule),
            cwe: vulnerabilityPattern.cwe,
            owasp: vulnerabilityPattern.owasp,
            category: this.getCategoryFromRule(vulnerabilityPattern.rule),
            tags: this.getTagsFromRule(vulnerabilityPattern.rule),
            codeContext: this.getCodeContext(lines, index),
            fixSuggestion: this.getFixSuggestion(vulnerabilityPattern.rule)
          });
        });
      });
    }

    issues.push(...await this.analyzeCodeSmells(filePath, content, language));
    issues.push(...await this.analyzeBugs(filePath, content, language));

    return issues;
  }

  private async analyzeCodeSmells(filePath: string, content: string, language: string): Promise<CodeQualityIssue[]> {
    const issues: CodeQualityIssue[] = [];
    const lines = content.split('\n');

    const longMethodThreshold = 50;
    const longParameterListThreshold = 7;
    const magicNumberPattern = /\b\d{2,}\b/g;

    let currentMethodLength = 0;
    let inMethod = false;

    lines.forEach((line, index) => {
      const trimmedLine = line.trim();

      if (language === 'javascript' || language === 'typescript') {
        if (trimmedLine.match(/function\s+\w+|=>\s*{|\w+\s*\([^)]*\)\s*{/)) {
          inMethod = true;
          currentMethodLength = 0;

          const paramMatch = line.match(/\(([^)]*)\)/);
          if (paramMatch && paramMatch[1]) {
            const paramCount = paramMatch[1].split(',').filter(p => p.trim()).length;
            if (paramCount > longParameterListThreshold) {
              issues.push({
                file: filePath,
                line: index + 1,
                severity: 'major',
                type: 'code_smell',
                rule: 'javascript:S107',
                message: `Functions should not have too many parameters (${paramCount} > ${longParameterListThreshold})`,
                description: 'Functions with many parameters are hard to understand and maintain',
                category: 'maintainability',
                tags: ['brain-overload']
              });
            }
          }
        }

        if (inMethod) {
          currentMethodLength++;
          if (trimmedLine === '}' && currentMethodLength > longMethodThreshold) {
            issues.push({
              file: filePath,
              line: index + 1,
              severity: 'major',
              type: 'code_smell',
              rule: 'javascript:S138',
              message: `Functions should not be too long (${currentMethodLength} > ${longMethodThreshold})`,
              description: 'Long functions are hard to understand and maintain',
              category: 'maintainability',
              tags: ['brain-overload']
            });
            inMethod = false;
          }
        }

        const magicNumbers = [...line.matchAll(magicNumberPattern)];
        magicNumbers.forEach(match => {
          const number = match[0];
          if (number !== '0' && number !== '1' && !this.isInComment(line, match.index || 0)) {
            issues.push({
              file: filePath,
              line: index + 1,
              column: match.index,
              severity: 'minor',
              type: 'code_smell',
              rule: 'javascript:S109',
              message: `Magic numbers should not be used (${number})`,
              description: 'Magic numbers make code harder to understand and maintain',
              category: 'readability',
              tags: ['confusing']
            });
          }
        });
      }

      if (trimmedLine.length > 120) {
        issues.push({
          file: filePath,
          line: index + 1,
          severity: 'minor',
          type: 'code_smell',
          rule: 'common:LineLength',
          message: 'Lines should not be too long',
          description: 'Long lines are hard to read',
          category: 'readability',
          tags: ['formatting']
        });
      }
    });

    return issues;
  }

  private async analyzeBugs(filePath: string, content: string, language: string): Promise<CodeQualityIssue[]> {
    const issues: CodeQualityIssue[] = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      if (language === 'javascript' || language === 'typescript') {
        if (line.match(/==\s*null/) && !line.includes('!=')) {
          issues.push({
            file: filePath,
            line: index + 1,
            severity: 'major',
            type: 'bug',
            rule: 'javascript:S2441',
            message: 'Non-existent operators "==" and "!=" should not be used',
            description: 'Use === and !== instead',
            category: 'reliability',
            tags: ['pitfall'],
            fixSuggestion: 'Replace == with === and != with !=='
          });
        }

        if (line.match(/var\s+\w+/)) {
          issues.push({
            file: filePath,
            line: index + 1,
            severity: 'minor',
            type: 'code_smell',
            rule: 'javascript:S3504',
            message: '"var" should not be used',
            description: 'Use "let" or "const" instead of "var"',
            category: 'maintainability',
            tags: ['es2015'],
            fixSuggestion: 'Replace "var" with "let" or "const"'
          });
        }

        if (line.match(/console\.(log|error|warn|info)/)) {
          issues.push({
            file: filePath,
            line: index + 1,
            severity: 'minor',
            type: 'code_smell',
            rule: 'javascript:S2228',
            message: 'Console logging should not be used in production code',
            description: 'Remove console statements or use proper logging',
            category: 'maintainability',
            tags: ['unused']
          });
        }
      }
    });

    return issues;
  }

  private async analyzeComplexity(files: string[], language: string): Promise<CodeQualityIssue[]> {
    const issues: CodeQualityIssue[] = [];
    const config = this.languagePatterns[language as keyof typeof this.languagePatterns];
    if (!config) return issues;

    for (const file of files) {
      const content = await fs.readFile(file, 'utf-8');
      const complexity = this.calculateCyclomaticComplexity(content, config.complexityTokens);
      const cognitiveComplexity = this.calculateCognitiveComplexity(content, language);

      if (complexity > 10) {
        issues.push({
          file,
          line: 1,
          severity: 'major',
          type: 'code_smell',
          rule: 'common:CyclomaticComplexity',
          message: `Cyclomatic complexity is too high (${complexity} > 10)`,
          description: 'High complexity makes code hard to test and maintain',
          category: 'maintainability',
          tags: ['brain-overload']
        });
      }

      if (cognitiveComplexity > 15) {
        issues.push({
          file,
          line: 1,
          severity: 'major',
          type: 'code_smell',
          rule: 'common:CognitiveComplexity',
          message: `Cognitive complexity is too high (${cognitiveComplexity} > 15)`,
          description: 'High cognitive complexity makes code hard to understand',
          category: 'maintainability',
          tags: ['brain-overload']
        });
      }
    }

    return issues;
  }

  private calculateCyclomaticComplexity(content: string, tokens: string[]): number {
    let complexity = 1;
    for (const token of tokens) {
      const matches = content.match(new RegExp(`\\b${token}\\b`, 'g'));
      if (matches) {
        complexity += matches.length;
      }
    }
    return complexity;
  }

  private calculateCognitiveComplexity(content: string, language: string): number {
    let complexity = 0;
    let nestingLevel = 0;
    const lines = content.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      
      if (trimmed.includes('{')) nestingLevel++;
      if (trimmed.includes('}')) nestingLevel = Math.max(0, nestingLevel - 1);

      if (language === 'javascript' || language === 'typescript') {
        if (trimmed.match(/\b(if|while|for|switch)\b/)) {
          complexity += 1 + nestingLevel;
        }
        if (trimmed.match(/\b(catch|else)\b/)) {
          complexity += 1;
        }
        if (trimmed.match(/&&|\|\|/)) {
          complexity += 1;
        }
      }
    }

    return complexity;
  }

  private async detectCodeDuplication(files: string[]): Promise<CodeQualityIssue[]> {
    const issues: CodeQualityIssue[] = [];
    const minBlockSize = 5;
    const codeBlocks: { [hash: string]: { file: string; startLine: number; lines: string[] }[] } = {};

    for (const file of files) {
      const content = await fs.readFile(file, 'utf-8');
      const lines = content.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('//') && !line.startsWith('/*'));

      for (let i = 0; i <= lines.length - minBlockSize; i++) {
        const block = lines.slice(i, i + minBlockSize);
        const blockContent = block.join('\n');
        const hash = crypto.MD5(blockContent).toString();

        if (!codeBlocks[hash]) {
          codeBlocks[hash] = [];
        }

        codeBlocks[hash].push({
          file,
          startLine: i + 1,
          lines: block
        });
      }
    }

    for (const [hash, blocks] of Object.entries(codeBlocks)) {
      if (blocks.length > 1) {
        for (const block of blocks) {
          issues.push({
            file: block.file,
            line: block.startLine,
            endLine: block.startLine + minBlockSize - 1,
            severity: 'major',
            type: 'code_smell',
            rule: 'common:DuplicatedBlocks',
            message: `Duplicated code block detected (${blocks.length} occurrences)`,
            description: 'Code duplication increases maintenance cost',
            category: 'maintainability',
            tags: ['duplicate']
          });
        }
      }
    }

    return issues;
  }

  private async calculateFileMetrics(filePath: string, language: string): Promise<Partial<SonarQubeMetrics>> {
    const content = await fs.readFile(filePath, 'utf-8');
    const lines = content.split('\n');
    
    const nonCommentLines = lines.filter(line => {
      const trimmed = line.trim();
      return trimmed && !trimmed.startsWith('//') && !trimmed.startsWith('/*') && !trimmed.startsWith('*');
    });

    const config = this.languagePatterns[language as keyof typeof this.languagePatterns];
    const complexity = config ? this.calculateCyclomaticComplexity(content, config.complexityTokens) : 1;
    const cognitiveComplexity = this.calculateCognitiveComplexity(content, language);

    return {
      lines: lines.length,
      ncloc: nonCommentLines.length,
      complexity,
      cognitive_complexity: cognitiveComplexity
    };
  }

  private initializeMetrics(): SonarQubeMetrics {
    return {
      lines: 0,
      ncloc: 0,
      complexity: 0,
      cognitive_complexity: 0,
      duplicated_lines_density: 0,
      coverage: 0,
      technical_debt: '0min',
      maintainability_rating: 'A',
      reliability_rating: 'A',
      security_rating: 'A',
      vulnerabilities: 0,
      bugs: 0,
      code_smells: 0,
      security_hotspots: 0
    };
  }

  private aggregateMetrics(metrics: SonarQubeMetrics, fileMetrics: Partial<SonarQubeMetrics>): SonarQubeMetrics {
    return {
      ...metrics,
      lines: metrics.lines + (fileMetrics.lines || 0),
      ncloc: metrics.ncloc + (fileMetrics.ncloc || 0),
      complexity: metrics.complexity + (fileMetrics.complexity || 0),
      cognitive_complexity: metrics.cognitive_complexity + (fileMetrics.cognitive_complexity || 0)
    };
  }

  private evaluateQualityGate(issues: CodeQualityIssue[], metrics: SonarQubeMetrics): QualityGate {
    const conditions = [...this.qualityGateTemplate];
    
    const vulnerabilities = issues.filter(i => i.type === 'vulnerability').length;
    const bugs = issues.filter(i => i.type === 'bug').length;
    const codeSmells = issues.filter(i => i.type === 'code_smell').length;
    const securityHotspots = issues.filter(i => i.type === 'security_hotspot').length;

    metrics.vulnerabilities = vulnerabilities;
    metrics.bugs = bugs;
    metrics.code_smells = codeSmells;
    metrics.security_hotspots = securityHotspots;

    const criticalIssues = issues.filter(i => i.severity === 'blocker' || i.severity === 'critical').length;
    const reliabilityRating = bugs > 0 ? (bugs > 5 ? 'E' : 'C') : 'A';
    const securityRating = vulnerabilities > 0 ? (vulnerabilities > 5 ? 'E' : 'C') : 'A';

    metrics.reliability_rating = reliabilityRating;
    metrics.security_rating = securityRating;

    const failed = criticalIssues > 0 || vulnerabilities > 0 || bugs > 0;

    return {
      passed: !failed,
      conditions: conditions.map(condition => ({
        ...condition,
        status: failed ? 'ERROR' : 'OK'
      }))
    };
  }

  private sortAndPrioritizeIssues(issues: CodeQualityIssue[]): CodeQualityIssue[] {
    const severityOrder = { blocker: 0, critical: 1, major: 2, minor: 3, info: 4 };
    const typeOrder = { vulnerability: 0, bug: 1, security_hotspot: 2, code_smell: 3 };

    return issues.sort((a, b) => {
      const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (severityDiff !== 0) return severityDiff;
      
      const typeDiff = typeOrder[a.type] - typeOrder[b.type];
      if (typeDiff !== 0) return typeDiff;
      
      return a.file.localeCompare(b.file);
    });
  }

  private getDetailedDescription(rule: string): string {
    const descriptions: { [key: string]: string } = {
      'javascript:S1523': 'Executing code dynamically is security-sensitive. It has led in the past to the following vulnerabilities: CVE-2017-9807, CVE-2017-9802.',
      'javascript:S5247': 'Using innerHTML or document.write with unsanitized data can lead to Cross-Site Scripting (XSS) vulnerabilities.',
      'javascript:S2068': 'Hard-coded credentials compromise security and should be stored securely outside of the code.',
      'javascript:S107': 'Functions with many parameters are difficult to understand and maintain.',
      'javascript:S138': 'Long functions are harder to understand and maintain than shorter ones.'
    };
    
    return descriptions[rule] || 'No detailed description available.';
  }

  private getCategoryFromRule(rule: string): string {
    if (rule.includes('S1523') || rule.includes('S5247') || rule.includes('S2068')) return 'security';
    if (rule.includes('S107') || rule.includes('S138')) return 'maintainability';
    return 'general';
  }

  private getTagsFromRule(rule: string): string[] {
    const tags: { [key: string]: string[] } = {
      'javascript:S1523': ['injection', 'owasp-top10'],
      'javascript:S5247': ['xss', 'owasp-top10'],
      'javascript:S2068': ['credentials', 'owasp-top10'],
      'javascript:S107': ['brain-overload'],
      'javascript:S138': ['brain-overload']
    };
    
    return tags[rule] || [];
  }

  private getCodeContext(lines: string[], lineIndex: number): string {
    const start = Math.max(0, lineIndex - 2);
    const end = Math.min(lines.length, lineIndex + 3);
    return lines.slice(start, end).join('\n');
  }

  private getFixSuggestion(rule: string): string {
    const suggestions: { [key: string]: string } = {
      'javascript:S1523': 'Avoid using eval(). Consider using JSON.parse() for JSON data or find alternative approaches.',
      'javascript:S5247': 'Sanitize user input before setting innerHTML. Consider using textContent instead.',
      'javascript:S2068': 'Store credentials in environment variables or secure configuration files.',
      'javascript:S107': 'Reduce the number of parameters by grouping related parameters into objects.',
      'javascript:S138': 'Break the function into smaller, more focused functions.'
    };
    
    return suggestions[rule] || 'Review the code and apply best practices.';
  }

  private isInComment(line: string, position: number): boolean {
    const beforePosition = line.substring(0, position);
    return beforePosition.includes('//') || beforePosition.includes('/*');
  }
}