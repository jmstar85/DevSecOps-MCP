import axios from 'axios';
import * as fs from 'fs-extra';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface DASTResult {
  url: string;
  method: string;
  vulnerability: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence?: string;
  cwe?: string;
  owasp?: string;
  recommendation: string;
}

export class DASTTool {
  private readonly commonPorts = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000];
  private readonly userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'DevSecOps-Scanner/1.0',
  ];

  async scan(args: {
    url: string;
    scan_type?: 'quick' | 'full' | 'api' | 'spider';
    auth?: {
      type: 'basic' | 'bearer' | 'session';
      credentials: any;
    };
  }) {
    const { url, scan_type = 'quick', auth } = args;

    if (!this.isValidUrl(url)) {
      throw new Error('Invalid URL provided');
    }

    const results: DASTResult[] = [];
    const startTime = Date.now();

    try {
      switch (scan_type) {
        case 'quick':
          results.push(...await this.performQuickScan(url, auth));
          break;
        case 'full':
          results.push(...await this.performFullScan(url, auth));
          break;
        case 'api':
          results.push(...await this.performApiScan(url, auth));
          break;
        case 'spider':
          results.push(...await this.performSpiderScan(url, auth));
          break;
      }

      const endTime = Date.now();
      const scanDuration = endTime - startTime;

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              scan_type: 'DAST',
              target: url,
              scan_mode: scan_type,
              timestamp: new Date().toISOString(),
              duration_ms: scanDuration,
              results,
              summary: {
                total_vulnerabilities: results.length,
                critical: results.filter(r => r.severity === 'critical').length,
                high: results.filter(r => r.severity === 'high').length,
                medium: results.filter(r => r.severity === 'medium').length,
                low: results.filter(r => r.severity === 'low').length,
              },
            }, null, 2),
          },
        ],
      };
    } catch (error) {
      throw new Error(`DAST scan failed: ${error.message}`);
    }
  }

  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  private async performQuickScan(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];

    results.push(...await this.checkBasicVulnerabilities(url, auth));
    results.push(...await this.checkHttpHeaders(url, auth));
    results.push(...await this.checkSslTls(url));

    return results;
  }

  private async performFullScan(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];

    results.push(...await this.performQuickScan(url, auth));
    results.push(...await this.checkXssVulnerabilities(url, auth));
    results.push(...await this.checkSqlInjection(url, auth));
    results.push(...await this.checkDirectoryTraversal(url, auth));
    results.push(...await this.checkCommandInjection(url, auth));
    results.push(...await this.performPortScan(url));

    return results;
  }

  private async performApiScan(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];

    results.push(...await this.checkBasicVulnerabilities(url, auth));
    results.push(...await this.checkApiSpecificVulnerabilities(url, auth));
    results.push(...await this.checkAuthenticationFlaws(url, auth));
    results.push(...await this.checkRateLimiting(url, auth));

    return results;
  }

  private async performSpiderScan(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];
    const discoveredUrls = await this.spiderWebsite(url, auth);

    for (const discoveredUrl of discoveredUrls) {
      results.push(...await this.checkBasicVulnerabilities(discoveredUrl, auth));
    }

    return results;
  }

  private async checkBasicVulnerabilities(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];

    try {
      const response = await this.makeRequest(url, 'GET', auth);
      
      if (response.status === 200) {
        const body = response.data;
        
        if (body.includes('error') || body.includes('exception') || body.includes('stack trace')) {
          results.push({
            url,
            method: 'GET',
            vulnerability: 'Information Disclosure',
            severity: 'medium',
            description: 'Application may be disclosing sensitive error information',
            evidence: 'Error messages detected in response',
            cwe: 'CWE-200',
            owasp: 'A01:2021 - Broken Access Control',
            recommendation: 'Implement proper error handling and avoid exposing sensitive information',
          });
        }

        if (body.includes('admin') || body.includes('dashboard') || body.includes('management')) {
          results.push({
            url,
            method: 'GET',
            vulnerability: 'Sensitive Content Exposure',
            severity: 'low',
            description: 'Page may contain references to administrative interfaces',
            evidence: 'Administrative keywords detected',
            cwe: 'CWE-200',
            recommendation: 'Review content for sensitive information disclosure',
          });
        }
      }
    } catch (error) {
      console.error(`Error checking basic vulnerabilities for ${url}:`, error.message);
    }

    return results;
  }

  private async checkHttpHeaders(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];

    try {
      const response = await this.makeRequest(url, 'GET', auth);
      const headers = response.headers;

      const securityHeaders = {
        'x-frame-options': 'X-Frame-Options header missing - Clickjacking protection',
        'x-content-type-options': 'X-Content-Type-Options header missing - MIME sniffing protection',
        'x-xss-protection': 'X-XSS-Protection header missing - XSS protection',
        'strict-transport-security': 'Strict-Transport-Security header missing - HTTPS enforcement',
        'content-security-policy': 'Content-Security-Policy header missing - XSS/injection protection',
        'referrer-policy': 'Referrer-Policy header missing - Information leakage protection',
      };

      for (const [header, description] of Object.entries(securityHeaders)) {
        if (!headers[header] && !headers[header.toLowerCase()]) {
          results.push({
            url,
            method: 'GET',
            vulnerability: 'Missing Security Header',
            severity: 'medium',
            description,
            cwe: 'CWE-693',
            owasp: 'A05:2021 - Security Misconfiguration',
            recommendation: `Implement ${header} header for enhanced security`,
          });
        }
      }

      if (headers['server']) {
        results.push({
          url,
          method: 'GET',
          vulnerability: 'Server Information Disclosure',
          severity: 'low',
          description: 'Server header reveals software information',
          evidence: `Server: ${headers['server']}`,
          cwe: 'CWE-200',
          recommendation: 'Remove or obfuscate server header information',
        });
      }
    } catch (error) {
      console.error(`Error checking HTTP headers for ${url}:`, error.message);
    }

    return results;
  }

  private async checkSslTls(url: string): Promise<DASTResult[]> {
    const results: DASTResult[] = [];

    if (!url.startsWith('https://')) {
      results.push({
        url,
        method: 'GET',
        vulnerability: 'Insecure Transport',
        severity: 'high',
        description: 'Application not using HTTPS',
        cwe: 'CWE-319',
        owasp: 'A02:2021 - Cryptographic Failures',
        recommendation: 'Implement HTTPS with proper SSL/TLS configuration',
      });
    }

    return results;
  }

  private async checkXssVulnerabilities(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '"><script>alert("XSS")</script>',
      "javascript:alert('XSS')",
      '<img src=x onerror=alert("XSS")>',
    ];

    for (const payload of xssPayloads) {
      try {
        const testUrl = `${url}?test=${encodeURIComponent(payload)}`;
        const response = await this.makeRequest(testUrl, 'GET', auth);
        
        if (response.data.includes(payload)) {
          results.push({
            url: testUrl,
            method: 'GET',
            vulnerability: 'Cross-Site Scripting (XSS)',
            severity: 'high',
            description: 'Reflected XSS vulnerability detected',
            evidence: `Payload reflected: ${payload}`,
            cwe: 'CWE-79',
            owasp: 'A03:2021 - Injection',
            recommendation: 'Implement input validation and output encoding',
          });
          break;
        }
      } catch (error) {
        console.error(`Error testing XSS payload:`, error.message);
      }
    }

    return results;
  }

  private async checkSqlInjection(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];
    const sqlPayloads = [
      "' OR '1'='1",
      "' UNION SELECT NULL--",
      "'; DROP TABLE users--",
      "1' OR '1'='1' --",
    ];

    for (const payload of sqlPayloads) {
      try {
        const testUrl = `${url}?id=${encodeURIComponent(payload)}`;
        const response = await this.makeRequest(testUrl, 'GET', auth);
        
        if (response.data.includes('mysql') || response.data.includes('postgresql') || 
            response.data.includes('sqlite') || response.data.includes('oracle')) {
          results.push({
            url: testUrl,
            method: 'GET',
            vulnerability: 'SQL Injection',
            severity: 'critical',
            description: 'SQL injection vulnerability detected',
            evidence: `Database error revealed with payload: ${payload}`,
            cwe: 'CWE-89',
            owasp: 'A03:2021 - Injection',
            recommendation: 'Use parameterized queries and input validation',
          });
          break;
        }
      } catch (error) {
        console.error(`Error testing SQL injection payload:`, error.message);
      }
    }

    return results;
  }

  private async checkDirectoryTraversal(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];
    const traversalPayloads = [
      '../../../etc/passwd',
      '....//....//....//etc/passwd',
      '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    ];

    for (const payload of traversalPayloads) {
      try {
        const testUrl = `${url}?file=${encodeURIComponent(payload)}`;
        const response = await this.makeRequest(testUrl, 'GET', auth);
        
        if (response.data.includes('root:') || response.data.includes('localhost')) {
          results.push({
            url: testUrl,
            method: 'GET',
            vulnerability: 'Directory Traversal',
            severity: 'high',
            description: 'Directory traversal vulnerability detected',
            evidence: `System files accessible via: ${payload}`,
            cwe: 'CWE-22',
            owasp: 'A01:2021 - Broken Access Control',
            recommendation: 'Implement proper input validation and file access controls',
          });
          break;
        }
      } catch (error) {
        console.error(`Error testing directory traversal payload:`, error.message);
      }
    }

    return results;
  }

  private async checkCommandInjection(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];
    const commandPayloads = [
      '; ls -la',
      '| whoami',
      '&& cat /etc/passwd',
      '`id`',
    ];

    for (const payload of commandPayloads) {
      try {
        const testUrl = `${url}?cmd=${encodeURIComponent(payload)}`;
        const response = await this.makeRequest(testUrl, 'GET', auth);
        
        if (response.data.includes('uid=') || response.data.includes('total ')) {
          results.push({
            url: testUrl,
            method: 'GET',
            vulnerability: 'Command Injection',
            severity: 'critical',
            description: 'Command injection vulnerability detected',
            evidence: `Command execution detected with payload: ${payload}`,
            cwe: 'CWE-78',
            owasp: 'A03:2021 - Injection',
            recommendation: 'Avoid executing system commands with user input',
          });
          break;
        }
      } catch (error) {
        console.error(`Error testing command injection payload:`, error.message);
      }
    }

    return results;
  }

  private async checkApiSpecificVulnerabilities(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];

    try {
      const response = await this.makeRequest(url, 'GET', auth);
      
      if (response.headers['content-type']?.includes('application/json')) {
        const corsResponse = await this.makeRequest(url, 'OPTIONS', auth);
        
        if (corsResponse.headers['access-control-allow-origin'] === '*') {
          results.push({
            url,
            method: 'OPTIONS',
            vulnerability: 'Overly Permissive CORS',
            severity: 'medium',
            description: 'CORS policy allows all origins',
            evidence: 'Access-Control-Allow-Origin: *',
            cwe: 'CWE-942',
            owasp: 'A05:2021 - Security Misconfiguration',
            recommendation: 'Restrict CORS to specific trusted domains',
          });
        }
      }
    } catch (error) {
      console.error(`Error checking API vulnerabilities:`, error.message);
    }

    return results;
  }

  private async checkAuthenticationFlaws(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];

    try {
      const response = await this.makeRequest(url, 'GET');
      
      if (response.status === 200 && auth) {
        results.push({
          url,
          method: 'GET',
          vulnerability: 'Authentication Bypass',
          severity: 'high',
          description: 'Resource accessible without authentication',
          cwe: 'CWE-287',
          owasp: 'A07:2021 - Identification and Authentication Failures',
          recommendation: 'Implement proper authentication checks',
        });
      }
    } catch (error) {
      console.error(`Error checking authentication:`, error.message);
    }

    return results;
  }

  private async checkRateLimiting(url: string, auth?: any): Promise<DASTResult[]> {
    const results: DASTResult[] = [];
    const requestCount = 10;
    const requests = [];

    for (let i = 0; i < requestCount; i++) {
      requests.push(this.makeRequest(url, 'GET', auth));
    }

    try {
      const responses = await Promise.all(requests);
      const successfulRequests = responses.filter(r => r.status === 200).length;
      
      if (successfulRequests === requestCount) {
        results.push({
          url,
          method: 'GET',
          vulnerability: 'Missing Rate Limiting',
          severity: 'medium',
          description: 'No rate limiting detected',
          evidence: `${requestCount} consecutive requests successful`,
          cwe: 'CWE-770',
          owasp: 'A04:2021 - Insecure Design',
          recommendation: 'Implement rate limiting to prevent abuse',
        });
      }
    } catch (error) {
      console.error(`Error checking rate limiting:`, error.message);
    }

    return results;
  }

  private async performPortScan(url: string): Promise<DASTResult[]> {
    const results: DASTResult[] = [];
    const hostname = new URL(url).hostname;

    for (const port of this.commonPorts) {
      try {
        const response = await axios.get(`http://${hostname}:${port}`, { timeout: 1000 });
        
        if (response.status === 200) {
          results.push({
            url: `http://${hostname}:${port}`,
            method: 'GET',
            vulnerability: 'Open Port',
            severity: 'low',
            description: `Port ${port} is open and responding`,
            cwe: 'CWE-200',
            recommendation: 'Review if this port should be publicly accessible',
          });
        }
      } catch (error) {
        
      }
    }

    return results;
  }

  private async spiderWebsite(url: string, auth?: any): Promise<string[]> {
    const discoveredUrls = new Set<string>([url]);
    const toVisit = [url];
    const visited = new Set<string>();
    const maxDepth = 3;

    while (toVisit.length > 0 && visited.size < maxDepth) {
      const currentUrl = toVisit.pop()!;
      if (visited.has(currentUrl)) continue;
      
      visited.add(currentUrl);

      try {
        const response = await this.makeRequest(currentUrl, 'GET', auth);
        const links = this.extractLinks(response.data, currentUrl);
        
        for (const link of links) {
          if (!discoveredUrls.has(link) && link.startsWith(url)) {
            discoveredUrls.add(link);
            toVisit.push(link);
          }
        }
      } catch (error) {
        console.error(`Error spidering ${currentUrl}:`, error.message);
      }
    }

    return Array.from(discoveredUrls);
  }

  private extractLinks(html: string, baseUrl: string): string[] {
    const links: string[] = [];
    const linkRegex = /href\s*=\s*["']([^"']+)["']/gi;
    let match;

    while ((match = linkRegex.exec(html)) !== null) {
      try {
        const link = new URL(match[1], baseUrl).href;
        links.push(link);
      } catch (error) {
        
      }
    }

    return links;
  }

  private async makeRequest(url: string, method: string = 'GET', auth?: any) {
    const config: any = {
      method,
      url,
      timeout: 10000,
      headers: {
        'User-Agent': this.userAgents[Math.floor(Math.random() * this.userAgents.length)],
      },
    };

    if (auth) {
      switch (auth.type) {
        case 'basic':
          config.auth = auth.credentials;
          break;
        case 'bearer':
          config.headers['Authorization'] = `Bearer ${auth.credentials.token}`;
          break;
        case 'session':
          config.headers['Cookie'] = auth.credentials.cookie;
          break;
      }
    }

    return await axios(config);
  }
}