import axios, { AxiosInstance } from 'axios';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

interface ZAPConfig {
  url: string;
  apiKey: string;
  timeout?: number;
}

interface ZAPScanParams {
  targetUrl: string;
  scanId: string;
  spiderOptions?: {
    maxDepth?: number;
    maxChildren?: number;
    excludePatterns?: string[];
  };
  authentication?: {
    username: string;
    password: string;
  };
  activeScanPolicy?: string;
}

interface ZAPAlert {
  pluginId: string;
  alertId: string;
  alert: string;
  name: string;
  riskcode: string;
  riskdesc: string;
  reliability: string;
  confidence: string;
  param: string;
  attack: string;
  otherinfo: string;
  solution: string;
  reference: string;
  evidence: string;
  cweid: string;
  wascid: string;
  sourceid: string;
  url: string;
  method: string;
  description: string;
  messageId: string;
  inputVector: string;
}

interface ZAPSpiderResult {
  scanId: string;
  status: string;
  progress: number;
  urlsFound: number;
  urlsProcessed: number;
  urlsInScope: number;
  urlsOutOfScope: number;
}

interface ZAPActiveScanResult {
  scanId: string;
  status: string;
  progress: number;
  hostsScanned: number;
  alertsRaised: number;
  parametersProcessed: number;
}

interface ZAPScanResult {
  scanId: string;
  targetUrl: string;
  status: 'completed' | 'failed' | 'running';
  spider: ZAPSpiderResult;
  activeScan?: ZAPActiveScanResult;
  alerts: ZAPAlert[];
  scanDuration: number;
}

export class ZAPConnector {
  private client: AxiosInstance;
  private config: ZAPConfig;

  constructor(config?: ZAPConfig) {
    this.config = config || {
      url: process.env.ZAP_URL || 'http://localhost:8080',
      apiKey: process.env.ZAP_API_KEY || '',
      timeout: 300000
    };

    this.client = axios.create({
      baseURL: this.config.url,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    this.client.interceptors.request.use(
      (config) => {
        // Add API key to all requests
        if (this.config.apiKey) {
          config.params = { ...config.params, apikey: this.config.apiKey };
        }
        
        logger.debug('ZAP API request', {
          method: config.method,
          url: config.url,
          params: config.params
        });
        return config;
      },
      (error) => {
        logger.error('ZAP API request error', { error: error.message });
        return Promise.reject(error);
      }
    );

    this.client.interceptors.response.use(
      (response) => {
        logger.debug('ZAP API response', {
          status: response.status,
          url: response.config.url
        });
        return response;
      },
      (error) => {
        logger.error('ZAP API response error', {
          status: error.response?.status,
          message: error.message,
          url: error.config?.url
        });
        return Promise.reject(error);
      }
    );
  }

  async executeBaselineScan(params: ZAPScanParams): Promise<ZAPScanResult> {
    const startTime = Date.now();
    
    try {
      logger.info('Starting ZAP baseline scan', {
        targetUrl: params.targetUrl,
        scanId: params.scanId
      });

      // Set up context and include URL in scope
      await this.setupScanContext(params);

      // Execute spider scan
      const spiderResult = await this.runSpiderScan(params);

      // Get alerts
      const alerts = await this.getAlerts(params.targetUrl);

      const scanDuration = Date.now() - startTime;

      return {
        scanId: params.scanId,
        targetUrl: params.targetUrl,
        status: 'completed',
        spider: spiderResult,
        alerts,
        scanDuration
      };

    } catch (error) {
      logger.error('ZAP baseline scan failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        targetUrl: params.targetUrl
      });
      
      return {
        scanId: params.scanId,
        targetUrl: params.targetUrl,
        status: 'failed',
        spider: {
          scanId: params.scanId,
          status: 'failed',
          progress: 0,
          urlsFound: 0,
          urlsProcessed: 0,
          urlsInScope: 0,
          urlsOutOfScope: 0
        },
        alerts: [],
        scanDuration: Date.now() - startTime
      };
    }
  }

  async executeFullScan(params: ZAPScanParams): Promise<ZAPScanResult> {
    const startTime = Date.now();
    
    try {
      logger.info('Starting ZAP full scan', {
        targetUrl: params.targetUrl,
        scanId: params.scanId
      });

      // Set up context and include URL in scope
      await this.setupScanContext(params);

      // Execute spider scan
      const spiderResult = await this.runSpiderScan(params);

      // Execute active scan
      const activeScanResult = await this.runActiveScan(params);

      // Get alerts
      const alerts = await this.getAlerts(params.targetUrl);

      const scanDuration = Date.now() - startTime;

      return {
        scanId: params.scanId,
        targetUrl: params.targetUrl,
        status: 'completed',
        spider: spiderResult,
        activeScan: activeScanResult,
        alerts,
        scanDuration
      };

    } catch (error) {
      logger.error('ZAP full scan failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        targetUrl: params.targetUrl
      });
      
      return {
        scanId: params.scanId,
        targetUrl: params.targetUrl,
        status: 'failed',
        spider: {
          scanId: params.scanId,
          status: 'failed',
          progress: 0,
          urlsFound: 0,
          urlsProcessed: 0,
          urlsInScope: 0,
          urlsOutOfScope: 0
        },
        alerts: [],
        scanDuration: Date.now() - startTime
      };
    }
  }

  private async setupScanContext(params: ZAPScanParams): Promise<void> {
    try {
      // Create new context
      const contextResponse = await this.client.get('/JSON/context/action/newContext/', {
        params: { contextName: `context-${params.scanId}` }
      });

      const contextId = contextResponse.data.contextId;

      // Include URL in context
      await this.client.get('/JSON/context/action/includeInContext/', {
        params: {
          contextName: `context-${params.scanId}`,
          regex: `${params.targetUrl}.*`
        }
      });

      // Set up authentication if provided
      if (params.authentication) {
        await this.setupAuthentication(contextId, params.authentication);
      }

      // Apply exclusions if provided
      if (params.spiderOptions?.excludePatterns) {
        for (const pattern of params.spiderOptions.excludePatterns) {
          await this.client.get('/JSON/context/action/excludeFromContext/', {
            params: {
              contextName: `context-${params.scanId}`,
              regex: pattern
            }
          });
        }
      }

    } catch (error) {
      throw new Error(`Failed to setup scan context: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async setupAuthentication(contextId: string, auth: { username: string; password: string }): Promise<void> {
    try {
      // Set up form-based authentication
      await this.client.get('/JSON/authentication/action/setAuthenticationMethod/', {
        params: {
          contextId,
          authMethodName: 'formBasedAuthentication',
          authMethodConfigParams: `loginUrl=${encodeURIComponent(auth.username)}&loginRequestData=${encodeURIComponent(auth.password)}`
        }
      });

      // Set up user
      await this.client.get('/JSON/users/action/newUser/', {
        params: {
          contextId,
          name: 'scan-user'
        }
      });

      await this.client.get('/JSON/users/action/setAuthenticationCredentials/', {
        params: {
          contextId,
          userId: '0',
          authCredentialsConfigParams: `username=${auth.username}&password=${auth.password}`
        }
      });

    } catch (error) {
      throw new Error(`Failed to setup authentication: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async runSpiderScan(params: ZAPScanParams): Promise<ZAPSpiderResult> {
    try {
      // Start spider scan
      const spiderResponse = await this.client.get('/JSON/spider/action/scan/', {
        params: {
          url: params.targetUrl,
          maxChildren: params.spiderOptions?.maxChildren || 10,
          recurse: true,
          contextName: `context-${params.scanId}`
        }
      });

      const spiderScanId = spiderResponse.data.scan;

      // Wait for spider to complete
      await this.waitForSpiderCompletion(spiderScanId);

      // Get spider results
      const statusResponse = await this.client.get('/JSON/spider/view/status/', {
        params: { scanId: spiderScanId }
      });

      const resultsResponse = await this.client.get('/JSON/spider/view/results/', {
        params: { scanId: spiderScanId }
      });

      return {
        scanId: spiderScanId,
        status: 'completed',
        progress: 100,
        urlsFound: resultsResponse.data.results?.length || 0,
        urlsProcessed: resultsResponse.data.results?.length || 0,
        urlsInScope: resultsResponse.data.results?.length || 0,
        urlsOutOfScope: 0
      };

    } catch (error) {
      throw new Error(`Spider scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async runActiveScan(params: ZAPScanParams): Promise<ZAPActiveScanResult> {
    try {
      // Start active scan
      const activeScanResponse = await this.client.get('/JSON/ascan/action/scan/', {
        params: {
          url: params.targetUrl,
          recurse: true,
          inScopeOnly: true,
          scanPolicyName: params.activeScanPolicy || 'Default Policy',
          contextId: `context-${params.scanId}`
        }
      });

      const activeScanId = activeScanResponse.data.scan;

      // Wait for active scan to complete
      await this.waitForActiveScanCompletion(activeScanId);

      // Get active scan results
      const statusResponse = await this.client.get('/JSON/ascan/view/status/', {
        params: { scanId: activeScanId }
      });

      const messagesResponse = await this.client.get('/JSON/ascan/view/messagesIds/', {
        params: { scanId: activeScanId }
      });

      return {
        scanId: activeScanId,
        status: 'completed',
        progress: 100,
        hostsScanned: 1,
        alertsRaised: 0,
        parametersProcessed: messagesResponse.data.messagesIds?.length || 0
      };

    } catch (error) {
      throw new Error(`Active scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async waitForSpiderCompletion(scanId: string): Promise<void> {
    const maxAttempts = 120;
    const pollInterval = 5000;
    let attempts = 0;

    while (attempts < maxAttempts) {
      try {
        const response = await this.client.get('/JSON/spider/view/status/', {
          params: { scanId }
        });

        const progress = parseInt(response.data.status);
        
        if (progress >= 100) {
          logger.info('Spider scan completed', { scanId, progress });
          return;
        }

        logger.debug('Spider scan in progress', { scanId, progress, attempt: attempts + 1 });
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        attempts++;

      } catch (error) {
        logger.warn('Error checking spider status', { 
          scanId, 
          error: error instanceof Error ? error.message : 'Unknown error',
          attempt: attempts + 1 
        });
        
        if (attempts >= maxAttempts - 1) {
          throw new Error(`Spider scan timeout after ${maxAttempts} attempts`);
        }
        
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        attempts++;
      }
    }

    throw new Error(`Spider scan timeout after ${maxAttempts} attempts`);
  }

  private async waitForActiveScanCompletion(scanId: string): Promise<void> {
    const maxAttempts = 240;
    const pollInterval = 10000;
    let attempts = 0;

    while (attempts < maxAttempts) {
      try {
        const response = await this.client.get('/JSON/ascan/view/status/', {
          params: { scanId }
        });

        const progress = parseInt(response.data.status);
        
        if (progress >= 100) {
          logger.info('Active scan completed', { scanId, progress });
          return;
        }

        logger.debug('Active scan in progress', { scanId, progress, attempt: attempts + 1 });
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        attempts++;

      } catch (error) {
        logger.warn('Error checking active scan status', { 
          scanId, 
          error: error instanceof Error ? error.message : 'Unknown error',
          attempt: attempts + 1 
        });
        
        if (attempts >= maxAttempts - 1) {
          throw new Error(`Active scan timeout after ${maxAttempts} attempts`);
        }
        
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        attempts++;
      }
    }

    throw new Error(`Active scan timeout after ${maxAttempts} attempts`);
  }

  private async getAlerts(baseUrl?: string): Promise<ZAPAlert[]> {
    try {
      const params: any = {};
      if (baseUrl) {
        params.baseurl = baseUrl;
      }

      const response = await this.client.get('/JSON/core/view/alerts/', { params });
      return response.data.alerts || [];

    } catch (error) {
      throw new Error(`Failed to get alerts: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getZAPStatus(): Promise<any> {
    try {
      const response = await this.client.get('/JSON/core/view/version/');
      return response.data;
    } catch (error) {
      throw new Error(`Failed to get ZAP status: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async stopAllScans(): Promise<void> {
    try {
      await this.client.get('/JSON/spider/action/stopAllScans/');
      await this.client.get('/JSON/ascan/action/stopAllScans/');
      logger.info('All ZAP scans stopped');
    } catch (error) {
      throw new Error(`Failed to stop scans: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async clearSession(): Promise<void> {
    try {
      await this.client.get('/JSON/core/action/newSession/');
      logger.info('ZAP session cleared');
    } catch (error) {
      throw new Error(`Failed to clear session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async generateReport(format: 'html' | 'xml' | 'json' = 'html'): Promise<string> {
    try {
      const endpoint = format === 'html' ? '/OTHER/core/other/htmlreport/' :
                     format === 'xml' ? '/OTHER/core/other/xmlreport/' :
                     '/JSON/core/view/alerts/';

      const response = await this.client.get(endpoint);
      return format === 'json' ? JSON.stringify(response.data, null, 2) : response.data;

    } catch (error) {
      throw new Error(`Failed to generate report: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}