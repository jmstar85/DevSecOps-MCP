import axios, { AxiosInstance } from 'axios';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

interface SonarQubeConfig {
  url: string;
  token: string;
  timeout?: number;
}

interface SonarQubeScanParams {
  projectKey: string;
  projectName: string;
  sources: string;
  qualityGate?: string;
  exclusions?: string[];
  inclusions?: string[];
  sonarScannerHome?: string;
}

interface SonarQubeIssue {
  key: string;
  rule: string;
  severity: string;
  component: string;
  project: string;
  line?: number;
  hash?: string;
  textRange?: {
    startLine: number;
    endLine: number;
    startOffset: number;
    endOffset: number;
  };
  flows?: any[];
  message: string;
  messageFormattings?: any[];
  debt?: string;
  author?: string;
  tags?: string[];
  creationDate: string;
  updateDate: string;
  type: string;
  organization?: string;
  fromHotspot?: boolean;
}

interface SonarQubeQualityGate {
  status: 'OK' | 'WARN' | 'ERROR';
  conditions: Array<{
    status: 'OK' | 'WARN' | 'ERROR';
    metricKey: string;
    comparator: string;
    errorThreshold?: string;
    actualValue: string;
  }>;
}

interface SonarQubeScanResult {
  projectKey: string;
  analysisKey: string;
  taskId: string;
  status: 'SUCCESS' | 'FAILED' | 'PENDING';
  issues: SonarQubeIssue[];
  qualityGate: SonarQubeQualityGate;
  metrics: {
    [key: string]: number | string;
  };
  scanDuration: number;
}

export class SonarQubeConnector {
  private client: AxiosInstance;
  private config: SonarQubeConfig;

  constructor(config?: SonarQubeConfig) {
    this.config = config || {
      url: process.env.SONARQUBE_URL || 'http://localhost:9000',
      token: process.env.SONARQUBE_TOKEN || '',
      timeout: 300000
    };

    if (!this.config.token) {
      throw new Error('SonarQube token is required');
    }

    this.client = axios.create({
      baseURL: this.config.url,
      timeout: this.config.timeout,
      headers: {
        'Authorization': `Bearer ${this.config.token}`,
        'Content-Type': 'application/json'
      }
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    this.client.interceptors.request.use(
      (config) => {
        logger.debug('SonarQube API request', {
          method: config.method,
          url: config.url,
          params: config.params
        });
        return config;
      },
      (error) => {
        logger.error('SonarQube API request error', { error: error.message });
        return Promise.reject(error);
      }
    );

    this.client.interceptors.response.use(
      (response) => {
        logger.debug('SonarQube API response', {
          status: response.status,
          url: response.config.url
        });
        return response;
      },
      (error) => {
        logger.error('SonarQube API response error', {
          status: error.response?.status,
          message: error.message,
          url: error.config?.url
        });
        return Promise.reject(error);
      }
    );
  }

  async executeScan(params: SonarQubeScanParams): Promise<SonarQubeScanResult> {
    const startTime = Date.now();
    
    try {
      logger.info('Starting SonarQube scan', {
        projectKey: params.projectKey,
        projectName: params.projectName
      });

      // Check if project exists, create if not
      await this.ensureProjectExists(params.projectKey, params.projectName);

      // Execute scanner
      const taskId = await this.runSonarScanner(params);

      // Wait for analysis to complete
      await this.waitForAnalysisCompletion(taskId);

      // Get analysis results
      const analysisResult = await this.getAnalysisResults(params.projectKey);

      const scanDuration = Date.now() - startTime;
      
      return {
        projectKey: params.projectKey,
        analysisKey: analysisResult.analysisKey,
        taskId: taskId,
        status: 'SUCCESS',
        issues: analysisResult.issues,
        qualityGate: analysisResult.qualityGate,
        metrics: analysisResult.metrics,
        scanDuration
      };

    } catch (error) {
      logger.error('SonarQube scan failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        projectKey: params.projectKey
      });
      
      return {
        projectKey: params.projectKey,
        analysisKey: '',
        taskId: '',
        status: 'FAILED',
        issues: [],
        qualityGate: { status: 'ERROR', conditions: [] },
        metrics: {},
        scanDuration: Date.now() - startTime
      };
    }
  }

  private async ensureProjectExists(projectKey: string, projectName: string): Promise<void> {
    try {
      const response = await this.client.get('/api/projects/search', {
        params: { projects: projectKey }
      });

      if (response.data.components.length === 0) {
        logger.info('Creating new SonarQube project', { projectKey, projectName });
        
        await this.client.post('/api/projects/create', {
          project: projectKey,
          name: projectName
        });
      }
    } catch (error) {
      throw new Error(`Failed to ensure project exists: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async runSonarScanner(params: SonarQubeScanParams): Promise<string> {
    const scannerParams = {
      'sonar.projectKey': params.projectKey,
      'sonar.projectName': params.projectName,
      'sonar.sources': params.sources,
      'sonar.host.url': this.config.url,
      'sonar.login': this.config.token
    };

    if (params.exclusions && params.exclusions.length > 0) {
      scannerParams['sonar.exclusions'] = params.exclusions.join(',');
    }

    if (params.inclusions && params.inclusions.length > 0) {
      scannerParams['sonar.inclusions'] = params.inclusions.join(',');
    }

    if (params.qualityGate) {
      scannerParams['sonar.qualitygate'] = params.qualityGate;
    }

    // In a real implementation, you would execute the sonar-scanner CLI
    // For this example, we'll simulate the scanner execution
    logger.info('Executing SonarQube scanner', { params: scannerParams });

    // Simulate scanner execution with a mock task ID
    const mockTaskId = `task-${Date.now()}`;
    
    // In practice, you would parse the scanner output to get the actual task ID
    return mockTaskId;
  }

  private async waitForAnalysisCompletion(taskId: string): Promise<void> {
    const maxAttempts = 60;
    const pollInterval = 5000;
    let attempts = 0;

    while (attempts < maxAttempts) {
      try {
        const response = await this.client.get(`/api/ce/task`, {
          params: { id: taskId }
        });

        const task = response.data.task;
        
        if (task.status === 'SUCCESS') {
          logger.info('SonarQube analysis completed successfully', { taskId });
          return;
        }
        
        if (task.status === 'FAILED' || task.status === 'CANCELED') {
          throw new Error(`Analysis failed with status: ${task.status}`);
        }

        logger.debug('Waiting for analysis completion', { 
          taskId, 
          status: task.status, 
          attempt: attempts + 1 
        });

        await new Promise(resolve => setTimeout(resolve, pollInterval));
        attempts++;

      } catch (error) {
        if (attempts >= maxAttempts - 1) {
          throw new Error(`Analysis timeout after ${maxAttempts} attempts`);
        }
        
        logger.warn('Error checking analysis status', { 
          taskId, 
          error: error instanceof Error ? error.message : 'Unknown error',
          attempt: attempts + 1 
        });
        
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        attempts++;
      }
    }

    throw new Error(`Analysis timeout after ${maxAttempts} attempts`);
  }

  private async getAnalysisResults(projectKey: string): Promise<{
    analysisKey: string;
    issues: SonarQubeIssue[];
    qualityGate: SonarQubeQualityGate;
    metrics: { [key: string]: number | string };
  }> {
    try {
      // Get issues
      const issuesResponse = await this.client.get('/api/issues/search', {
        params: {
          componentKeys: projectKey,
          resolved: false,
          ps: 500
        }
      });

      // Get quality gate status
      const qualityGateResponse = await this.client.get('/api/qualitygates/project_status', {
        params: { projectKey }
      });

      // Get metrics
      const metricsResponse = await this.client.get('/api/measures/component', {
        params: {
          component: projectKey,
          metricKeys: [
            'bugs',
            'vulnerabilities',
            'security_hotspots',
            'code_smells',
            'coverage',
            'duplicated_lines_density',
            'ncloc',
            'sqale_index'
          ].join(',')
        }
      });

      const metrics: { [key: string]: number | string } = {};
      if (metricsResponse.data.component?.measures) {
        metricsResponse.data.component.measures.forEach((measure: any) => {
          metrics[measure.metric] = measure.value;
        });
      }

      return {
        analysisKey: qualityGateResponse.data.projectStatus?.analysisId || '',
        issues: issuesResponse.data.issues || [],
        qualityGate: qualityGateResponse.data.projectStatus || { status: 'ERROR', conditions: [] },
        metrics
      };

    } catch (error) {
      throw new Error(`Failed to get analysis results: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getProjects(): Promise<any[]> {
    try {
      const response = await this.client.get('/api/projects/search');
      return response.data.components || [];
    } catch (error) {
      throw new Error(`Failed to get projects: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getQualityGates(): Promise<any[]> {
    try {
      const response = await this.client.get('/api/qualitygates/list');
      return response.data.qualitygates || [];
    } catch (error) {
      throw new Error(`Failed to get quality gates: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async createQualityGate(name: string, conditions: any[]): Promise<any> {
    try {
      const response = await this.client.post('/api/qualitygates/create', {
        name
      });

      const qualityGateId = response.data.id;

      // Add conditions
      for (const condition of conditions) {
        await this.client.post('/api/qualitygates/create_condition', {
          gateId: qualityGateId,
          metric: condition.metric,
          op: condition.operator,
          error: condition.threshold
        });
      }

      return response.data;
    } catch (error) {
      throw new Error(`Failed to create quality gate: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async deleteProject(projectKey: string): Promise<void> {
    try {
      await this.client.post('/api/projects/delete', {
        project: projectKey
      });
      
      logger.info('SonarQube project deleted', { projectKey });
    } catch (error) {
      throw new Error(`Failed to delete project: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getSystemHealth(): Promise<any> {
    try {
      const response = await this.client.get('/api/system/health');
      return response.data;
    } catch (error) {
      throw new Error(`Failed to get system health: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}