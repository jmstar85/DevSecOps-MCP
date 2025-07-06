import { jest } from '@jest/globals';
import { DASTTool } from '../../src/mcp/tools/dast-tool';
import axios from 'axios';

// Mock dependencies
jest.mock('axios');
jest.mock('../../src/mcp/connectors/zap');

const mockAxios = axios as jest.Mocked<typeof axios>;

describe('DASTTool', () => {
  let dastTool: DASTTool;

  beforeEach(() => {
    dastTool = new DASTTool();
    jest.clearAllMocks();
  });

  describe('executeScan', () => {
    it('should validate required parameters', async () => {
      const invalidParams = {};
      
      const result = await dastTool.executeScan(invalidParams as any);
      
      expect(result.content[0].text).toContain('Invalid parameters');
      expect(result.content[0].text).toContain('target_url');
    });

    it('should validate URL format', async () => {
      const invalidParams = {
        target_url: 'not-a-valid-url'
      };
      
      const result = await dastTool.executeScan(invalidParams);
      
      expect(result.content[0].text).toContain('Invalid parameters');
    });

    it('should execute baseline scan successfully', async () => {
      const params = {
        target_url: 'https://example.com',
        scan_type: 'baseline' as const
      };

      // Mock target validation
      mockAxios.get.mockResolvedValueOnce({
        status: 200,
        data: 'OK'
      });

      // Mock ZAP connector
      const mockZapResult = {
        alerts: [
          {
            pluginId: '10038',
            name: 'Content Security Policy (CSP) Header Not Set',
            riskcode: '2',
            confidence: '3',
            url: 'https://example.com',
            method: 'GET',
            description: 'CSP header missing',
            solution: 'Implement CSP header'
          }
        ],
        spider: {
          urlsFound: 10,
          urlsProcessed: 10
        }
      };

      // Mock the ZAP connector method
      const mockZapConnector = {
        executeBaselineScan: jest.fn().mockResolvedValue(mockZapResult)
      };

      (dastTool as any).zapConnector = mockZapConnector;

      const result = await dastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.tool).toBe('OWASP ZAP');
      expect(scanResult.status).toBe('completed');
      expect(scanResult.target_url).toBe('https://example.com');
      expect(scanResult.vulnerabilities).toHaveLength(1);
      expect(scanResult.metadata.scan_type).toBe('baseline');
    });

    it('should execute full scan with active scanning', async () => {
      const params = {
        target_url: 'https://example.com',
        scan_type: 'full' as const,
        active_scan_policy: 'Custom Policy'
      };

      // Mock target validation
      mockAxios.get.mockResolvedValueOnce({
        status: 200,
        data: 'OK'
      });

      const mockZapResult = {
        alerts: [
          {
            pluginId: '40012',
            name: 'Cross Site Scripting (Reflected)',
            riskcode: '3',
            confidence: '2',
            url: 'https://example.com/search',
            method: 'GET',
            parameter: 'q',
            attack: '<script>alert(1)</script>',
            description: 'XSS vulnerability found',
            cwe_id: 79
          }
        ],
        spider: {
          urlsFound: 25,
          urlsProcessed: 25
        },
        activeScan: {
          parametersProcessed: 15
        }
      };

      const mockZapConnector = {
        executeFullScan: jest.fn().mockResolvedValue(mockZapResult)
      };

      (dastTool as any).zapConnector = mockZapConnector;

      const result = await dastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.tool).toBe('OWASP ZAP');
      expect(scanResult.status).toBe('completed');
      expect(scanResult.vulnerabilities).toHaveLength(1);
      expect(scanResult.vulnerabilities[0].severity).toBe('high');
      expect(scanResult.coverage.parameters_tested).toBe(15);
    });

    it('should handle authentication configuration', async () => {
      const params = {
        target_url: 'https://example.com',
        authentication: {
          username: 'testuser',
          password: 'testpass'
        }
      };

      // Mock target validation
      mockAxios.get.mockResolvedValueOnce({
        status: 200,
        data: 'OK'
      });

      const mockZapResult = {
        alerts: [],
        spider: { urlsFound: 5, urlsProcessed: 5 }
      };

      const mockZapConnector = {
        executeBaselineScan: jest.fn().mockResolvedValue(mockZapResult)
      };

      (dastTool as any).zapConnector = mockZapConnector;

      await dastTool.executeScan(params);

      expect(mockZapConnector.executeBaselineScan).toHaveBeenCalledWith(
        expect.objectContaining({
          authentication: {
            username: 'testuser',
            password: 'testpass'
          }
        })
      );
    });

    it('should validate target accessibility', async () => {
      const params = {
        target_url: 'https://nonexistent.example.com'
      };

      // Mock connection refused error
      mockAxios.get.mockRejectedValueOnce({
        code: 'ECONNREFUSED',
        message: 'Connection refused'
      });

      const result = await dastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.message).toContain('not accessible');
    });

    it('should handle server errors gracefully', async () => {
      const params = {
        target_url: 'https://example.com'
      };

      // Mock server error
      mockAxios.get.mockResolvedValueOnce({
        status: 500,
        data: 'Internal Server Error'
      });

      const result = await dastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.message).toContain('server error');
    });
  });

  describe('vulnerability mapping', () => {
    it('should correctly map ZAP risk levels to severity', () => {
      const tool = new DASTTool();
      
      // Access private method for testing
      const mapRisk = (tool as any).mapZAPRiskToSeverity.bind(tool);
      
      expect(mapRisk(3)).toBe('critical');
      expect(mapRisk(2)).toBe('high');
      expect(mapRisk(1)).toBe('medium');
      expect(mapRisk(0)).toBe('low');
      expect(mapRisk('High')).toBe('high');
      expect(mapRisk('Medium')).toBe('medium');
      expect(mapRisk('Low')).toBe('low');
    });

    it('should correctly map ZAP confidence levels', () => {
      const tool = new DASTTool();
      
      const mapConfidence = (tool as any).mapZAPConfidence.bind(tool);
      
      expect(mapConfidence(3)).toBe('high');
      expect(mapConfidence(2)).toBe('medium');
      expect(mapConfidence(1)).toBe('low');
      expect(mapConfidence('High')).toBe('high');
      expect(mapConfidence('Medium')).toBe('medium');
      expect(mapConfidence('Low')).toBe('low');
    });

    it('should generate vulnerability summary correctly', () => {
      const vulnerabilities = [
        { severity: 'critical' },
        { severity: 'high' },
        { severity: 'high' },
        { severity: 'medium' },
        { severity: 'low' }
      ];

      const tool = new DASTTool();
      const summary = (tool as any).calculateSummary(vulnerabilities);

      expect(summary.total).toBe(5);
      expect(summary.critical).toBe(1);
      expect(summary.high).toBe(2);
      expect(summary.medium).toBe(1);
      expect(summary.low).toBe(1);
    });
  });

  describe('spider configuration', () => {
    it('should apply spider options correctly', async () => {
      const params = {
        target_url: 'https://example.com',
        spider_options: {
          max_depth: 3,
          max_children: 20,
          exclude_patterns: ['.*\\.pdf', '.*\\.zip']
        }
      };

      // Mock target validation
      mockAxios.get.mockResolvedValueOnce({
        status: 200,
        data: 'OK'
      });

      const mockZapResult = {
        alerts: [],
        spider: { urlsFound: 15, urlsProcessed: 15 }
      };

      const mockZapConnector = {
        executeBaselineScan: jest.fn().mockResolvedValue(mockZapResult)
      };

      (dastTool as any).zapConnector = mockZapConnector;

      await dastTool.executeScan(params);

      expect(mockZapConnector.executeBaselineScan).toHaveBeenCalledWith(
        expect.objectContaining({
          spiderOptions: {
            max_depth: 3,
            max_children: 20,
            exclude_patterns: ['.*\\.pdf', '.*\\.zip']
          }
        })
      );
    });
  });

  describe('error handling', () => {
    it('should handle ZAP connector failures', async () => {
      const params = {
        target_url: 'https://example.com'
      };

      // Mock target validation
      mockAxios.get.mockResolvedValueOnce({
        status: 200,
        data: 'OK'
      });

      const mockZapConnector = {
        executeBaselineScan: jest.fn().mockRejectedValue(new Error('ZAP connection failed'))
      };

      (dastTool as any).zapConnector = mockZapConnector;

      const result = await dastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.message).toContain('ZAP connection failed');
    });

    it('should handle timeout errors', async () => {
      const params = {
        target_url: 'https://example.com'
      };

      // Mock timeout error
      mockAxios.get.mockRejectedValueOnce({
        code: 'ETIMEDOUT',
        message: 'Request timeout'
      });

      const result = await dastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
    });

    it('should handle DNS resolution errors', async () => {
      const params = {
        target_url: 'https://invalid-domain.local'
      };

      // Mock DNS error
      mockAxios.get.mockRejectedValueOnce({
        code: 'ENOTFOUND',
        message: 'Domain not found'
      });

      const result = await dastTool.executeScan(params);
      const scanResult = JSON.parse(result.content[0].text);

      expect(scanResult.success).toBe(false);
      expect(scanResult.message).toContain('domain not found');
    });
  });
});