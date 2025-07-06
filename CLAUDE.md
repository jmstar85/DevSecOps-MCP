# DevSecOps MCP Server Development

## 🚨 CRITICAL RULES

### Git Safety (MANDATORY)
```bash
# ALWAYS verify before commits - NEVER commit as Claude
CURRENT_USER=$(git config user.name)
if [[ "$CURRENT_USER" =~ [Cc]laude ]] || [[ -z "$CURRENT_USER" ]]; then
    echo "❌ BLOCKED: Set real developer name"
    echo "git config user.name 'Your Real Name'"
    exit 1
fi
```

### File Creation Control
- **ASK FIRST**: "Should I create [filename] for [purpose]?"
- **WAIT** for explicit "yes" or "create it"
- **ONLY** create security-critical files or when explicitly requested
- **NEVER** create examples, demos, or unnecessary files

## 🎯 Project Goal: DevSecOps MCP Server

Build MCP (Model Context Protocol) server that integrates SAST, DAST, IAST, SCA tools for AI-powered DevSecOps automation.

### MCP Server Architecture
```typescript
// Core MCP server structure
interface DevSecOpsMCP {
  sast: SASTConnector;    // SonarQube, Semgrep, CodeQL
  dast: DASTConnector;    // OWASP ZAP, Burp Suite
  iast: IASTConnector;    // Veracode, Contrast Security
  sca: SCAConnector;      // Snyk, GitHub Security
}
```

### Required MCP Tools
```json
{
  "mcpTools": {
    "security_scan": "Execute SAST/DAST/IAST/SCA scans",
    "vulnerability_report": "Generate security reports",
    "policy_check": "Validate security policies",
    "remediation_suggest": "Suggest vulnerability fixes"
  }
}
```

## 🔧 DevSecOps Core Functions

### 1. SAST Integration
- **Tools**: SonarQube, Semgrep
- **Triggers**: Pre-commit, PR, CI/CD
- **Thresholds**: 0 critical, 0 high, ≤5 medium

### 2. DAST Integration  
- **Tools**: OWASP ZAP
- **Environment**: Staging only
- **Frequency**: Every deployment

### 3. IAST Integration
- **Tools**: Veracode IAST
- **Runtime**: Development/Staging
- **Performance**: <5% overhead

### 4. SCA Integration
- **Tools**: Snyk, GitHub Security
- **Scope**: Dependencies, containers
- **Auto-fix**: Medium and below

## 📁 MCP Server File Structure
```
src/
├── mcp/
│   ├── server.ts           # Main MCP server
│   ├── tools/
│   │   ├── sast-tool.ts    # SAST integration
│   │   ├── dast-tool.ts    # DAST integration  
│   │   ├── iast-tool.ts    # IAST integration
│   │   └── sca-tool.ts     # SCA integration
│   └── connectors/
│       ├── sonarqube.ts
│       ├── zap.ts
│       ├── veracode.ts
│       └── snyk.ts
├── config/
│   ├── security-rules.yml
│   └── tool-configs.json
└── tests/security/
```

## 🛠️ Development Standards

### Secure Coding Rules
- Validate all inputs
- Use parameterized queries
- No hardcoded secrets
- Implement proper authentication
- Apply least privilege principle

### MCP Protocol Requirements
```typescript
// MCP tool definition example
const sastTool: Tool = {
  name: "run_sast_scan",
  description: "Execute SAST security scan",
  inputSchema: {
    type: "object",
    properties: {
      target: { type: "string" },
      rules: { type: "array" }
    }
  }
};
```

### Error Handling
```typescript
// Secure error responses for MCP
try {
  const result = await securityScan(params);
  return { success: true, data: result };
} catch (error) {
  // Never expose sensitive error details
  return { 
    success: false, 
    error: "Security scan failed",
    code: "SCAN_ERROR"
  };
}
```

## 🔒 Security Configuration

### Pre-commit Hooks
```bash
#!/bin/bash
# Essential security checks
git-secrets --scan
semgrep --config=auto --error
npm audit --audit-level high
snyk test --severity-threshold=high
```

### CI/CD Pipeline Gates
```yaml
security_gates:
  - secret_detection
  - sast_analysis  
  - dependency_scan
  - container_security
```

### Environment Variables
```bash
# Tool API keys (use secrets)
SONARQUBE_TOKEN=<secret>
SNYK_TOKEN=<secret>
VERACODE_API_KEY=<secret>
ZAP_API_KEY=<secret>

# MCP server config
MCP_PORT=3000
SECURITY_STRICT_MODE=true
LOG_LEVEL=info
```

## 📊 Quality Gates

### SAST Requirements
- Zero critical/high vulnerabilities
- Code coverage >85%
- No hardcoded secrets
- Input validation on all endpoints

### DAST Requirements  
- OWASP Top 10 compliance
- API security validation
- Authentication testing
- SSL/TLS verification

### SCA Requirements
- No critical dependency vulnerabilities
- License compliance (Apache-2.0, MIT, BSD only)
- SBOM generation
- Auto-update minor vulnerabilities

## 🔄 MCP Server Development Workflow

### Phase 1: Core MCP Framework
```bash
# Setup MCP server foundation
npm install @modelcontextprotocol/sdk
# Create server.ts with basic MCP structure
# Implement health check and basic tools
```

### Phase 2: Security Tool Connectors
```bash
# Implement SAST connector (SonarQube/Semgrep)
# Implement DAST connector (OWASP ZAP)  
# Implement SCA connector (Snyk)
# Add error handling and validation
```

### Phase 3: Advanced Features
```bash
# Add IAST connector (Veracode)
# Implement policy engine
# Add vulnerability correlation
# Create security dashboard integration
```

### Phase 4: Testing & Deployment
```bash
# Security test suite
# Performance benchmarks
# Integration tests with real tools
# Docker containerization
```

## 🎯 MCP Tool Implementations

### SAST Tool Example
```typescript
async function runSASTScan(params: SASTParams): Promise<ScanResult> {
  // Validate inputs
  if (!params.target || !params.rules) {
    throw new Error("Invalid SAST parameters");
  }
  
  // Execute scan via SonarQube API
  const result = await sonarQubeConnector.scan(params);
  
  // Return standardized result
  return {
    tool: "SAST",
    status: result.status,
    vulnerabilities: result.issues.map(formatVulnerability),
    summary: generateSummary(result)
  };
}
```

### Integration Commands
```bash
# Start MCP server
npm run start:mcp

# Test MCP tools
curl -X POST http://localhost:3000/mcp \
  -d '{"method": "tools/call", "params": {"name": "run_sast_scan"}}'

# Deploy as service
docker build -t devsecops-mcp .
docker run -p 3000:3000 devsecops-mcp
```

---

**Project**: DevSecOps MCP Server for AI-powered security automation  
**Stack**: TypeScript, MCP Protocol, Docker  
**Security**: SAST/DAST/IAST/SCA integration  
**Version**: 1.0  
**Updated**: 2025-07-06