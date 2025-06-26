# DevSecOps MCP Server

[![CI/CD Pipeline](https://github.com/jmstar85/DevSecOps-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/jmstar85/DevSecOps-MCP/actions/workflows/ci.yml)
[![Security Scanning](https://github.com/jmstar85/DevSecOps-MCP/actions/workflows/security.yml/badge.svg)](https://github.com/jmstar85/DevSecOps-MCP/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-43853D?logo=node.js&logoColor=white)](https://nodejs.org/)

An enterprise-grade Model Context Protocol (MCP) server providing comprehensive DevSecOps capabilities including **Static Application Security Testing (SAST)**, **Software Composition Analysis (SCA)**, and **Dynamic Application Security Testing (DAST)**.

## 🚀 Features

### 🔍 Advanced SAST (Static Application Security Testing)
- **SonarQube-level analysis** with comprehensive rule sets
- **Multi-language support**: JavaScript, TypeScript, Python, Java, C#, Go, PHP, Ruby
- **Code quality metrics**: Complexity, maintainability, reliability ratings
- **Quality gates** with configurable thresholds
- **Vulnerability detection**: XSS, SQL injection, command injection, hardcoded secrets
- **Code smell detection**: Long methods, complex functions, duplicated code
- **CWE and OWASP mapping** for compliance reporting

### 📦 Software Composition Analysis (SCA)
- **BlackDuck-level dependency scanning** with vulnerability detection
- **Multi-ecosystem support**: npm, PyPI, Maven, NuGet, RubyGems, Go, Cargo
- **License analysis** with risk assessment and compliance checking
- **Transitive dependency analysis** with complete dependency trees
- **Policy enforcement** with configurable violation rules
- **Vulnerability databases**: OSV, NVD, npm audit integration
- **Risk scoring** and business impact assessment

### 🌐 Advanced DAST (Dynamic Application Security Testing)
- **OWASP ZAP-level capabilities** with comprehensive vulnerability detection
- **Multiple scan types**: Passive, Active, API, Ajax Spider
- **Browser automation** with Playwright for modern web apps
- **Security testing**: XSS, SQL injection, CSRF, clickjacking, XXE, SSRF
- **SSL/TLS analysis** with certificate validation
- **HTTP security headers** assessment
- **Authentication testing** with multiple auth methods
- **API security testing** including GraphQL and REST APIs

### 📊 Enterprise Reporting
- **SARIF format** support for CI/CD integration
- **Compliance mapping**: OWASP Top 10, CWE, PCI DSS, GDPR
- **Risk assessment** with business impact analysis
- **Remediation guidance** with specific fix recommendations
- **Quality metrics** and trend analysis

## 🏗️ Architecture

```
DevSecOps MCP Server
├── Advanced SAST Engine
│   ├── Multi-language analyzers
│   ├── Quality metrics calculator
│   ├── Code complexity analyzer
│   └── Vulnerability pattern matcher
├── SCA Engine
│   ├── Dependency resolver
│   ├── Vulnerability scanner
│   ├── License analyzer
│   └── Policy engine
├── Advanced DAST Engine
│   ├── Web crawler/spider
│   ├── Vulnerability scanner
│   ├── Browser automation
│   └── API security tester
└── Reporting Engine
    ├── SARIF generator
    ├── Compliance mapper
    └── Risk assessor
```

## 🚦 Quick Start

### Prerequisites

- **Node.js** 18.0.0 or higher
- **npm** or **yarn** package manager
- **Git** for version control

### Installation

```bash
# Clone the repository
git clone https://github.com/username/devsecops-mcp-server.git
cd devsecops-mcp-server

# Install dependencies
npm install

# Build the project
npm run build

# Start the server
npm start
```

### Docker Deployment

```bash
# Build the Docker image
docker build -t devsecops-mcp-server .

# Run with Docker Compose
docker-compose up -d
```

## 📖 Usage

### MCP Tools Available

#### 1. Advanced SAST Scan

Perform enterprise-grade static application security testing:

```json
{
  "tool": "advanced_sast_scan",
  "parameters": {
    "path": "/path/to/source/code",
    "language": "typescript",
    "include_metrics": true,
    "quality_gate": true,
    "exclude_patterns": ["**/node_modules/**", "**/dist/**"]
  }
}
```

**Response includes:**
- Detailed vulnerability findings with CWE/OWASP mapping
- Code quality metrics (complexity, maintainability)
- Quality gate evaluation results
- Remediation suggestions

#### 2. Software Composition Analysis

Analyze dependencies for vulnerabilities and license compliance:

```json
{
  "tool": "sca_analysis",
  "parameters": {
    "path": "/path/to/project",
    "ecosystem": "npm",
    "include_transitive": true,
    "check_licenses": true,
    "check_vulnerabilities": true,
    "policy_file": "/path/to/policy.json"
  }
}
```

**Response includes:**
- Complete dependency inventory
- Vulnerability assessment with CVSS scores
- License compliance analysis
- Policy violation reports
- Risk assessment and recommendations

#### 3. Advanced DAST Scan

Perform dynamic security testing on running applications:

```json
{
  "tool": "advanced_dast_scan",
  "parameters": {
    "target_url": "https://example.com",
    "scan_type": "full",
    "max_depth": 5,
    "max_duration": 30,
    "authentication": {
      "type": "form",
      "login_url": "https://example.com/login",
      "username_field": "email",
      "password_field": "password",
      "credentials": {
        "username": "test@example.com",
        "password": "password"
      }
    },
    "scan_policy": {
      "xss_tests": true,
      "sql_injection_tests": true,
      "command_injection_tests": true,
      "path_traversal_tests": true
    }
  }
}
```

**Response includes:**
- Comprehensive vulnerability findings
- Security header analysis
- SSL/TLS configuration assessment
- Spider results with discovered URLs
- Risk-prioritized recommendations

#### 4. Vulnerability Report Generation

Generate enterprise-grade security reports:

```json
{
  "tool": "vulnerability_report",
  "parameters": {
    "scan_results": [...],
    "format": "sarif",
    "include_remediation": true,
    "risk_assessment": true
  }
}
```

**Supported formats:**
- **JSON**: Machine-readable detailed results
- **SARIF**: Industry-standard format for CI/CD integration
- **HTML**: Human-readable dashboard
- **CSV**: Spreadsheet-compatible format

## ⚙️ Configuration

### Environment Variables

```bash
# Server configuration
NODE_ENV=production
LOG_LEVEL=info

# Database configuration (optional)
DATABASE_URL=postgresql://user:pass@localhost:5432/devsecops
REDIS_URL=redis://localhost:6379

# API keys for enhanced scanning
SNYK_TOKEN=your_snyk_token
NVD_API_KEY=your_nvd_api_key
```

### Policy Configuration

Create a `policy.json` file for SCA enforcement:

```json
{
  "blocked_licenses": ["GPL-3.0", "AGPL-3.0"],
  "warning_licenses": ["GPL-2.0", "LGPL-2.1"],
  "max_vulnerability_score": 7.0,
  "max_age_days": 730,
  "require_license": true,
  "allowed_ecosystems": ["npm", "pypi", "maven"]
}
```

## 🔧 Development

### Project Structure

```
devsecops-mcp-server/
├── src/
│   ├── index.ts                 # Main MCP server
│   ├── tools/
│   │   ├── advanced-sast.ts     # SAST implementation
│   │   ├── sca.ts              # SCA implementation
│   │   └── advanced-dast.ts     # DAST implementation
│   └── utils/
├── .github/
│   └── workflows/              # CI/CD pipelines
├── config/                     # Configuration files
├── docs/                       # Documentation
├── tests/                      # Test suites
├── docker-compose.yml          # Docker deployment
├── Dockerfile                  # Container definition
└── package.json               # Dependencies
```

### Development Scripts

```bash
# Development with hot reload
npm run dev

# Run tests
npm test

# Lint code
npm run lint

# Format code
npm run format

# Type checking
npx tsc --noEmit

# Build for production
npm run build
```

### Testing

```bash
# Run all tests
npm test

# Run specific test suites
npm run test:sast
npm run test:sca
npm run test:dast

# Run with coverage
npm run test:coverage
```

## 🔒 Security Features

### Built-in Security

- **Input validation** and sanitization
- **Output encoding** to prevent XSS
- **SQL injection prevention** through parameterized queries
- **Path traversal protection**
- **Rate limiting** and DoS protection
- **Secure headers** configuration
- **Container security** with non-root user

### Security Scanning

The project includes comprehensive security scanning:

- **SAST**: ESLint with security rules
- **SCA**: npm audit and Snyk integration
- **Secret scanning**: TruffleHog integration
- **Container scanning**: Trivy vulnerability scanner
- **Dependency scanning**: GitHub Dependabot

## 📊 Performance

### Benchmarks

| Operation | Time | Throughput |
|-----------|------|------------|
| SAST scan (1000 LOC) | ~30s | 33 LOC/s |
| SCA analysis (100 deps) | ~45s | 2.2 deps/s |
| DAST scan (50 URLs) | ~5min | 10 URLs/min |

### Optimization

- **Parallel processing** for multiple files
- **Caching** of dependency information
- **Incremental scanning** for CI/CD
- **Resource pooling** for browser automation

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your changes
4. **Add** tests for new functionality
5. **Run** the test suite
6. **Submit** a pull request

### Code Standards

- **TypeScript** with strict type checking
- **ESLint** for code quality
- **Prettier** for code formatting
- **Jest** for testing
- **Conventional Commits** for commit messages

## 📝 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

## 🙏 Acknowledgments

- **OWASP** for security standards and guidelines
- **SonarQube** for code quality metrics inspiration
- **BlackDuck** for SCA methodology
- **OWASP ZAP** for DAST testing approaches
- **Node.js** and **TypeScript** communities

## 📞 Support

- **Documentation**: [Wiki](https://github.com/username/devsecops-mcp-server/wiki)
- **Issues**: [GitHub Issues](https://github.com/username/devsecops-mcp-server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/username/devsecops-mcp-server/discussions)
- **Security**: [Security Policy](SECURITY.md)

## 🗺️ Roadmap

### Version 2.1.0
- [ ] Machine learning-based vulnerability detection
- [ ] GraphQL API security testing
- [ ] Infrastructure as Code (IaC) scanning
- [ ] Kubernetes security analysis

### Version 2.2.0
- [ ] WebAssembly (WASM) security analysis
- [ ] Mobile application security testing
- [ ] Cloud security posture management
- [ ] Threat modeling integration

### Version 3.0.0
- [ ] AI-powered remediation suggestions
- [ ] Real-time security monitoring
- [ ] Compliance automation (SOC2, ISO 27001)
- [ ] Security training recommendations

---

**Built with ❤️ for the DevSecOps community**
