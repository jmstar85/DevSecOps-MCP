# Contributing to DevSecOps MCP Server

We love your input! We want to make contributing to DevSecOps MCP Server as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, track issues and feature requests, as well as accept pull requests.

### Pull Requests

Pull requests are the best way to propose changes to the codebase. We actively welcome your pull requests:

1. **Fork the repository** and create your branch from `main`
2. **Add tests** if you've added code that should be tested
3. **Update documentation** if you've changed APIs
4. **Ensure the test suite passes**
5. **Make sure your code lints** with our ESLint configuration
6. **Issue the pull request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/devsecops-mcp-server.git
cd devsecops-mcp-server

# Install dependencies
npm install

# Run tests
npm test

# Start development server
npm run dev
```

### Code Style

We use automated tooling to maintain code quality:

- **ESLint** for code linting
- **Prettier** for code formatting
- **TypeScript** for type safety
- **Jest** for testing

Run these commands before submitting:

```bash
# Format code
npm run format

# Lint code
npm run lint

# Type check
npx tsc --noEmit

# Run tests
npm test
```

### Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Code style changes (formatting, missing semi-colons, etc)
- `refactor`: Code changes that neither fix a bug nor add a feature
- `perf`: Performance improvements
- `test`: Adding missing tests or correcting existing tests
- `chore`: Changes to build process or auxiliary tools

**Examples:**
```
feat(sast): add support for Go language analysis
fix(sca): resolve npm registry timeout issues
docs: update installation instructions
test(dast): add tests for XSS detection
```

## Bug Reports

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/username/devsecops-mcp-server/issues/new).

### Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report security issues to [security@example.com](mailto:security@example.com). We will respond as quickly as possible.

### Bug Report Template

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Feature Requests

We welcome feature requests! Please [open an issue](https://github.com/username/devsecops-mcp-server/issues/new) with:

- **Clear description** of the feature
- **Use case** explaining why this feature would be valuable
- **Proposed implementation** (if you have ideas)
- **Examples** of how the feature would be used

## Architecture Guidelines

### SAST Engine

When contributing to the SAST engine:

- Follow the existing pattern for language analyzers
- Ensure new rules include CWE and OWASP mappings
- Add comprehensive tests for new vulnerability patterns
- Update quality gate thresholds appropriately

### SCA Engine

When contributing to the SCA engine:

- Support new package ecosystems following existing patterns
- Ensure vulnerability database integrations handle rate limits
- Add license information for new supported licenses
- Include policy enforcement for new ecosystems

### DAST Engine

When contributing to the DAST engine:

- Use Playwright for browser automation
- Ensure scans handle authentication properly
- Add new vulnerability tests with appropriate payloads
- Consider false positive rates when adding new checks

## Testing Guidelines

### Test Structure

```typescript
// Example test structure
describe('AdvancedSASTTool', () => {
  describe('performAdvancedScan', () => {
    it('should detect SQL injection vulnerabilities', async () => {
      // Arrange
      const tool = new AdvancedSASTTool();
      const mockCode = `
        const query = "SELECT * FROM users WHERE id = " + userId;
      `;
      
      // Act
      const result = await tool.performAdvancedScan({
        path: '/mock/file.js',
        language: 'javascript'
      });
      
      // Assert
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          vulnerability: 'SQL Injection',
          severity: 'critical'
        })
      );
    });
  });
});
```

### Testing Best Practices

- **Unit tests** for individual functions and classes
- **Integration tests** for tool interactions
- **E2E tests** for complete scanning workflows
- **Mock external services** to avoid dependencies
- **Test error conditions** and edge cases
- **Maintain test coverage** above 80%

## Documentation

### Code Documentation

- Use **TSDoc** comments for functions and classes
- Include **examples** in documentation
- Document **parameters** and **return values**
- Explain **complex algorithms** and **business logic**

```typescript
/**
 * Performs advanced static application security testing
 * @param args - Scan configuration parameters
 * @param args.path - Path to source code directory
 * @param args.language - Programming language (auto-detected if not provided)
 * @param args.include_metrics - Whether to include code quality metrics
 * @returns Promise resolving to scan results with issues, metrics, and quality gate
 * @example
 * ```typescript
 * const tool = new AdvancedSASTTool();
 * const result = await tool.performAdvancedScan({
 *   path: './src',
 *   language: 'typescript',
 *   include_metrics: true
 * });
 * ```
 */
async performAdvancedScan(args: ScanArgs): Promise<ScanResult> {
  // Implementation
}
```

### README Updates

When adding new features:

- Update the **Features** section
- Add **usage examples**
- Update **configuration** documentation
- Add to **roadmap** if appropriate

## Performance Guidelines

### Optimization Principles

- **Parallel processing** where possible
- **Caching** of expensive operations
- **Streaming** for large file processing
- **Resource pooling** for browser instances
- **Incremental analysis** for CI/CD integration

### Performance Testing

- Measure performance impact of changes
- Include benchmarks for new features
- Test with realistic data sizes
- Profile memory usage for large scans

## Release Process

### Version Numbering

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes to API
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] Security scan results clean
- [ ] Performance benchmarks acceptable
- [ ] Changelog updated
- [ ] Version bumped appropriately

## Community

### Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

### Getting Help

- **GitHub Discussions**: For questions and community discussion
- **GitHub Issues**: For bug reports and feature requests
- **Security Email**: For security-related concerns

### Recognition

Contributors will be recognized in:

- **README acknowledgments**
- **Release notes**
- **Contributor hall of fame**

## License

By contributing, you agree that your contributions will be licensed under the same [MIT License](LICENSE) that covers the project.

## Questions?

Don't hesitate to reach out if you have questions about contributing. We're here to help!

---

**Thank you for contributing to DevSecOps MCP Server!** 🚀