# GitHub Workflows Documentation

This document describes the comprehensive CI/CD pipeline setup for the Go Backend project, including automated testing, security scanning, building, and deployment workflows.

## Overview

The project uses a modern, multi-stage CI/CD pipeline with the following key features:

- 🔒 **Security-First**: Automated security scanning, vulnerability detection, and code quality checks
- 🚀 **Performance**: Parallel job execution, intelligent caching, and matrix strategies
- 📦 **Multi-Platform**: Support for Linux, macOS, and Windows across AMD64 and ARM64 architectures
- 🐳 **Container-Ready**: Docker image building with multi-architecture support
- 🔄 **Automated Dependencies**: Dependabot integration for keeping dependencies up-to-date

## Workflows

### 1. CI/CD Pipeline (`integration-tests.yml`)

**Triggers:** Push to `main`/`develop` branches, Pull Requests
**Purpose:** Comprehensive testing, security scanning, and quality assurance

#### Jobs Overview

| Job | Purpose | Dependencies |
|-----|---------|-------------|
| `security` | CodeQL security analysis | None |
| `vulnerability-scan` | Dependency vulnerability scanning | None |
| `lint` | Code quality and formatting checks | None |
| `unit-tests` | Unit tests across Go versions | None |
| `integration-tests` | End-to-end testing with real database | None |
| `docker-build` | Docker image building and testing | lint, unit-tests |
| `benchmarks` | Performance benchmarks (main branch only) | None |
| `test-summary` | Consolidated test results | All previous jobs |

#### Key Features

**Security & Quality:**
- CodeQL static analysis for security vulnerabilities
- Gosec security scanner with SARIF output
- golangci-lint for code quality
- Go formatting and module consistency checks

**Testing Strategy:**
- Unit tests with race detection across Go 1.23 and 1.24
- Integration tests with real PostgreSQL database
- Matrix testing for both password and OTP authentication modes
- Coverage reporting with Codecov integration
- Performance benchmarking

**Build & Deploy:**
- Docker multi-architecture builds with BuildKit
- Intelligent caching for faster builds
- Artifact upload for test reports and coverage

#### Configuration

**Environment Variables:**
```yaml
DB_USER: postgres
DB_PASSWORD: postgres2025
DB_NAME: gobackend
DB_HOST: localhost
DB_PORT: 5432
OTP_ENABLED: true/false (matrix)
ENV: development
```

**Required Secrets:**
- `CODECOV_TOKEN` (optional, for coverage reporting)

### 2. Release Pipeline (`release.yml`)

**Triggers:** Git tags (`v*`), Manual workflow dispatch
**Purpose:** Automated releases with multi-platform binaries and Docker images

#### Jobs Overview

| Job | Purpose | Artifacts |
|-----|---------|-----------|
| `pre-release-checks` | Security and quality validation | SARIF reports |
| `build-binaries` | Cross-platform binary compilation | Binaries for 5 platforms |
| `build-docker` | Multi-arch Docker image | Container images, SBOM |
| `integration-test` | Test release artifacts | Test results |
| `create-release` | GitHub release creation | Release notes, checksums |
| `deploy-staging` | Staging environment deployment | Deployment logs |
| `security-scan-release` | Container security scanning | Trivy SARIF |
| `notify` | Release notifications | Summary reports |

#### Supported Platforms

**Binaries:**
- Linux (AMD64, ARM64)
- macOS (AMD64, ARM64)  
- Windows (AMD64)

**Docker:**
- Linux (AMD64, ARM64)

#### Features

**Security:**
- Pre-release security scanning
- Vulnerability detection with govulncheck
- Container image scanning with Trivy
- SBOM (Software Bill of Materials) generation

**Release Management:**
- Automated changelog generation
- Semantic versioning support
- Pre-release detection (alpha, beta, rc)
- Checksum generation for all artifacts

**Deployment:**
- Staging environment deployment
- Environment protection rules
- Rollback capabilities

#### Configuration

**Required Secrets:**
- `GITHUB_TOKEN` (automatically provided)
- Staging deployment secrets (environment-specific)

**Optional Notifications:**
- Slack webhooks (`SLACK_WEBHOOK_URL`)
- Discord webhooks
- Microsoft Teams

### 3. Dependency Management (`dependabot.yml`)

**Purpose:** Automated dependency updates with intelligent grouping

#### Update Schedule

| Ecosystem | Day | Time | Frequency |
|-----------|-----|------|-----------|
| Go modules | Monday | 09:00 | Weekly |
| Docker | Tuesday | 09:00 | Weekly |
| GitHub Actions | Wednesday | 09:00 | Weekly |

#### Grouping Strategy

**Go Dependencies:**
- **go-core**: Standard library and core Go tools
- **database**: PostgreSQL and database-related packages
- **testing**: Testing frameworks and utilities
- **security**: Cryptography and security packages

**GitHub Actions:**
- **actions-official**: Official GitHub Actions
- **setup-actions**: Environment setup actions
- **security-actions**: Security and scanning actions
- **build-actions**: Build and artifact actions

## Usage Examples

### Triggering Workflows

**Automatic Triggers:**
```bash
# Triggers CI/CD pipeline
git push origin main

# Triggers release pipeline  
git tag v1.2.3
git push origin v1.2.3
```

**Manual Triggers:**
```bash
# Manual release (GitHub CLI)
gh workflow run release.yml -f tag=v1.2.3
```

### Local Development

**Run tests locally:**
```bash
# Unit tests
make test-unit

# Integration tests
make test-integration

# All tests
make test
```

**Local security scanning:**
```bash
# Install gosec
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Run security scan
gosec ./...
```

### Monitoring Workflows

**GitHub UI:**
- Actions tab for workflow runs
- Security tab for vulnerability reports
- Releases page for published releases

**CLI Monitoring:**
```bash
# List workflow runs
gh run list

# View specific run
gh run view <run-id>

# Download artifacts
gh run download <run-id>
```

## Security Features

### Code Analysis
- **CodeQL**: Semantic code analysis for security vulnerabilities
- **Gosec**: Go-specific security rule scanning
- **Dependency Scanning**: Known vulnerability detection

### Container Security
- **Trivy**: Comprehensive container vulnerability scanning
- **SBOM**: Software Bill of Materials for supply chain security
- **Multi-stage Builds**: Minimal attack surface

### Access Control
- **Permissions**: Least-privilege principle for all jobs
- **Environment Protection**: Manual approval for production deployments
- **Secret Management**: Secure handling of sensitive data

## Performance Optimizations

### Caching Strategy
- **Go Module Cache**: Shared across jobs
- **Docker Layer Cache**: Buildx with GitHub Actions cache
- **Binary Artifacts**: Reused across jobs

### Parallel Execution
- **Matrix Strategies**: Parallel testing across versions/modes
- **Independent Jobs**: Concurrent execution where possible
- **Selective Triggering**: Skip unnecessary jobs

### Resource Management
- **Artifact Retention**: Automated cleanup (7-30 days)
- **Cache Limits**: Optimized cache usage
- **Timeout Controls**: Prevent hanging jobs

## Troubleshooting

### Common Issues

**Test Failures:**
```bash
# Check logs
gh run view <run-id> --log

# Re-run failed jobs
gh run rerun <run-id> --failed
```

**Security Alerts:**
- Check Security tab in GitHub
- Review SARIF uploads in Actions
- Update dependencies via Dependabot PRs

**Release Issues:**
- Verify tag format (`v*`)
- Check pre-release security scans
- Validate binary compilation across platforms

### Debug Mode

**Enable debug logging:**
```yaml
- name: Debug Step
  run: echo "Debug information"
  env:
    ACTIONS_STEP_DEBUG: true
```

**Local debugging:**
```bash
# Act (local Actions runner)
act -j unit-tests

# Docker debugging
docker run -it --rm gobackend:test /bin/sh
```

## Best Practices

### Development Workflow
1. **Feature Branches**: Always work on feature branches
2. **PR Reviews**: Require review for protected branches
3. **Status Checks**: Ensure all checks pass before merge
4. **Semantic Versioning**: Use proper version tags

### Security Guidelines
1. **Secret Management**: Never commit secrets to repository
2. **Dependency Updates**: Review and test Dependabot PRs
3. **Vulnerability Response**: Address security alerts promptly
4. **Image Scanning**: Regular container security reviews

### Performance Guidelines
1. **Cache Usage**: Leverage caching for repeated operations
2. **Matrix Optimization**: Use focused matrix strategies
3. **Artifact Management**: Clean up unused artifacts
4. **Resource Monitoring**: Monitor workflow execution time

## Configuration Reference

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DB_USER` | Database username | postgres | Yes |
| `DB_PASSWORD` | Database password | - | Yes |
| `DB_NAME` | Database name | gobackend | Yes |
| `DB_HOST` | Database host | localhost | Yes |
| `DB_PORT` | Database port | 5432 | Yes |
| `OTP_ENABLED` | Enable OTP authentication | false | No |
| `ENV` | Environment name | development | No |

### Required Secrets

| Secret | Purpose | Scope |
|--------|---------|-------|
| `GITHUB_TOKEN` | GitHub API access | Automatic |
| `CODECOV_TOKEN` | Coverage reporting | Repository |
| Deployment secrets | Environment-specific | Environment |

### Permissions

```yaml
permissions:
  contents: read          # Read repository content
  packages: write         # Push Docker images
  security-events: write  # Upload security results
  actions: read          # Read workflow information
```

## Migration Guide

### From Previous Setup

1. **Update Action Versions**: All actions updated to latest versions
2. **New Security Features**: Additional security scanning and reporting
3. **Enhanced Testing**: Matrix strategies and comprehensive coverage
4. **Release Automation**: Full release pipeline with multi-platform support

### Required Changes

1. **Secrets**: Ensure required secrets are configured
2. **Branch Protection**: Update status check requirements
3. **Environment Setup**: Configure staging environment if needed
4. **Notification Setup**: Configure team notifications

## Support

For issues with the CI/CD pipeline:

1. **Check Workflow Logs**: Review failed job outputs
2. **Security Alerts**: Address vulnerability reports
3. **Performance Issues**: Monitor workflow execution times
4. **Configuration Help**: Review this documentation

**Resources:**
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Go Testing Best Practices](https://golang.org/doc/testing)
- [Docker Security Scanning](https://docs.docker.com/engine/scan/)
- [Dependabot Configuration](https://docs.github.com/en/code-security/dependabot)