# Integration Test Documentation

## Overview

This document provides comprehensive documentation for the integration test implementation in the Go Backend project. The integration tests provide end-to-end validation of the authentication workflow using real HTTP servers, database connections, and production-like conditions.

## Architecture & Design

### Core Philosophy

The integration test suite is built on these principles:

- **Real Environment Testing**: Uses actual HTTP servers and database connections
- **Production Parity**: Tests mirror production conditions as closely as possible
- **Isolation**: Each test is self-contained with proper cleanup
- **Docker-First**: Primary testing approach uses Docker for consistency
- **CI/CD Ready**: Seamlessly integrates with GitHub Actions workflows

### Test Structure

```
test/
├── integration_test.go     # Main test implementation
├── run-docker.sh          # Docker-based test runner
├── setup-docker.sh        # Docker environment setup
└── README.md             # Quick reference guide
```

## Test Implementation Details

### TestServer Architecture

The `TestServer` struct provides a complete testing environment:

```go
type TestServer struct {
    *httptest.Server        // Real HTTP server instance
    Client      *http.Client     // HTTP client with cookie jar
    AuthService *auth.Service    // Authentication service
    Pool        *pgxpool.Pool    // Database connection pool
}
```

**Key Features:**
- Real HTTP server using `httptest.Server`
- Cookie jar for automatic session management
- Direct access to authentication service for verification
- Connection pooling for database operations
- Automatic cleanup and resource management

### Helper Functions

#### Server Management
- `setupTestServer(t *testing.T) *TestServer` - Initializes complete test environment
- `(ts *TestServer) cleanup(t *testing.T)` - Proper resource cleanup

#### HTTP Operations
- `postForm(t *testing.T, path string, data url.Values) *http.Response` - Form submissions
- `postFormWithCSRF(t *testing.T, path string, data url.Values, csrfToken string) *http.Response` - CSRF-protected requests
- `postJSON(t *testing.T, path string, data interface{}) *http.Response` - JSON API calls

#### Response Processing
- `extractOTPFromResponse(body string) string` - Parse OTP codes from responses
- `extractCSRFTokenFromResponse(body string) string` - Extract CSRF tokens
- `getResponseBody(t *testing.T, resp *http.Response) string` - Safe response reading

## Test Coverage

### 1. Password-Based Authentication Flow

**Test Function:** `TestAuthenticationWorkflowWithPassword`

**Flow Coverage:**
1. **User Registration**
   - POST /register with email and password
   - Verify successful registration response
   - Confirm user creation in database

2. **User Login**
   - POST /login with credentials
   - Verify session cookie is set
   - Extract and validate CSRF token

3. **Protected Access**
   - POST /dashboard with session cookie and CSRF token
   - Verify authenticated access
   - Confirm session validation

4. **User Logout**
   - POST /logout with proper tokens
   - Verify session invalidation
   - Confirm cookie cleanup

5. **Post-Logout Verification**
   - Attempt protected access without valid session
   - Verify unauthorized response

### 2. OTP-Based Authentication Flow

**Test Function:** `TestAuthenticationWorkflowWithOTP`

**Flow Coverage:**
1. **Initial Registration**
   - POST /register with email only
   - Verify OTP generation and response
   - Extract OTP code from response body

2. **OTP Verification**
   - POST /verify-otp with OTP code
   - Verify session upgrade to authenticated
   - Confirm CSRF token generation

3. **Protected Access After OTP**
   - Access protected endpoints with verified session
   - Validate full authentication state

4. **Returning User Login**
   - POST /login for existing user
   - Verify new OTP generation
   - Complete verification cycle

5. **Session Management**
   - Verify session persistence across requests
   - Test session invalidation on logout

### 3. Error Scenario Testing

**Test Function:** `TestAuthenticationErrorScenarios`

**Coverage Areas:**
- **Input Validation Errors**
  - Invalid email format
  - Password too short
  - Missing required fields

- **Authentication Errors**
  - Wrong password attempts
  - Invalid OTP codes
  - Non-existent user login

- **Authorization Errors**
  - Unauthorized endpoint access
  - Missing session cookies
  - Invalid CSRF tokens
  - Expired sessions

### 4. Concurrency Testing

**Test Function:** `TestConcurrentAuthentication`

**Features:**
- Multiple simultaneous authentication attempts
- Race condition detection
- Session isolation verification
- Database connection stress testing
- Goroutine-based parallel execution

### 5. Session Management

**Test Function:** `TestSessionExpiry`

**Validation:**
- Session timeout behavior
- Automatic session cleanup
- Access denial after expiration
- Database session state consistency

## Docker-Based Testing

### Primary Test Runner

**Script:** `./test/run-docker.sh`

This is the main entry point for running integration tests with Docker-based database setup.

#### Basic Usage

```bash
# Run integration tests with Docker
./test/run-docker.sh

# Run with specific test type
./test/run-docker.sh integration
./test/run-docker.sh integration-coverage
./test/run-docker.sh unit

# Run with OTP enabled
./test/run-docker.sh -o integration
```

#### Advanced Options

```bash
# Setup environment only
./test/run-docker.sh -s

# Cleanup only
./test/run-docker.sh -c

# Keep Docker running after tests
./test/run-docker.sh -k integration

# Run specific test pattern
./test/run-docker.sh -p "TestAuthenticationWorkflow*"

# Verbose output
./test/run-docker.sh -v integration

# Get help
./test/run-docker.sh --help
```

### Environment Setup

**Script:** `./test/setup-docker.sh`

Handles Docker Compose environment management:

```bash
# Setup database environment
./test/setup-docker.sh

# Cleanup environment
./test/setup-docker.sh --cleanup
```

### Docker Configuration

**Required Environment Variables:**
```bash
DB_USER=postgres
DB_PASSWORD=postgres2025
DB_NAME=gobackend
DB_HOST=localhost  # Automatically set for tests
DB_PORT=5432
OTP_ENABLED=false  # or true for OTP tests
ENV=development
```

**Docker Services:**
- PostgreSQL 16 database
- Automatic health checks
- Volume management for data persistence
- Port mapping for localhost access

## Makefile Integration

### Available Targets

```bash
# Run all tests (unit + integration)
make test

# Unit tests only
make test-unit

# Integration tests with Docker
make test-integration

# Verbose integration tests
make test-integration-verbose

# Integration tests with coverage
make test-integration-coverage

# Environment management
make setup-test-env
make cleanup-test-env
```

### Target Implementation

Each Makefile target uses the Docker-based testing approach:

```makefile
test-integration:
	@echo "Running Docker-based integration tests..."
	@./test/run-docker.sh integration

test-integration-coverage:
	@echo "Running Docker-based integration tests with coverage..."
	@./test/run-docker.sh integration-coverage
```

## GitHub Actions Integration

### CI/CD Workflow

The integration tests are fully integrated into the GitHub Actions workflow:

**Workflow Features:**
- PostgreSQL service container
- Matrix testing (password/OTP modes)
- Environment variable configuration
- Artifact upload for coverage reports
- Parallel job execution
- Comprehensive error reporting

**Workflow Configuration:**
```yaml
strategy:
  matrix:
    auth-mode: [password, otp]

services:
  postgres:
    image: postgres:16
    env:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres2025
      POSTGRES_DB: gobackend
```

**Test Execution:**
```yaml
- name: Run integration tests with coverage
  env:
    DB_HOST: localhost
    DB_PORT: 5432
    OTP_ENABLED: ${{ matrix.auth-mode == 'otp' && 'true' || 'false' }}
  run: |
    go test -v -race -coverprofile=integration-coverage.out ./test/...
```

## Local Development Workflow

### Quick Start

```bash
# 1. Setup Docker environment
./test/run-docker.sh -s

# 2. Run tests (in same or different terminal)
make test-integration

# 3. Cleanup when done
./test/run-docker.sh -c
```

### Development Cycle

```bash
# Keep Docker running for faster iterations
./test/run-docker.sh -k integration

# Run specific tests during development
go test ./test/... -v -run TestAuthenticationWorkflowWithPassword

# Test with different configurations
OTP_ENABLED=true go test ./test/... -v

# Cleanup when development session ends
./test/run-docker.sh -c
```

### Debugging Tests

```bash
# Verbose output with Docker logs
./test/run-docker.sh -v integration

# Setup environment and debug manually
./test/run-docker.sh -s
go test ./test/... -v -run TestSpecificTest

# Check Docker service status
docker-compose ps
docker-compose logs db
```

## Test Data Management

### Data Isolation Strategy

**Unique Identifiers:**
- Email addresses use timestamps: `test-password-{timestamp}@example.com`
- Test data includes unique suffixes to prevent conflicts
- Each test creates its own dataset

**Cleanup Approach:**
- Automatic cleanup in test teardown
- Database-level isolation where possible
- Proper resource disposal in defer statements

### Environment-Specific Considerations

**Development:**
- Uses Docker-based PostgreSQL
- Automatic environment setup
- Safe for local development

**CI/CD:**
- Service containers in GitHub Actions
- Isolated test databases per workflow run
- Automatic cleanup after workflow completion

**Production:**
- Never run integration tests against production databases
- Use separate test environments
- Implement proper data lifecycle management

## Performance Characteristics

### Execution Timing

**Typical Performance:**
- Individual test: 2-5 seconds
- Full integration suite: 30-60 seconds
- Docker startup: 10-15 seconds
- Database initialization: 5-10 seconds

### Optimization Strategies

**Docker Optimizations:**
- Reuse containers with `-k` flag during development
- Use Docker layer caching
- Optimize database initialization

**Test Optimizations:**
- Parallel test execution where safe
- Connection pooling
- Efficient cleanup procedures

**CI/CD Optimizations:**
- Matrix strategy for parallel execution
- Artifact caching
- Service container health checks

## Security Considerations

### Test Environment Security

**Database Security:**
- Isolated test databases
- Non-production credentials
- Automatic cleanup procedures
- No persistent sensitive data

**Container Security:**
- Official PostgreSQL images
- Latest security patches
- Minimal exposed ports
- Network isolation

### Authentication Testing Security

**Session Security:**
- Real session token generation and validation
- CSRF token testing
- Cookie security attribute testing
- Session expiration validation

**Data Security:**
- Test data uses non-sensitive information
- Automatic test data cleanup
- No real user credentials
- Sanitized test inputs

## Troubleshooting Guide

### Common Issues

#### Docker Issues

**Problem:** "Docker is not installed or not running"
```bash
# Solutions:
1. Install Docker and Docker Compose
2. Start Docker daemon
3. Verify: docker info
4. Check service status: systemctl status docker
```

**Problem:** "Database failed to start"
```bash
# Diagnosis:
docker-compose logs db
docker-compose ps

# Solutions:
1. Check port 5432 availability: lsof -i :5432
2. Verify .env file exists and is valid
3. Clean volumes: docker-compose down --volumes
4. Restart Docker daemon
```

**Problem:** "Database connection timeout"
```bash
# Solutions:
1. Increase health check timeout
2. Wait longer for database startup
3. Check Docker resources (memory/CPU)
4. Verify network connectivity
```

#### Test Failures

**Problem:** "Session cookie should be set"
```bash
# Diagnosis:
1. Check authentication service initialization
2. Verify database schema exists
3. Confirm environment variables are set
4. Check session generation logic

# Solutions:
1. Run database migrations
2. Verify test database connectivity
3. Check authentication service configuration
```

**Problem:** "OTP code should be present in response"
```bash
# Diagnosis:
1. Confirm OTP_ENABLED=true
2. Check OTP generation logic
3. Verify response body parsing

# Solutions:
1. Set correct environment variable
2. Check OTP service configuration
3. Debug response content
```

**Problem:** "Concurrent test failures"
```bash
# Diagnosis:
1. Check for race conditions
2. Verify database isolation
3. Confirm proper resource cleanup

# Solutions:
1. Add proper synchronization
2. Use unique test data
3. Implement better cleanup
```

### Performance Issues

**Problem:** "Slow test execution"
```bash
# Solutions:
1. Use -short flag: go test -short ./test/...
2. Keep Docker running: ./test/run-docker.sh -k
3. Optimize Docker resources
4. Run specific tests: -run TestPattern
```

**Problem:** "Docker resource exhaustion"
```bash
# Solutions:
1. Clean unused containers: docker system prune
2. Increase Docker memory allocation
3. Monitor resource usage: docker stats
4. Use cleanup flag: ./test/run-docker.sh -c
```

### Development Issues

**Problem:** "Environment variable conflicts"
```bash
# Solutions:
1. Use .env file for consistency
2. Check variable precedence
3. Verify Docker environment passing
4. Clear conflicting exports
```

**Problem:** "Test data conflicts"
```bash
# Solutions:
1. Use unique timestamps in test data
2. Implement proper cleanup
3. Check for leftover test data
4. Use separate test database
```


This integration test implementation provides a robust foundation for ensuring the authentication system works correctly across different environments while maintaining high standards for security, performance, and maintainability.
