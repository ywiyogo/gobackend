# Integration Tests

This directory contains system integration tests for the authentication workflow in the Go backend application.

## Overview

The integration tests verify the complete authentication flow end-to-end by:
- Starting a real HTTP server with the full application stack
- Making actual HTTP requests to test endpoints
- Testing both password-based and OTP-based authentication workflows
- Verifying session management and cookie handling
- Testing error scenarios and edge cases

## Test Coverage

### Authentication Workflows

1. **Password-based Authentication** (`TestAuthenticationWorkflowWithPassword`)
   - User registration with email and password
   - Login with email and password
   - Access to protected endpoints
   - Logout functionality
   - Session invalidation after logout

2. **OTP-based Authentication** (`TestAuthenticationWorkflowWithOTP`)
   - User registration with email (generates OTP)
   - OTP verification with session token
   - Access to protected endpoints after OTP verification
   - Login for existing users (generates new OTP)
   - Complete OTP verification flow

### Error Scenarios

3. **Error Handling** (`TestAuthenticationErrorScenarios`)
   - Invalid email format validation
   - Password length validation
   - Wrong password attempts
   - Invalid OTP codes
   - Unauthorized access attempts
   - Missing session cookies

### Performance & Concurrency

4. **Concurrent Authentication** (`TestConcurrentAuthentication`)
   - Multiple simultaneous login attempts
   - Race condition testing
   - Session management under load

5. **Session Expiry** (`TestSessionExpiry`)
   - Session timeout behavior
   - Access after session expiration

## Prerequisites

### Docker-based Setup (Recommended)

The integration tests use Docker Compose to provide a consistent database environment:

1. **Docker & Docker Compose**: Ensure both are installed and running
2. **Environment File**: Create or verify `.env` file in project root:

```bash
DB_USER=postgres
DB_PASSWORD=postgres2025
DB_NAME=gobackend
DB_HOST=db  # Will be changed to localhost for tests
DB_PORT=5432
OTP_ENABLED=false
ENV=development
```

### Manual Database Setup (Alternative)

If you prefer to use an existing PostgreSQL database, set these environment variables:

```bash
export DB_USER=postgres
export DB_PASSWORD=your_password
export DB_NAME=gobackend
export DB_HOST=localhost
export DB_PORT=5432
```

### Dependencies

Ensure all Go dependencies are installed:

```bash
go mod download
```

## Running the Tests

### Docker-based Testing (Recommended)

#### Quick Start
```bash
# Setup Docker environment and run integration tests
./test/run-docker.sh

# Run specific test types
./test/run-docker.sh integration
./test/run-docker.sh integration-coverage
./test/run-docker.sh unit

# Run with OTP enabled
./test/run-docker.sh -o integration
```

#### Advanced Docker Usage
```bash
# Setup environment only (for manual testing)
./test/run-docker.sh -s

# Run specific test patterns
./test/run-docker.sh -p TestAuthenticationWorkflowWithPassword

# Keep Docker services running after tests
./test/run-docker.sh -k integration

# Cleanup Docker services only
./test/run-docker.sh -c

# Get help
./test/run-docker.sh --help
```

#### Makefile Targets
```bash
# Docker-based integration tests
make test-integration-docker
make test-integration-docker-verbose
make test-integration-docker-coverage
make test-docker-otp

# Setup and cleanup
make setup-test-env
make cleanup-test-env
```

### Manual Testing (Without Docker)

```bash
cd gobackend
go test ./test/... -v
```

### Run Specific Test

```bash
# Run only password workflow test
go test ./test/... -v -run TestAuthenticationWorkflowWithPassword

# Run only OTP workflow test
go test ./test/... -v -run TestAuthenticationWorkflowWithOTP

# Run only error scenarios
go test ./test/... -v -run TestAuthenticationErrorScenarios
```

### Run Tests with Coverage

```bash
go test ./test/... -v -cover
```

### Skip Long-Running Tests

```bash
go test ./test/... -v -short
```

## Test Configuration

### Environment Variables

The tests respect the following environment variables:

- `OTP_ENABLED`: Set to "true" for OTP mode, "false" for password mode
- `ENV`: Set to "production" for secure cookies (tests typically use "development")
- Database connection variables (DB_USER, DB_PASSWORD, etc.)

### Test Data Cleanup

Tests use unique email addresses with timestamps to avoid conflicts:
- `test-password-{timestamp}@example.com`
- `test-otp-{timestamp}@example.com`

**Note**: In production environments, implement proper test data cleanup mechanisms or use a separate test database.

## Test Architecture

### TestServer Structure

The `TestServer` struct provides:
- `httptest.Server`: Real HTTP server for testing
- `http.Client`: HTTP client with cookie jar for session management
- `auth.Service`: Authentication service instance
- `pgxpool.Pool`: Database connection pool

### Helper Functions

- `setupTestServer()`: Initializes test server with full application stack
- `postForm()`: Makes POST requests with form data
- `postJSON()`: Makes POST requests with JSON data
- `extractOTPFromResponse()`: Parses OTP codes from response bodies
- `getResponseBody()`: Safely reads response bodies

### Docker Scripts

- `setup-docker.sh`: Sets up Docker Compose database environment
- `run-docker.sh`: Complete Docker-based test runner with multiple options

## Example Test Flow

### Docker-based Testing
```bash
# 1. Setup Docker environment
./test/run-docker.sh -s

# 2. Run tests (in another terminal)
make test-integration

# 3. Cleanup when done
./test/run-docker.sh -c
```

### Go Test Code
```go
// 1. Setup test server (uses Docker database)
ts := setupTestServer(t)
defer ts.cleanup(t)

// 2. Register user
data := url.Values{
    "email":    {"test@example.com"},
    "password": {"securePassword123"},
}
resp := ts.postForm(t, "/register", data)

// 3. Login user
loginData := url.Values{
    "email":    {"test@example.com"},
    "password": {"securePassword123"},
}
loginResp := ts.postForm(t, "/login", loginData)

// 4. Access protected endpoint
dashboardResp := ts.postForm(t, "/dashboard", url.Values{})
assert.Equal(t, http.StatusOK, dashboardResp.StatusCode)
```

## Common Issues & Troubleshooting

### Docker Issues

1. **"Docker is not installed" or "Docker daemon is not running"**
   - Install Docker and Docker Compose
   - Start Docker service
   - Verify with `docker info`

2. **"Failed to start database service"**
   - Check if port 5432 is already in use
   - Verify `.env` file exists and has correct values
   - Check Docker logs: `docker-compose logs db`

3. **"Database failed to start within timeout"**
   - Increase timeout in setup script
   - Check system resources (RAM, disk space)
   - Try `docker-compose down --volumes` then restart

### Database Connection Issues

1. **"Database credentials not set"**
   - Ensure `.env` file exists in project root
   - Check all DB_* environment variables are set
   - Verify `.env` file format (no spaces around =)

2. **"Unable to create connection pool"**
   - For Docker: ensure container is running with `docker-compose ps`
   - For manual: verify database host and port are correct
   - Check firewall settings and ensure database exists

### Test Failures

1. **"Session cookie should be set"**
   - Check if authentication service is properly initialized
   - Verify database queries are working
   - Ensure database schema exists

2. **"OTP code should be present in response"**
   - Ensure OTP_ENABLED=true for OTP tests
   - Check if OTP generation is working properly
   - Verify test is using correct environment variable

### Performance Issues

1. **Slow test execution**
   - Use `-short` flag to skip long-running tests
   - Check Docker container resources
   - Use `./test/run-docker.sh -k` to keep database running between test runs

## Contributing

When adding new integration tests:

1. Follow the existing naming convention
2. Use unique test data (timestamps, UUIDs)
3. Always clean up test data
4. Add appropriate assertions
5. Handle errors properly
6. Document any special requirements
7. Test both Docker and manual database setups
8. Update Docker scripts if new environment variables are needed

## Security Considerations

- Tests may leave test data in the database
- Docker provides isolated database environment
- Use a separate test database in production environments
- Don't commit sensitive credentials to version control
- Ensure test users have limited privileges
- Docker containers use non-root users when possible

## Docker vs Manual Testing

### Use Docker When:
- Setting up consistent development environment
- Running tests in CI/CD
- Need isolated database state
- Working with team (consistent setup)

### Use Manual Database When:
- Already have PostgreSQL running locally
- Need to debug database interactions
- Working with existing database setup
- Performance testing with specific database configuration