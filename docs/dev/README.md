# Development Documentation

This folder contains technical documentation for developers working on or contributing to the Go Backend project.

## 📚 Files Overview

### [auth_workflow.md](./auth_workflow.md)
Detailed documentation of the authentication system including:
- Authentication flow diagrams
- Password-based vs OTP-based authentication
- Session management implementation
- Security considerations and best practices

### [multi_tenancy_architecture.md](./multi_tenancy_architecture.md)
Comprehensive guide to the multi-tenant architecture:
- Tenant isolation strategies
- Domain-based routing implementation
- Database schema design for multi-tenancy
- Middleware and request handling

### [integration_test.md](./integration_test.md)
Testing guide and best practices:
- Integration test setup and configuration
- Docker-based testing environment
- Test scenarios and coverage
- CI/CD integration patterns

### [repository_pattern.md](./repository_pattern.md)
Code architecture and design patterns:
- Repository pattern implementation
- Service layer architecture
- Dependency injection patterns
- Code organization principles

## 🏗️ Architecture Overview

### System Components
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HTTP Router   │────│  Middleware     │────│   Handlers      │
│                 │    │  - Tenant       │    │  - Auth         │
│                 │    │  - CORS         │    │  - Notes        │
│                 │    │  - Auth         │    │  - Admin        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                       ┌─────────────────┐    ┌─────────────────┐
                       │   Services      │────│  Repositories   │
                       │  - Auth         │    │  - User         │
                       │  - Tenant       │    │  - Session      │
                       │  - Notes        │    │  - Tenant       │
                       └─────────────────┘    └─────────────────┘
                                                        │
                                              ┌─────────────────┐
                                              │   Database      │
                                              │  - PostgreSQL   │
                                              │  - Migrations   │
                                              └─────────────────┘
```

### Key Design Principles
- **Repository Pattern**: Clean separation between business logic and data access
- **Multi-Tenant Isolation**: Complete tenant data separation
- **Session-Based Auth**: Secure session management with CSRF protection
- **Middleware Chain**: Composable request processing pipeline

## 🛠️ Development Setup

### Prerequisites
- Go 1.19+
- Docker & Docker Compose
- PostgreSQL
- golang-migrate

### Local Development
```bash
# Clone repository
git clone <repository-url>
cd gobackend

# Start development environment
docker compose --env-file .env.dev up -d

# Run database migrations
make migrate-up

# Start development server (with hot reload)
make dev
```

### Project Structure
```
gobackend/
├── main.go                    # Application entry point
├── internal/
│   ├── api/                  # HTTP routing and middleware
│   │   ├── router.go         # Route definitions
│   │   └── middleware.go     # Custom middleware
│   ├── auth/                 # Authentication module
│   │   ├── handler.go        # HTTP handlers
│   │   ├── service.go        # Business logic
│   │   ├── repository.go     # Data access
│   │   └── models.go         # Domain models
│   ├── tenant/               # Multi-tenant management
│   ├── notes/                # Notes feature module
│   ├── health/               # Health check endpoints
│   └── db/                   # Database layer
│       ├── migrations/       # SQL migrations
│       └── sqlc/            # Generated queries
├── test/                     # Integration tests
├── docs/                     # Documentation
└── deployment/               # Deployment configs
```

## 🔍 Code Patterns

### Repository Pattern
```go
// Repository interface
type UserRepository interface {
    Create(ctx context.Context, user *User) error
    GetByEmail(ctx context.Context, email string) (*User, error)
    Update(ctx context.Context, user *User) error
}

// Service layer
type AuthService struct {
    repo UserRepository
    mailer MailerService
}

// Handler layer
type AuthHandler struct {
    service *AuthService
}
```

### Multi-Tenant Context
```go
// Middleware extracts tenant from Origin header
func TenantMiddleware(service *TenantService) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            tenant := service.GetTenantByDomain(origin)
            ctx := context.WithValue(r.Context(), "tenant", tenant)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### Error Handling
```go
// Consistent error responses
type ErrorResponse struct {
    Error   string            `json:"error"`
    Code    string            `json:"code,omitempty"`
    Details map[string]string `json:"details,omitempty"`
}

func writeError(w http.ResponseWriter, message string, code int) {
    w.WriteHeader(code)
    json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}
```

## 🧪 Testing Strategy

### Test Categories
- **Unit Tests**: Individual function/method testing
- **Integration Tests**: API endpoint testing with database
- **End-to-End Tests**: Complete workflow testing

### Testing Tools
- Go's built-in testing framework
- Docker for test environment isolation
- testify for assertions and mocking
- Custom test utilities for database setup

### Running Tests
```bash
# Unit tests
make test-unit

# Integration tests
make test-integration

# All tests with coverage
make test-coverage
```

## 🚀 Deployment Considerations

### Environment Configuration
- Database connection settings
- SMTP configuration for email
- Session and security settings
- Multi-tenant configuration

### Production Checklist
- [ ] Database migrations applied
- [ ] Environment variables configured
- [ ] SSL/TLS certificates in place
- [ ] Monitoring and logging configured
- [ ] Health check endpoints accessible
- [ ] Backup strategy implemented

## 🔧 Development Workflow

### Making Changes
1. **Feature Development**:
   - Create feature branch
   - Implement following repository pattern
   - Add unit tests
   - Update integration tests

2. **API Changes**:
   - Update handlers and models
   - Modify OpenAPI specification
   - Update API documentation
   - Add Postman collection examples

3. **Database Changes**:
   - Create migration files
   - Update SQLC queries
   - Test migration rollback
   - Update repository methods

### Code Quality
- Go formatting with `gofmt`
- Linting with `golangci-lint`
- Security scanning with `gosec`
- Dependency checking with `go mod tidy`

## 📖 Understanding the Codebase

### Start Here
1. **Architecture**: Read [multi_tenancy_architecture.md](./multi_tenancy_architecture.md)
2. **Authentication**: Study [auth_workflow.md](./auth_workflow.md)
3. **Code Patterns**: Review [repository_pattern.md](./repository_pattern.md)
4. **Testing**: Follow [integration_test.md](./integration_test.md)

### Key Files to Examine
- `main.go`: Application bootstrap and wiring
- `internal/api/router.go`: Route definitions and middleware
- `internal/auth/`: Complete authentication implementation
- `internal/tenant/`: Multi-tenant middleware and services

## 🤝 Contributing Guidelines

### Code Style
- Follow Go conventions and idioms
- Use meaningful variable and function names
- Add comments for complex business logic
- Keep functions focused and testable

### Documentation
- Update relevant documentation for changes
- Add inline code comments for complex logic
- Update API documentation for endpoint changes
- Include examples in documentation

### Testing Requirements
- Unit tests for business logic
- Integration tests for API endpoints
- Maintain test coverage above 80%
- Test both happy path and error scenarios

## 🔗 External Resources

### Go Best Practices
- [Effective Go](https://golang.org/doc/effective_go.html)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Standard Go Project Layout](https://github.com/golang-standards/project-layout)

### Database Patterns
- [Repository Pattern in Go](https://threedots.tech/post/repository-pattern-in-go/)
- [SQLC Documentation](https://sqlc.dev/)
- [Database Migration Best Practices](https://github.com/golang-migrate/migrate)

---

**Ready to contribute?** Start by understanding the [Multi-Tenancy Architecture](./multi_tenancy_architecture.md) and then dive into the specific component you want to work on.