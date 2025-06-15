# Documentation

Welcome to the Go Backend API documentation. This directory contains comprehensive documentation organized for both API users and developers working on the project.

## 📁 Documentation Structure

### 📚 API Documentation (`/api`)
Documentation for developers who want to use the API:

- **[API Reference](./api/reference.md)** - Complete REST API reference with endpoints, request/response formats, and examples
- **[Quick Reference](./api/quick-reference.md)** - Fast-track guide for common operations and API usage
- **[Postman Collection](./api/postman-collection.json)** - Import this collection into Postman for easy API testing
- **[OpenAPI Specification](./api/openapi.yaml)** - OpenAPI 3.0 specification for API documentation and code generation

### 🛠️ Development Documentation (`/dev`)
Documentation for developers contributing to or understanding the codebase:

- **[Authentication Workflow](./dev/auth_workflow.md)** - Detailed authentication flow documentation
- **[Multi-Tenancy Architecture](./dev/multi_tenancy_architecture.md)** - Multi-tenant system design and implementation
- **[Integration Testing](./dev/integration_test.md)** - Integration testing guide and best practices
- **[Repository Pattern](./dev/repository_pattern.md)** - Code architecture and design patterns used in the project

## 🚀 Quick Start Paths

### For API Users
1. **Get Started Fast**: Check the [API Quick Reference](./api/quick-reference.md) for immediate setup and testing
2. **Understand the API**: Read the [API Reference](./api/reference.md) for comprehensive endpoint details
3. **Test Interactively**: Import the [Postman Collection](./api/postman-collection.json) for hands-on testing

### For Developers
1. **Understand Architecture**: Review [Multi-Tenancy Architecture](./dev/multi_tenancy_architecture.md) and [Repository Pattern](./dev/repository_pattern.md)
2. **Learn Authentication**: Study the [Authentication Workflow](./dev/auth_workflow.md)
3. **Set Up Testing**: Follow the [Integration Testing](./dev/integration_test.md) guide

## 📖 Key Concepts

### Multi-Tenant Architecture
This backend supports multiple tenants with complete data isolation. Each tenant is identified by their domain via the `Origin` header in requests.

### Authentication Modes
- **Password Mode**: Traditional email/password authentication
- **OTP Mode**: Email-based one-time password authentication

### Session Management
- HTTP-only cookies for session storage
- CSRF protection for state-changing operations
- Configurable session timeouts per tenant

## 🔧 Development Tools

### API Testing
- **Postman Collection**: Pre-configured requests for all endpoints
- **OpenAPI Spec**: Generate client libraries or use with API tools like Swagger UI
- **curl Examples**: Copy-paste commands from the documentation

### Environment Setup
```bash
# Start development environment
docker compose --env-file .env.dev up -d

# Run database migrations
make migrate-up

# Create a test tenant
curl -X POST http://localhost:8080/admin/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Tenant",
    "domain": "test.local",
    "admin_email": "admin@test.local",
    "is_active": true
  }'
```

## 📋 API Overview

### Core Endpoints
- **Authentication**: `/register`, `/login`, `/logout`, `/verify-otp`
- **Notes Management**: `/api/notes/*`
- **Health Checks**: `/health`, `/ready`, `/live`
- **Tenant Admin**: `/admin/tenants/*`

### Required Headers
All requests must include:
```
Origin: your-tenant-domain.com
```

Protected endpoints also require:
```
X-CSRF-Token: <csrf_token>
Cookie: session_token=<session_token>
```

## 🛠️ Common Use Cases

### 1. Setting Up a New Tenant
```bash
# Create tenant
POST /admin/tenants
{
  "name": "My Company",
  "domain": "mycompany.com",
  "admin_email": "admin@mycompany.com",
  "is_active": true,
  "settings": {
    "otp_enabled": false
  }
}
```

### 2. User Registration & Login
```bash
# Register user
POST /register
Origin: mycompany.com
{
  "email": "user@mycompany.com",
  "password": "securepassword"
}

# Login user
POST /login
Origin: mycompany.com
{
  "email": "user@mycompany.com",
  "password": "securepassword"
}
```

### 3. Managing Notes
```bash
# Create note
POST /api/notes
Origin: mycompany.com
{
  "author": "John Doe",
  "text": "My note content"
}

# Get all notes
GET /api/notes
Origin: mycompany.com
```

## 🔍 Troubleshooting

### Common Issues

**Tenant Not Found**
- Verify the `Origin` header matches the tenant's domain
- Check if the tenant exists and is active

**Authentication Failed**
- Ensure CSRF token is included in protected requests
- Verify session cookies are being sent
- Check if the tenant supports the authentication method (password/OTP)

**CORS Errors**
- Add the requesting domain to the tenant's `allowed_origins` setting
- Ensure the `Origin` header is set correctly

### Debug Information
Enable debug logging:
```bash
LOG_LEVEL=debug docker compose up
```

Check application logs:
```bash
docker compose logs -f app
```

## 📞 Support

For issues or questions:
- **API Users**: Check the [API Reference](./api/reference.md) and [Quick Reference](./api/quick-reference.md)
- **Developers**: Review the architecture docs in the `/dev` folder
- **Testing**: Use the [Postman Collection](./api/postman-collection.json) to isolate issues
- **Integration**: Examine the [Integration Tests](./dev/integration_test.md) for working examples

## 🤝 Contributing

When contributing to the project:

### API Changes
1. Update the [API Reference](./api/reference.md) for any endpoint changes
2. Add examples to the [Postman Collection](./api/postman-collection.json)
3. Update the [OpenAPI Specification](./api/openapi.yaml) to match changes

### Code Changes
1. Follow the patterns described in [Repository Pattern](./dev/repository_pattern.md)
2. Update [Architecture Documentation](./dev/multi_tenancy_architecture.md) for structural changes
3. Add integration tests following the [Integration Testing](./dev/integration_test.md) guide

## 📁 File Organization

```
docs/
├── README.md                           # This file
├── api/                               # API Documentation
│   ├── reference.md                   # Complete API reference
│   ├── quick-reference.md             # Quick start guide
│   ├── postman-collection.json        # Postman collection
│   └── openapi.yaml                   # OpenAPI specification
└── dev/                               # Development Documentation
    ├── auth_workflow.md               # Authentication implementation
    ├── multi_tenancy_architecture.md  # Multi-tenant design
    ├── integration_test.md            # Testing guide
    └── repository_pattern.md          # Code architecture
```

---

**Ready to start?**
- **Using the API**: Start with [API Quick Reference](./api/quick-reference.md)
- **Contributing**: Begin with [Multi-Tenancy Architecture](./dev/multi_tenancy_architecture.md)
- **Testing**: Import the [Postman Collection](./api/postman-collection.json)