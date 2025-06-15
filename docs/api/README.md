# API Documentation

This folder contains comprehensive documentation for developers who want to use the Go Backend API.

## 📚 Files Overview

### [reference.md](./reference.md)
Complete REST API reference documentation including:
- All available endpoints with detailed descriptions
- Request/response formats and examples
- Authentication requirements
- Error handling and status codes
- Multi-tenant usage patterns

### [quick-reference.md](./quick-reference.md)
Fast-track guide for developers who want to get started quickly:
- Setup instructions
- Common API operations with curl examples
- Authentication flows
- Troubleshooting guide
- Development commands

### [postman-collection.json](./postman-collection.json)
Ready-to-import Postman collection featuring:
- Pre-configured requests for all endpoints
- Environment variables for easy testing
- Automatic token extraction scripts
- Test workflows for common scenarios

### [openapi.yaml](./openapi.yaml)
OpenAPI 3.0 specification for:
- Machine-readable API documentation
- Client library code generation
- Integration with API tools (Swagger UI, etc.)
- Schema validation

## 🚀 Getting Started

### 1. Quick Setup
Start with the [Quick Reference](./quick-reference.md) for immediate setup and basic operations.

### 2. Interactive Testing
Import the [Postman Collection](./postman-collection.json) into Postman for hands-on API testing.

### 3. Complete Reference
Use the [API Reference](./reference.md) for detailed endpoint documentation.

### 4. Code Generation
Use the [OpenAPI Specification](./openapi.yaml) with tools like OpenAPI Generator to create client libraries.

## 🔑 Key Concepts

### Multi-Tenant Architecture
Every API request must include an `Origin` header to identify the tenant:
```
Origin: your-tenant-domain.com
```

### Authentication Modes
- **Password Mode**: Traditional email/password authentication
- **OTP Mode**: Email-based one-time password authentication

### Session Management
- HTTP-only cookies for session storage
- CSRF tokens required for protected endpoints
- Configurable session timeouts per tenant

## 📋 Quick API Overview

### Core Endpoints
| Category | Endpoints | Description |
|----------|-----------|-------------|
| Authentication | `/register`, `/login`, `/logout`, `/verify-otp` | User authentication |
| Notes | `/api/notes/*` | CRUD operations for notes |
| Health | `/health`, `/ready`, `/live` | System health checks |
| Admin | `/admin/tenants/*` | Tenant management |

### Required Headers
**All requests:**
```
Origin: your-tenant-domain.com
```

**Protected endpoints:**
```
Origin: your-tenant-domain.com
X-CSRF-Token: <csrf_token>
Cookie: session_token=<session_token>
```

## 🛠️ Tools Integration

### Postman
1. Import [postman-collection.json](./postman-collection.json)
2. Set environment variables:
   - `baseUrl`: `http://localhost:8080`
   - `tenantDomain`: Your tenant domain
3. Start testing with the pre-configured requests

### Swagger UI
Serve the [OpenAPI specification](./openapi.yaml) with Swagger UI:
```bash
# Using swagger-ui-serve
npx swagger-ui-serve openapi.yaml

# Or using Docker
docker run -p 8080:8080 -e SWAGGER_JSON=/app/openapi.yaml -v $(pwd):/app swaggerapi/swagger-ui
```

### Code Generation
Generate client libraries using OpenAPI Generator:
```bash
# JavaScript client
openapi-generator-cli generate -i openapi.yaml -g javascript -o ./clients/js

# Python client
openapi-generator-cli generate -i openapi.yaml -g python -o ./clients/python

# Go client
openapi-generator-cli generate -i openapi.yaml -g go -o ./clients/go
```

## 🔍 Common Use Cases

### Creating a New Tenant
```bash
curl -X POST http://localhost:8080/admin/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Company",
    "domain": "mycompany.com",
    "admin_email": "admin@mycompany.com",
    "is_active": true
  }'
```

### User Authentication
```bash
# Register
curl -X POST http://localhost:8080/register \
  -H "Origin: mycompany.com" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@mycompany.com", "password": "password123"}'

# Login
curl -X POST http://localhost:8080/login \
  -H "Origin: mycompany.com" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@mycompany.com", "password": "password123"}' \
  -c cookies.txt
```

### Managing Notes
```bash
# Create note
curl -X POST http://localhost:8080/api/notes \
  -H "Origin: mycompany.com" \
  -H "Content-Type: application/json" \
  -d '{"author": "John Doe", "text": "My note"}'

# Get all notes
curl -X GET http://localhost:8080/api/notes \
  -H "Origin: mycompany.com"
```

## 🆘 Need Help?

- **Quick answers**: Check the [Quick Reference](./quick-reference.md)
- **Detailed info**: Browse the [API Reference](./reference.md)
- **Interactive testing**: Use the [Postman Collection](./postman-collection.json)
- **Integration issues**: Review error responses in the API Reference

## 🔗 Related Documentation

For deeper understanding of the system:
- [Multi-Tenancy Architecture](../dev/multi_tenancy_architecture.md)
- [Authentication Workflow](../dev/auth_workflow.md)
- [Integration Testing](../dev/integration_test.md)

---

**Ready to integrate?** Start with the [Quick Reference](./quick-reference.md) for immediate setup guidance.