# Quick Reference Guide

## Getting Started

### 1. Start the Application
```bash
# Clone and navigate to project
git clone <repository>
cd gobackend

# Start services
docker compose --env-file .env.dev up -d

# Run migrations
make migrate-up
```

### 2. Create a Tenant
```bash
curl -X POST http://localhost:8080/admin/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "domain": "myapp.local",
    "admin_email": "admin@myapp.local",
    "is_active": true,
    "settings": {
      "otp_enabled": false
    }
  }'
```

### 3. Test Authentication
```bash
# Register
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -H "Origin: myapp.local" \
  -d '{
    "email": "user@myapp.local",
    "password": "password123"
  }'

# Login (save cookies)
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -H "Origin: myapp.local" \
  -d '{
    "email": "user@myapp.local",
    "password": "password123"
  }' \
  -c cookies.txt

# Access protected endpoint
curl -X POST http://localhost:8080/dashboard \
  -H "Origin: myapp.local" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN" \
  -b cookies.txt
```

## API Endpoints Overview

### Authentication
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/register` | Register new user | No |
| POST | `/login` | Login user | No |
| POST | `/verify-otp` | Verify OTP code | No |
| POST | `/logout` | Logout user | Yes |
| POST | `/dashboard` | User dashboard | Yes |

### Notes Management
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/notes` | Get all notes | No |
| POST | `/api/notes` | Create note | No |
| GET | `/api/notes/{id}` | Get note by ID | No |
| PUT | `/api/notes/{id}` | Update note | No |
| DELETE | `/api/notes/{id}` | Delete note | No |

### Health Checks
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Comprehensive health check |
| GET | `/ready` | Readiness probe |
| GET | `/live` | Liveness probe |

### Tenant Management (Admin)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/tenants` | List all tenants |
| POST | `/admin/tenants` | Create tenant |
| GET | `/admin/tenants/{id}` | Get tenant |
| PUT | `/admin/tenants/{id}` | Update tenant |
| DELETE | `/admin/tenants/{id}` | Delete tenant |

## Required Headers

### All Requests
```
Origin: your-tenant-domain.com
```

### Protected Endpoints
```
Origin: your-tenant-domain.com
X-CSRF-Token: <csrf_token>
Cookie: session_token=<session_token>
```

### JSON Requests
```
Content-Type: application/json
```

## Authentication Modes

### Password Mode (OTP Disabled)
1. Register with email + password
2. Login with email + password
3. Access protected resources

### OTP Mode (OTP Enabled)
1. Register with email only → OTP sent
2. Verify OTP → Complete registration
3. Login with email only → OTP sent
4. Verify OTP → Access granted

## Common Request/Response Examples

### Register User
```json
// Request
{
  "email": "user@example.com",
  "password": "password123"
}

// Response
{
  "user": {
    "id": "uuid",
    "email": "user@example.com"
  },
  "session_token": "token",
  "csrf_token": "csrf",
  "expires_at": "2024-01-16T10:30:00Z"
}
```

### Create Note
```json
// Request
{
  "author": "John Doe",
  "text": "My note content"
}

// Response
{
  "id": "note-uuid",
  "author": "John Doe",
  "text": "My note content"
}
```

### Create Tenant
```json
// Request
{
  "name": "My Company",
  "domain": "mycompany.com",
  "admin_email": "admin@mycompany.com",
  "is_active": true,
  "settings": {
    "otp_enabled": true,
    "session_timeout_minutes": 1440
  }
}

// Response
{
  "id": "tenant-uuid",
  "name": "My Company",
  "domain": "mycompany.com",
  "api_key": "generated-key",
  "settings": { ... }
}
```

## Development Commands

```bash
# Build application
make build

# Run locally (without Docker)
make run

# Run tests
make test
make test-unit
make test-integration

# Database operations
make migrate-up
make migrate-down
make migrate-create NAME=add_new_table

# View logs
docker compose logs app
docker compose logs db

# Clean up
docker compose down --rmi local -v
```

## Environment Variables

### Required
```bash
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=database
DB_HOST=localhost
DB_PORT=5432
```

### Optional
```bash
# Application
APP_PORT=8080
ENV=development

# Authentication
OTP_ENABLED=false
SESSION_TIMEOUT_MINUTES=1440
CSRF_ENABLED=true

# Email (for OTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=email@gmail.com
SMTP_PASSWORD=app_password
EMAIL_MODE=development
```

## Troubleshooting

### Common Issues

**Database Connection Failed**
```bash
# Check if database is running
docker compose ps

# Check database logs
docker compose logs db

# Verify environment variables
cat .env.dev
```

**Tenant Not Found**
- Ensure `Origin` header matches tenant domain
- Check if tenant exists: `GET /admin/tenants`
- Verify tenant is active

**Authentication Failed**
- Check CSRF token in response headers
- Verify session cookie is being sent
- Ensure tenant supports chosen auth method (password/OTP)

**CORS Errors**
- Add tenant domain to `allowed_origins` in tenant settings
- Ensure `Origin` header is set correctly

### Debug Mode
```bash
# Enable debug logging
LOG_LEVEL=debug docker compose up

# Check application logs
docker compose logs -f app
```

## Testing with curl

### Save and Reuse Cookies
```bash
# Login and save cookies
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -H "Origin: myapp.local" \
  -d '{"email":"user@test.com","password":"pass"}' \
  -c cookies.txt -v

# Use saved cookies
curl -X POST http://localhost:8080/dashboard \
  -H "Origin: myapp.local" \
  -H "X-CSRF-Token: EXTRACTED_FROM_LOGIN" \
  -b cookies.txt
```

### Extract CSRF Token
```bash
# Extract CSRF token from login response
CSRF_TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -H "Origin: myapp.local" \
  -d '{"email":"user@test.com","password":"pass"}' \
  -c cookies.txt | jq -r '.csrf_token')

# Use extracted token
curl -X POST http://localhost:8080/dashboard \
  -H "Origin: myapp.local" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b cookies.txt
```

## Project Structure Quick Tour

```
gobackend/
├── main.go                 # Application entry point
├── internal/
│   ├── api/               # HTTP routing and middleware
│   ├── auth/              # Authentication logic
│   │   ├── handler.go     # HTTP handlers
│   │   ├── service.go     # Business logic
│   │   ├── repository.go  # Data access
│   │   └── models.go      # Request/response types
│   ├── tenant/            # Multi-tenant management
│   ├── notes/             # Notes feature
│   ├── health/            # Health check endpoints
│   └── db/                # Database migrations & queries
├── docs/                  # Documentation
├── test/                  # Integration tests
└── docker-compose.yml     # Development environment
```

For detailed API documentation, see [reference.md](./reference.md).