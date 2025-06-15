# API Documentation

## Overview

This Go backend provides a RESTful API with multi-tenant support, authentication, and notes management. The API supports both password-based and OTP-based authentication flows.

## Base URL

```
http://localhost:8080
```

## Authentication

The API uses session-based authentication with CSRF protection. All protected endpoints require:
- Valid session cookie
- CSRF token in `X-CSRF-Token` header
- Tenant identification via `Origin` header

## Multi-Tenant Support

All requests must include the tenant's domain in the `Origin` header:

```
Origin: your-tenant-domain.com
```

## Common Headers

```
Content-Type: application/json
Origin: your-tenant-domain.com
X-CSRF-Token: <csrf_token> (for protected endpoints)
```

## Error Responses

All endpoints return errors in the following format:

```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": {
    "field": "Additional context"
  }
}
```

Common HTTP status codes:
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `405` - Method Not Allowed
- `500` - Internal Server Error

## Authentication Endpoints

### Register User

Creates a new user account in the specified tenant.

**Endpoint:** `POST /register`

**Headers:**
```
Content-Type: application/json
Origin: your-tenant-domain.com
```

**Request Body (Password-based auth):**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Request Body (OTP-based auth):**
```json
{
  "email": "user@example.com"
}
```

**Fields:**
- `email` (required): Valid email address
- `password` (required for password-based auth): User's password
- Note: For OTP-based auth, only email is required. OTP will be sent to the provided email address

**Response (Success - 200):**
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  },
  "session_token": "abc123...",
  "csrf_token": "def456...",
  "expires_at": "2024-01-16T10:30:00Z",
  "requires_otp": false,
  "message": "Registration successful"
}
```

**Response (OTP Required - 200):**
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  },
  "requires_otp": true,
  "message": "OTP sent to email. Please verify to complete registration."
}
```

### Login User

Authenticates a user and creates a session.

**Endpoint:** `POST /login`

**Headers:**
```
Content-Type: application/json
Origin: your-tenant-domain.com
```

**Request Body (Password-based auth):**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Request Body (OTP-based auth):**
```json
{
  "email": "user@example.com"
}
```

**Fields:**
- `email` (required): User's email address
- `password` (required for password-based auth): User's password
- Note: For OTP-based auth, only email is required. OTP will be sent to the provided email address

**Response (Success - 200):**
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  },
  "session_token": "abc123...",
  "csrf_token": "def456...",
  "expires_at": "2024-01-16T10:30:00Z",
  "requires_otp": false,
  "message": "Login successful"
}
```

### Verify OTP

Verifies an OTP code sent to the user's email.

**Endpoint:** `POST /verify-otp`

**Headers:**
```
Content-Type: application/json
Origin: your-tenant-domain.com
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "otp": "123456",
  "session_token": "temp_session_token"
}
```

**Fields:**
- `email` (required): User's email address
- `otp` (required): 6-digit OTP code
- `session_token` (optional): Temporary session token from registration/login

**Response (Success - 200):**
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  },
  "session_token": "abc123...",
  "csrf_token": "def456...",
  "expires_at": "2024-01-16T10:30:00Z",
  "requires_otp": false,
  "message": "OTP verified successfully"
}
```

### Logout User

Terminates the user's session.

**Endpoint:** `POST /logout`

**Headers:**
```
Content-Type: application/json
Origin: your-tenant-domain.com
X-CSRF-Token: <csrf_token>
```

**Request Body:**
```json
{
  "all_devices": false
}
```

**Fields:**
- `all_devices` (optional): If true, terminates all sessions for the user

**Response (Success - 200):**
```json
{
  "message": "Logout successful"
}
```

## Protected Endpoints

### Dashboard

Returns user dashboard information (protected endpoint example).

**Endpoint:** `POST /dashboard`

**Headers:**
```
Content-Type: application/json
Origin: your-tenant-domain.com
X-CSRF-Token: <csrf_token>
Cookie: session_token=<session_token>
```

**Response (Success - 200):**
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  },
  "message": "Dashboard data retrieved successfully"
}
```

## Notes Management

### Get All Notes

Retrieves all notes.

**Endpoint:** `GET /api/notes`

**Headers:**
```
Origin: your-tenant-domain.com
```

**Response (Success - 200):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "author": "John Doe",
    "text": "This is a sample note"
  },
  {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "author": "Jane Smith",
    "text": "Another note example"
  }
]
```

### Create Note

Creates a new note.

**Endpoint:** `POST /api/notes`

**Headers:**
```
Content-Type: application/json
Origin: your-tenant-domain.com
```

**Request Body:**
```json
{
  "author": "John Doe",
  "text": "This is a new note"
}
```

**Fields:**
- `author` (required): Author of the note
- `text` (required): Content of the note

**Response (Success - 201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "author": "John Doe",
  "text": "This is a new note"
}
```

### Get Note by ID

Retrieves a specific note by its ID.

**Endpoint:** `GET /api/notes/{id}`

**Headers:**
```
Origin: your-tenant-domain.com
```

**Response (Success - 200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "author": "John Doe",
  "text": "This is a sample note"
}
```

**Response (Not Found - 404):**
```json
{
  "error": "Note not found"
}
```

### Update Note

Updates an existing note.

**Endpoint:** `PUT /api/notes/{id}`

**Headers:**
```
Content-Type: application/json
Origin: your-tenant-domain.com
```

**Request Body:**
```json
{
  "author": "John Doe",
  "text": "Updated note content"
}
```

**Response (Success - 200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "author": "John Doe",
  "text": "Updated note content"
}
```

**Response (Not Found - 404):**
```json
{
  "error": "Note not found"
}
```

### Delete Note

Deletes a specific note.

**Endpoint:** `DELETE /api/notes/{id}`

**Headers:**
```
Origin: your-tenant-domain.com
```

**Response (Success - 200):**
```json
{
  "message": "Note deleted successfully"
}
```

**Response (Not Found - 404):**
```json
{
  "error": "Note not found"
}
```

## Health Check Endpoints

### Health Check

Comprehensive health check including database connectivity.

**Endpoint:** `GET /health`

**Response (Healthy - 200):**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "checks": {
    "database": "healthy",
    "tenants_table": "healthy"
  }
}
```

**Response (Unhealthy - 503):**
```json
{
  "status": "unhealthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "checks": {
    "database": "unhealthy",
    "tenants_table": "skipped"
  },
  "message": "Database connectivity issues detected"
}
```

### Readiness Check

Simple readiness probe for container orchestration.

**Endpoint:** `GET /ready`

**Response (Ready - 200):**
```
OK
```

**Response (Not Ready - 503):**
```
Service not ready: <error_message>
```

### Liveness Check

Simple liveness probe for container orchestration.

**Endpoint:** `GET /live`

**Response (Alive - 200):**
```
OK
```

## Tenant Management (Admin)

### Get All Tenants

Retrieves all tenants (admin endpoint).

**Endpoint:** `GET /admin/tenants`

**Response (Success - 200):**
```json
{
  "tenants": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Example Tenant",
      "domain": "example.com",
      "subdomain": "app",
      "api_key": "tenant_api_key_123",
      "settings": {
        "otp_enabled": true,
        "session_timeout_minutes": 1440,
        "rate_limit_per_minute": 60
      },
      "admin_email": "admin@example.com",
      "is_active": true,
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1
}
```

### Create Tenant

Creates a new tenant.

**Endpoint:** `POST /admin/tenants`

**Headers:**
```
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "New Tenant",
  "domain": "newtenant.com",
  "subdomain": "app",
  "admin_email": "admin@newtenant.com",
  "is_active": true,
  "settings": {
    "otp_enabled": true,
    "session_timeout_minutes": 720,
    "rate_limit_per_minute": 100
  }
}
```

**Fields:**
- `name` (required): Tenant name
- `domain` (required): Tenant domain
- `subdomain` (optional): Subdomain prefix
- `admin_email` (required): Admin email address
- `is_active` (required): Whether tenant is active
- `settings` (optional): Tenant-specific settings

**Response (Success - 201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "New Tenant",
  "domain": "newtenant.com",
  "subdomain": "app",
  "api_key": "generated_api_key_123",
  "settings": {
    "otp_enabled": true,
    "session_timeout_minutes": 720,
    "rate_limit_per_minute": 100
  },
  "admin_email": "admin@newtenant.com",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### Get Tenant by ID

Retrieves a specific tenant.

**Endpoint:** `GET /admin/tenants/{id}`

**Response (Success - 200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Example Tenant",
  "domain": "example.com",
  "subdomain": "app",
  "api_key": "tenant_api_key_123",
  "settings": {
    "otp_enabled": true,
    "session_timeout_minutes": 1440
  },
  "admin_email": "admin@example.com",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### Update Tenant

Updates an existing tenant.

**Endpoint:** `PUT /admin/tenants/{id}`

**Headers:**
```
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "Updated Tenant Name",
  "is_active": false,
  "settings": {
    "otp_enabled": false,
    "session_timeout_minutes": 2880
  }
}
```

**Response (Success - 200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Updated Tenant Name",
  "domain": "example.com",
  "subdomain": "app",
  "api_key": "tenant_api_key_123",
  "settings": {
    "otp_enabled": false,
    "session_timeout_minutes": 2880
  },
  "admin_email": "admin@example.com",
  "is_active": false,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:35:00Z"
}
```

### Delete Tenant

Deletes a tenant.

**Endpoint:** `DELETE /admin/tenants/{id}`

**Response (Success - 200):**
```json
{
  "message": "Tenant deleted successfully"
}
```

## Authentication Flows

### Password-Based Authentication

1. **Register:** `POST /register` with `email` and `password`
2. **Login:** `POST /login` with `email` and `password`
3. **Access Protected Resources:** Include session cookie and CSRF token

### OTP-Based Authentication

1. **Register:** `POST /register` with `email` only (OTP sent to email)
2. **Verify OTP:** `POST /verify-otp` with email and OTP code
3. **Login:** `POST /login` with `email` only (OTP sent to email)
4. **Verify OTP:** `POST /verify-otp` with email and OTP code
5. **Access Protected Resources:** Include session cookie and CSRF token

**Note:** Password and OTP fields should never be used together. The authentication method is determined by the tenant's `otp_enabled` setting.

## Environment Configuration

### Tenant Settings

Each tenant can have the following settings:

```json
{
  "otp_enabled": true,
  "session_timeout_minutes": 1440,
  "allowed_origins": ["https://example.com"],
  "rate_limit_per_minute": 60,
  "require_email_verification": false,
  "custom_branding": {
    "logo_url": "https://example.com/logo.png",
    "primary_color": "#007bff"
  }
}
```

### Default Settings

- `otp_enabled`: false
- `session_timeout_minutes`: 1440 (24 hours)
- `rate_limit_per_minute`: 60
- `require_email_verification`: false

## Rate Limiting

The API implements rate limiting per tenant:
- Default: 60 requests per minute per IP
- Configurable per tenant via settings
- Returns `429 Too Many Requests` when exceeded

## CORS Configuration

- Configured per tenant via `allowed_origins` setting
- Requests must include proper `Origin` header
- Preflight requests are handled automatically

## Session Management

- Session cookies are httpOnly and secure (in production)
- Sessions expire based on tenant settings
- CSRF tokens are required for state-changing operations
- Sessions can be terminated individually or globally

## Error Handling

The API provides detailed error responses with appropriate HTTP status codes and structured error messages to help with debugging and user experience.

For additional documentation, see:
- [Authentication Workflow](../dev/auth_workflow.md)
- [Multi-Tenancy Architecture](../dev/multi_tenancy_architecture.md)
- [Integration Testing](../dev/integration_test.md)