# Multi-Tenant Architecture Implementation Roadmap

## Overview

This document provides a comprehensive roadmap for converting the current single-tenant Go backend authentication system to a **Domain-Based Multi-Tenancy architecture with ISOLATED User Data**. This implementation will allow a single deployment to serve multiple applications (e.g., `myapp.com`, `mysecond.app`) while maintaining complete data isolation between tenants.

## 🎯 Goals and Benefits

### Primary Goals
- **Single Deployment**: Serve multiple applications from one VPS deployment
- **Data Isolation**: Complete separation of user data between applications
- **Resource Efficiency**: Shared infrastructure and authentication logic
- **Scalability**: Easy addition of new tenant applications
- **Backward Compatibility**: Minimal disruption to existing functionality

### Expected Benefits
- **Cost Reduction**: Single infrastructure for multiple apps
- **Maintenance Efficiency**: Centralized authentication logic
- **Consistent Security**: Shared security implementations
- **Rapid Deployment**: Quick setup for new applications

## 📊 Current State Analysis

### Existing Architecture
```
Current Multi-Tenant Setup (Implemented):
├── Database: PostgreSQL with tenants, users, sessions tables (tenant-aware)
├── Authentication: Password + OTP based auth (tenant-scoped)
├── API Endpoints: /register, /login, /logout, /verify-otp, /dashboard (tenant-aware)
├── Session Management: Cookie-based with CSRF protection (tenant-isolated)
├── Tenant Management: Domain-based identification with settings
└── Testing: Comprehensive multi-tenant integration tests
```

### Current Database Schema (Implemented)
```sql
-- Multi-tenant tables (implemented)
tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE NOT NULL,
    subdomain VARCHAR(100),
    api_key VARCHAR(255) UNIQUE NOT NULL,
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),  -- Tenant isolation implemented
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    otp_code VARCHAR(10),
    otp_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, email)  -- Email unique per tenant
);

sessions (
    id SERIAL PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id),  -- Tenant isolation implemented
    user_id UUID REFERENCES users(id),
    session_token VARCHAR(255) UNIQUE NOT NULL,
    csrf_token VARCHAR(255) NOT NULL,
    user_agent TEXT,
    ip VARCHAR(45),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

## 🏗️ Target Multi-Tenant Architecture

### High-Level Architecture
```
Multi-Tenant Architecture:
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   myapp.com     │    │  mysecond.app   │    │   thirdapp.io   │
│   (Frontend)    │    │   (Frontend)    │    │   (Frontend)    │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                          ┌──────▼──────┐
                          │   Reverse   │
                          │   Proxy     │
                          │ (Nginx/CF)  │
                          └──────┬──────┘
                                 │
                          ┌──────▼──────┐
                          │ Go Backend  │
                          │ Multi-tenant│
                          │ Auth API    │
                          └──────┬──────┘
                                 │
                          ┌──────▼──────┐
                          │ PostgreSQL  │
                          │ Multi-tenant│
                          │  Database   │
                          └─────────────┘
```

### Data Isolation Strategy
- **Tenant Identification**: Domain-based (via Origin header)
- **Data Separation**: `tenant_id` column in all user-related tables
- **Session Isolation**: Tenant-scoped session validation
- **API Isolation**: Tenant-aware endpoints with CORS restrictions

## 🗺️ Implementation Status

### ✅ Phase 1: Foundation Setup (COMPLETED)
**Goal**: Establish multi-tenant infrastructure

#### ✅ Step 1.1: Tenant Management System (COMPLETED)
**Implemented Files:**
1. `internal/tenant/models.go` - Tenant data structures and strongly-typed settings
2. `internal/tenant/service.go` - Tenant management logic with caching
3. `internal/tenant/repository.go` - Tenant database operations
4. `internal/tenant/admin_handler.go` - Admin API for tenant management
5. `internal/tenant/middleware.go` - Tenant identification middleware

#### ✅ Step 1.2: Database Schema Extension (COMPLETED)
**Migration Applied**: Multi-tenant database schema with tenant isolation

#### ✅ Step 1.3: SQLC Queries (COMPLETED)
**Updated**: `internal/db/queries/auth.sql`
- Added tenant-aware queries for users and sessions
- Maintains backward compatibility
- Generated SQLC code with tenant support

**Key Implementation Details:**
```bash
# SQLC code regenerated with tenant support
sqlc generate
```

### ✅ Phase 2: Core Multi-Tenant Implementation (COMPLETED)

#### ✅ Step 2.1: TenantSettings Model (COMPLETED)
**Implemented**: `internal/tenant/models.go`
```go
type TenantSettings struct {
    OTPEnabled               bool              `json:"otp_enabled"`
    SessionTimeoutMinutes    int               `json:"session_timeout_minutes"`
    AllowedOrigins           []string          `json:"allowed_origins,omitempty"`
    RateLimitPerMinute       int               `json:"rate_limit_per_minute"`
    RequireEmailVerification bool              `json:"require_email_verification"`
    CustomBranding           map[string]string `json:"custom_branding,omitempty"`
}

// Strongly-typed request/response models
type CreateTenantRequest struct {
    Name       string           `json:"name" validate:"required"`
    Domain     string           `json:"domain" validate:"required"`
    Subdomain  *string          `json:"subdomain,omitempty"`
    Settings   *TenantSettings  `json:"settings,omitempty"`
    AdminEmail string           `json:"admin_email" validate:"required,email"`
    IsActive   bool             `json:"is_active"`
}
```

#### ✅ Step 2.2: Tenant Service (COMPLETED)
**Implemented**: `internal/tenant/service.go`
- Domain-based tenant resolution with caching
- Tenant settings management with JSON conversion
- CRUD operations for tenant administration
- Database connectivity checks

#### ✅ Step 2.3: Tenant Middleware (COMPLETED)
**Implemented**: `internal/tenant/middleware.go`
- Origin header-based tenant identification
- Tenant context injection into requests
- CORS handling per tenant


### ✅ Phase 3: Authentication Service Updates (COMPLETED)

#### ✅ Step 3.1: Authentication Repository (COMPLETED)
**Updated**: `internal/auth/repository.go`
- All queries now tenant-aware using SQLC generated methods
- Tenant-scoped user lookups and session management
- Data isolation enforced at database level

#### ✅ Step 3.2: Authentication Service (COMPLETED)
**Updated**: `internal/auth/service.go`
- Tenant context integration in all authentication flows
- Tenant-specific settings respected (OTP enabled/disabled)
- Session management with tenant isolation


### ✅ Phase 4: Handler and API Updates (COMPLETED)

#### ✅ Step 4.1: Authentication Handlers (COMPLETED)
**Updated**: `internal/auth/handlers.go`
- All endpoints now tenant-aware via middleware
- Origin header validation for CORS
- Tenant-specific authentication flows

#### ✅ Step 4.2: Main Application (COMPLETED)
**Updated**: `main.go`
- Tenant middleware integration
- Multi-tenant routing and service initialization


### ✅ Phase 5: Integration and Testing Updates (COMPLETED)

#### ✅ Step 5.1: Integration Tests (COMPLETED)
**Implemented**: 
- `test/integration_otp_multi_tenants_test.go` - OTP-based multi-tenant auth tests
- `test/integration_paswd_multi_tenants_test.go` - Password-based multi-tenant auth tests
- `test/shared_test.go` - Updated with tenant-aware test helpers
- Complete test coverage for tenant isolation, cross-tenant security, and data separation

#### ✅ Step 5.2: Environment Configuration (COMPLETED)
- Multi-tenant configuration support
- Backward compatibility maintained

### ⚠️ Phase 6: Migration Strategy (PENDING)

#### 🔄 Step 6.1: Data Migration Script (TODO)
**Need to Implement**: Migration script for existing single-tenant data
- Create default tenant for existing users
- Migrate existing users to default tenant
- Preserve existing session data

#### 🔄 Step 6.2: Migration Command (TODO)
**Need to Create**: `cmd/migrate/main.go`
- Command-line tool for safe data migration
- Backup and rollback capabilities

### Phase 7: Deployment and Monitoring

#### Step 7.2: Docker Configuration Update
**Update**: `docker-compose.yml`

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DB_HOST=db
      - DB_USER=postgres
      - DB_PASSWORD=postgres2025
      - DB_NAME=gobackend_multitenant
      - ENABLE_MULTI_TENANT=true
      - ENV=production
    depends_on:
      db:
        condition: service_healthy
    networks:
      - backend

  db:
    image: postgres:16
    environment:
      POSTGRES_DB: gobackend_multitenant
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres2025
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend

  caddy:
    image: caddy:2-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - app
    networks:
      - backend

volumes:
  postgres_data:
  caddy_data:
  caddy_config:

networks:
  backend:
    driver: bridge
```

#### Step 7.3: Caddy Configuration
**Create**: `Caddyfile`

## 🧪 Testing Strategy (IMPLEMENTED)

### ✅ Automated Testing Coverage
**Comprehensive test suites implemented:**

1. **Multi-Tenant OTP Authentication** (`integration_otp_multi_tenants_test.go`):
   - Tenant settings validation (OTP enabled/disabled)
   - Cross-tenant OTP isolation
   - Session security across tenants
   - Complete OTP workflow testing
   - Error scenario testing

2. **Multi-Tenant Password Authentication** (`integration_paswd_multi_tenants_test.go`):
   - Password-based authentication flows
   - Tenant data isolation
   - Cross-tenant session security
   - Domain resolution testing
   - Concurrent access testing

3. **Test Infrastructure** (`shared_test.go`):
   - Tenant-aware test server setup
   - Helper functions for multi-tenant testing
   - Automatic tenant creation for tests

### Manual Testing with cURL

#### Test Multi-Tenant Registration
```bash
# Register user on localhost (default tenant)
curl -X POST http://localhost:8080/register \
     -H "Origin: http://localhost:3000" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=user@localhost.com" \
     -d "password=password123" \
     -c "cookies_localhost.txt"

# Register user on myapp.com tenant (requires tenant to exist)
curl -X POST http://localhost:8080/register \
     -H "Origin: https://myapp.com" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=user@myapp.com" \
     -d "password=password123" \
     -c "cookies_myapp.txt"

# Register user on mysecond.app tenant (requires tenant to exist)
curl -X POST http://localhost:8080/register \
     -H "Origin: https://mysecond.app" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=user@mysecond.com" \
     -d "password=password123" \
     -c "cookies_mysecond.txt"
```

#### Test Admin API for Tenant Management
```bash
# Create a new tenant
curl -X POST http://localhost:8080/admin/tenants \
     -H "Content-Type: application/json" \
     -d '{
       "name": "My App",
       "domain": "myapp.com",
       "admin_email": "admin@myapp.com",
       "settings": {
         "otp_enabled": true,
         "session_timeout_minutes": 1440,
         "rate_limit_per_minute": 100
       },
       "is_active": true
     }'

# List all tenants
curl -X GET http://localhost:8080/admin/tenants

# Get specific tenant
curl -X GET http://localhost:8080/admin/tenants/{tenant-id}

# Update tenant settings
curl -X PUT http://localhost:8080/admin/tenants/{tenant-id} \
     -H "Content-Type: application/json" \
     -d '{
       "settings": {
         "otp_enabled": false,
         "session_timeout_minutes": 720
       }
     }'

# Delete tenant
curl -X DELETE http://localhost:8080/admin/tenants/{tenant-id}
```

#### Test Multi-Tenant Login
```bash
# Login to localhost tenant
curl -X POST http://localhost:8080/login \
     -H "Origin: http://localhost:3000" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=user@localhost.com" \
     -d "password=password123" \
     -c "cookies_localhost.txt"

# Login to myapp.com tenant
curl -X POST http://localhost:8080/login \
     -H "Origin: https://myapp.com" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=user@myapp.com" \
     -d "password=password123" \
     -c "cookies_myapp.txt"

# Login to mysecond.app tenant
curl -X POST http://localhost:8080/login \
     -H "Origin: https://mysecond.app" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=user@mysecond.com" \
     -d "password=password123" \
     -c "cookies_mysecond.txt"
```

#### Test Cross-Tenant Session Isolation
```bash
# Try to access localhost tenant with myapp.com session (should fail)
curl -X POST http://localhost:8080/dashboard \
     -H "Origin: http://localhost:3000" \
     -H "X-CSRF-Token: CSRF_TOKEN_FROM_MYAPP" \
     -b "cookies_myapp.txt"

# Try to access myapp.com tenant with mysecond.app session (should fail)
curl -X POST http://localhost:8080/dashboard \
     -H "Origin: https://myapp.com" \
     -H "X-CSRF-Token: CSRF_TOKEN_FROM_MYSECOND" \
     -b "cookies_mysecond.txt"
```

#### Test Tenant-Specific Logout
```bash
# Logout from localhost tenant
curl -X POST http://localhost:8080/logout \
     -H "Origin: http://localhost:3000" \
     -H "X-CSRF-Token: CSRF_TOKEN_FROM_LOCALHOST" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -b "cookies_localhost.txt" \
     -c "cookies_localhost.txt"

# Verify cookies are cleared
cat cookies_localhost.txt

# Logout from myapp.com tenant
curl -X POST http://localhost:8080/logout \
     -H "Origin: https://myapp.com" \
     -H "X-CSRF-Token: CSRF_TOKEN_FROM_MYAPP" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -b "cookies_myapp.txt" \
     -c "cookies_myapp.txt"

# Verify cookies are cleared
cat cookies_myapp.txt
```

#### Test Data Isolation
```bash
# Register same email on different tenants (should succeed)
curl -X POST http://localhost:8080/register \
     -H "Origin: https://myapp.com" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=test@example.com" \
     -d "password=password123"

curl -X POST http://localhost:8080/register \
     -H "Origin: https://mysecond.app" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=test@example.com" \
     -d "password=password456"
```

#### Test Invalid Origins (CORS)
```bash
# Try to register with invalid origin (should fail)
curl -X POST http://localhost:8080/register \
     -H "Origin: https://malicious.com" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=hacker@malicious.com" \
     -d "password=password123"

# Try to login with invalid origin (should fail)
curl -X POST http://localhost:8080/login \
     -H "Origin: https://unauthorized.com" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=user@myapp.com" \
     -d "password=password123"
```

### ✅ Integration Tests (IMPLEMENTED)
- ✅ Multi-tenant authentication workflows
- ✅ Cross-tenant session validation  
- ✅ CORS handling per tenant
- ✅ Data isolation between tenants
- ✅ Tenant settings inheritance
- ✅ Error handling and edge cases

### Load Testing
```bash
# Test multi-tenant load capacity
ab -n 1000 -c 10 -H "Origin: https://myapp.com" https://api.yourdomain.com/login
ab -n 1000 -c 10 -H "Origin: https://mysecond.app" https://api.yourdomain.com/login

# Test admin API load
ab -n 100 -c 5 -T "application/json" -p tenant_payload.json https://api.yourdomain.com/admin/tenants
```

## 📋 Migration Guide

### ✅ Schema Migration (COMPLETED)
The multi-tenant database schema has been implemented and can be applied to existing databases.

### 🔄 Data Migration Steps (TODO)
1. **Backup Database**
   ```bash
   pg_dump gobackend > backup_$(date +%Y%m%d_%H%M%S).sql
   ```
   Uses `-Fc` format for compressed, flexible backups:
   ```bash
   # Full database backup with timestamp
   pg_dump -Fc -v \
     -h $DB_HOST \
     -U $DB_USER \
     -d $DB_NAME \
     -f backup_$(date +%Y%m%d_%H%m%S).dump

   # Verify backup
   pg_restore --list backup_*.dump | head -n 10
   ```

2. **Run Schema Migration**
   ```bash
   # Apply multi-tenant schema migrations
   goose -dir internal/db/migrations postgres "user=... dbname=..." up
   ```

3. **Data Migration** (TODO - Script needed)
   ```bash
   # Create migration tool first
   # go run cmd/migrate/main.go -dry-run

   # Actual migration with verbose logging
   # go run cmd/migrate/main.go -verbose 2>&1 | tee migration.log

   # Verify migration results
   psql -h $DB_HOST -U $DB_USER -d $DB_NAME \
     -c "SELECT COUNT(*) FROM tenants; SELECT COUNT(*) FROM users WHERE tenant_id IS NOT NULL;"
   ```

4. **Deploy New Code**
   ```bash
   docker-compose down
   docker-compose up -d --build
   ```

5. **Verify Migration**
   ```bash
   # Verify schema version
   psql -h $DB_HOST -U $DB_USER -d $DB_NAME \
     -c "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1;"

   # Test multi-tenant endpoints
   for tenant in localhost myapp.com mysecond.app; do
     curl -s -o /dev/null -w "%{http_code}" \
       -H "Origin: https://$tenant" \
       https://api.yourdomain.com/health
     echo " - $tenant"
   done

   # Test admin API
   curl -s -o /dev/null -w "%{http_code}" \
     https://api.yourdomain.com/admin/tenants
   echo " - Admin API"
   ```

## 🎉 Implementation Summary

### ✅ Completed Features
- **Database Schema**: Full multi-tenant schema with tenant isolation
- **Tenant Management**: CRUD operations via admin API with strongly-typed models
- **Authentication**: Tenant-aware authentication flows (password + OTP)
- **Middleware**: Domain-based tenant identification and context injection
- **Data Isolation**: Complete separation of user data between tenants
- **Session Management**: Tenant-scoped session validation and CSRF protection
- **Testing**: Comprehensive multi-tenant test coverage
- **SQLC Integration**: Type-safe database operations with tenant support

### 🔄 Remaining Work
- **Data Migration Tool**: Command-line tool for migrating existing single-tenant data
- **Admin UI**: Web interface for tenant management (optional)
- **Monitoring**: Tenant-specific metrics and logging (optional)
- **Documentation**: API documentation for admin endpoints (optional)

### 🏗️ Architecture Benefits Achieved
- ✅ **Single Deployment**: One application serves multiple tenants
- ✅ **Data Isolation**: Complete separation enforced at database level
- ✅ **Resource Efficiency**: Shared infrastructure with tenant-specific settings
- ✅ **Scalability**: Easy addition of new tenants via admin API
- ✅ **Type Safety**: Strongly-typed tenant settings with JSON conversion
- ✅ **Backward Compatibility**: Existing functionality preserved
