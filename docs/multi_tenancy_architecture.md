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
Current Single-Tenant Setup:
├── Database: PostgreSQL with users, sessions tables
├── Authentication: Password + OTP based auth
├── API Endpoints: /register, /login, /logout, /verify-otp, /dashboard
├── Session Management: Cookie-based with CSRF protection
└── Testing: Comprehensive integration tests
```

### Current Database Schema
```sql
-- Existing tables that need modification
users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE,  -- Will become tenant-scoped
    password_hash VARCHAR(255),
    otp_code VARCHAR(10),
    otp_expires_at TIMESTAMP,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

sessions (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    session_token VARCHAR(255) UNIQUE,
    csrf_token VARCHAR(255),
    user_agent TEXT,
    ip VARCHAR(45),
    expires_at TIMESTAMP,
    created_at TIMESTAMP
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

## 🗺️ Implementation Roadmap

### Phase 1: Foundation Setup
**Goal**: Establish multi-tenant infrastructure without breaking existing functionality

#### Step 1.1: Create Tenant Management System
```bash
# Create new directory structure
mkdir -p internal/tenant
mkdir -p internal/middleware
```

**Files to Create:**
1. `internal/tenant/models.go` - Tenant data structures
2. `internal/tenant/service.go` - Tenant management logic
3. `internal/tenant/repository.go` - Tenant database operations
4. `internal/middleware/tenant.go` - Tenant identification middleware

#### Step 1.2: Database Schema Extension
**Create Migration File**: `internal/db/migrations/2025060810553_add_multi_tenant_support.up.sql`
**Create Down Migration**: `internal/db/migrations/2025060810553_add_multi_tenant_support.down.sql`


#### Step 1.3: Update SQLC Queries
**Update**: `internal/db/queries/auth.sql`

Add new tenant-aware queries while keeping existing ones for backward compatibility:

**Regenerate SQLC Code:**
```bash
sqlc generate
```

### Phase 2: Core Multi-Tenant Implementation

#### Step 2.1: Implement TenantSettings Model
**File**: `internal/tenant/models.go`
```
type TenantSettings struct {
    OTPEnabled           bool     `json:"otp_enabled"`
    SessionTimeout       int      `json:"session_timeout_minutes"`
    AllowedOrigins       []string `json:"allowed_origins"`
    RateLimitPerMinute   int      `json:"rate_limit_per_minute"`
    RequireEmailVerification bool `json:"require_email_verification"`
}
```

#### Step 2.2: Implement Tenant Service
**File**: `internal/tenant/service.go`


#### Step 2.3: Implement Tenant Middleware
**File**: `internal/tenant/middleware.go`


### Phase 3: Authentication Service Updates (Week 3)

#### Step 3.1: Update Authentication Repository
**Update**: `internal/auth/repository.go`


#### Step 3.2: Update Authentication Service
**Update**: `internal/auth/service.go`


### Phase 4: Handler and API Updates (Week 4)

#### Step 4.1: Update Authentication Handlers
**Update**: `internal/auth/handlers.go`



#### Step 4.2: Update Main Application
**Update**: `main.go`


### Phase 5: Integration and Testing Updates (Week 5)

#### Step 5.1: Update Integration Tests
**Update**: `test/integration_test.go`

#### Step 5.2: Update Environment Configuration

### Phase 6: Migration Strategy

#### Step 6.1: Data Migration Script

#### Step 6.2: Migration Command
**Create**: `cmd/migrate/main.go`

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

## 🧪 Testing Strategy

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

# Register user on myapp.com tenant
curl -X POST http://localhost:8080/register \
     -H "Origin: https://myapp.com" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=user@myapp.com" \
     -d "password=password123" \
     -c "cookies_myapp.txt"

# Register user on mysecond.app tenant
curl -X POST http://localhost:8080/register \
     -H "Origin: https://mysecond.app" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=user@mysecond.com" \
     -d "password=password123" \
     -c "cookies_mysecond.txt"
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

### Integration Tests
- Multi-tenant authentication workflows
- Cross-tenant session validation
- CORS handling per tenant
- Rate limiting per tenant

### Load Testing
```bash
# Test multi-tenant load capacity
ab -n 1000 -c 10 -H "Origin: https://myapp.com" https://api.yourdomain.com/login
ab -n 1000 -c 10 -H "Origin: https://mysecond.app" https://api.yourdomain.com/login
```

## 📋 Migration Guide

### Migration Steps
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

2. **Run Migration**
   ```bash
    # Dry run first
    go run cmd/migrate/main.go -dry-run

    # Actual migration with verbose logging
    go run cmd/migrate/main.go -verbose 2>&1 | tee migration.log

    # Verify migration results
    psql -h $DB_HOST -U $DB_USER -d $DB_NAME \
      -c "SELECT COUNT(*) FROM tenants; SELECT COUNT(*) FROM users WHERE tenant_id IS NOT NULL;"
    ```

3. **Deploy New Code**
   ```bash
   docker-compose down
   docker-compose up -d --build
   ```

 4. **Verify Migration**
   ```bash
   # Verify schema version
   psql -h $DB_HOST -U $DB_USER -d $DB_NAME \
     -c "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1;"

   # Test critical endpoints
   for tenant in localhost myapp.com mysecond.app; do
     curl -s -o /dev/null -w "%{http_code}" \
       -H "Origin: https://$tenant" \
       https://api.yourdomain.com/health
     echo " - $tenant"
   done
    ```
