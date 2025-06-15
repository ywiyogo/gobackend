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

### Database Schema
```sql
tenants (id, name, domain, api_key, settings, is_active, ...)
users (id, tenant_id, email, password_hash, otp, otp_expires_at, ...)
sessions (id, tenant_id, user_id, session_token, csrf_token, ...)
```
**Note**: `otp` field standardized from `otp_code`. Use `otp=123456` not `otp_code=123456`.

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


### Phase 6: Deployment and Monitoring

#### Step 6.1: Docker Configuration Update
**Update**: `docker-compose.yml`

#### Step 6.2: Caddy Configuration
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
# Create tenant with OTP enabled
curl -X POST http://localhost:8080/admin/tenants \
     -H "Content-Type: application/json" \
     -d '{"name":"Test App","domain":"company.com","settings":{"otp_enabled":true}}'

# List/Get/Update/Delete
curl -X GET http://localhost:8080/admin/tenants
curl -X PUT http://localhost:8080/admin/tenants/{id} -d '{"settings":{"otp_enabled":false}}'
curl -X DELETE http://localhost:8080/admin/tenants/{id}
```

#### Test Multi-Tenant Login (Password-based)
```bash
# Login to different tenants using Origin header
curl -X POST http://localhost:8080/login \
     -H "Origin: https://tenant1.com" \
     -d "email=user@tenant1.com&password=password123" -c cookies1.txt

curl -X POST http://localhost:8080/login \
     -H "Origin: https://tenant2.com" \
     -d "email=user@tenant2.com&password=password123" -c cookies2.txt
```

#### Test Multi-Tenant OTP Workflow
```bash
# 1. Register with OTP on tenant1
curl -X POST http://localhost:8080/register \
     -H "Origin: https://company1.example.com" \
     -d "email=user@company1.com" -c cookies1.txt
# Response includes: "otp": "123456", "csrf_token": "csrf123"

# 2. Verify OTP (use correct field name 'otp')
curl -X POST http://localhost:8080/verify-otp \
     -H "Origin: https://company1.example.com" \
     -H "X-CSRF-Token: csrf123" \
     -d "otp=123456" -b cookies1.txt

# return
{"user":{"id":"057b02c6-e5b7-4bfb-9a6e-57861f29068c","email":"test@example.com","created_at":"2025-06-14T09:44:45.202993364Z","updated_at":"2025-06-14T09:44:45.202993404Z"},"session_token":"TMv9-l1zDuT01Ujja5n7yxgbPwTSkeBBuyM0IiLtCAU","csrf_token":"gGqO7kcBPh7nSe7G-HZEWNvsvRmZjuqwGAmhkSXiT68","expires_at":"2025-06-15T09:44:45.19761774Z","requires_otp":false,"message":"OTP verified successfully"}

# 3. Login with OTP on different tenant
curl -X POST http://localhost:8080/login \
     -H "Origin: https://company2.example.com" \
     -d "email=user@company2.com" -c cookies2.txt

# 4. Test cross-tenant OTP isolation (should fail)
curl -X POST http://localhost:8080/verify-otp \
     -H "Origin: https://company2.example.com" \
     -d "otp=123456" -b cookies2.txt
# Response: 401 Unauthorized - OTPs are tenant-scoped
```

#### Test OTP Field Validation
```bash
# ✅ Correct field name 'otp' (succeeds):
curl -X POST http://localhost:8080/verify-otp -d "otp=123456"

# ❌ Wrong field name 'otp_code' (fails with 401):
curl -X POST http://localhost:8080/verify-otp -d "otp_code=123456"
# Response: {"error":"Invalid OTP code"}

# Migration: Update 'otp_code' → 'otp' in forms and JSON
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
ab -n 1000 -c 10 -H "Origin: https://myapp.com" https://api.yourdomain.com/login
```

## 📋 Migration Guide

### ✅ Schema Migration (COMPLETED)
The multi-tenant database schema has been implemented and can be applied to existing databases.

### 🔄 Data Migration Steps (TODO)
1. **Backup Database**: `pg_dump gobackend > backup_$(date +%Y%m%d).sql`
2. **Run Schema Migration**: `goose -dir internal/db/migrations postgres "..." up`
3. **Deploy New Code**: `docker-compose up -d --build`
4. **Verify**: Test endpoints with different Origin headers

## 🎉 Implementation Summary

### ✅ Completed Features
- **Database Schema**: Full multi-tenant schema with tenant isolation
- **Tenant Management**: CRUD operations via admin API with strongly-typed models
- **Authentication**: Tenant-aware authentication flows (password + OTP)
- **OTP Field Standardization**: Updated from `otp_code` to `otp` with validation and error handling
- **Middleware**: Domain-based tenant identification and context injection
- **Data Isolation**: Complete separation of user data between tenants
- **Session Management**: Tenant-scoped session validation and CSRF protection
- **Testing**: Comprehensive multi-tenant test coverage with OTP field validation tests
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
