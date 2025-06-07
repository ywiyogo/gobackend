# Authentication Workflow

## Overview

This application supports two authentication modes:
- **Password-based authentication** (OTP_ENABLED=false)
- **OTP-based authentication** (OTP_ENABLED=true)

Both modes use session tokens with CSRF protection for secure API access.

## Authentication Flows

```mermaid
flowchart TD
    A[POST /register] --> B{OTP_ENABLED?}
    B -->|Yes| C[Create user with OTP]
    B -->|No| D[Create user with password]
    C --> E[Generate session + CSRF tokens]
    D --> F[Registration complete]
    E --> G[Set session cookie]

    H[POST /login] --> I{OTP_ENABLED?}
    I -->|Yes| J[Generate new OTP]
    I -->|No| K[Validate password]
    J --> L[Generate session + CSRF tokens]
    K --> L
    L --> M[Set session cookie]
    M --> N[Return CSRF token]

    O[POST /verify-otp] --> P[Validate OTP]
    P --> Q[Update session token]
    Q --> R[Return new CSRF token]

    S[POST /protected] --> T[AuthMiddleware]
    T --> U[Validate session cookie]
    U --> V[Validate CSRF header]
    V --> W[Grant access]

    X[POST /logout] --> Y[Delete session]
    Y --> Z[Clear cookies]
```

## Authentication Components

### 1. Session Management
- **Session Token**: Stored in HttpOnly cookie, validated against database
- **CSRF Token**: Returned in response body, must be sent in `X-CSRF-Token` header
- **Session Storage**: Database-backed with expiration (24 hours)
- **Device Sessions**: Multiple concurrent sessions supported per user

### 2. Password Authentication (OTP_ENABLED=false)
- **Registration**: Creates user with hashed password (bcrypt)
- **Login**: Validates credentials and creates session
- **Security**: Minimum 6 character password requirement

### 3. OTP Authentication (OTP_ENABLED=true)
- **Registration**: Creates user and generates initial OTP
- **Login**: Generates new OTP for existing users
- **Verification**: 6-digit OTP with 5-minute expiration
- **Session**: Temporary session for OTP verification, upgraded after validation

### 4. Security Features
- **CSRF Protection**: Required for all protected endpoints
- **Session Validation**: Automatic expiry and cleanup
- **Device Management**: Sessions isolated by user agent and IP
- **Rate Limiting**: Built-in middleware support

## API Endpoints

### Registration

**Password Mode:**
```bash
curl -X POST http://localhost:8080/register \
     -d "email=user@example.com" \
     -d "password=mypassword123"
```

**OTP Mode:**
```bash
curl -X POST http://localhost:8080/register \
     -d "email=user@example.com" \
     -c cookies.txt
# Response: "Setting cookie with session token: xxx, CSRF: yyy. OTP: 123456"
```

### Login

**Password Mode:**
```bash
curl -X POST http://localhost:8080/login \
     -d "email=user@example.com" \
     -d "password=mypassword123" \
     -c cookies.txt
# Response: "User with email user@example.com logged in successfully!
#           sessionToken: xxx, CSRF: yyy."
```

**OTP Mode:**
```bash
curl -X POST http://localhost:8080/login \
     -d "email=user@example.com" \
     -c cookies.txt
# Response: "User with email user@example.com logged in successfully!
#           sessionToken: xxx, CSRF: yyy. OTP code: 123456"
```

### OTP Verification (OTP Mode Only)

```bash
curl -X POST http://localhost:8080/verify-otp \
     -d "otp_code=123456" \
     -H "X-CSRF-Token: YOUR_CSRF_TOKEN" \
     -b cookies.txt
# Response: "OTP verified successfully, new session token set in cookie. CSRF: yyy"
```

### Accessing Protected Resources

```bash
# Extract CSRF token from login response
CSRF_TOKEN="your_csrf_token_from_login_response"

# Access protected endpoint
curl -X POST http://localhost:8080/dashboard \
     -H "X-CSRF-Token: $CSRF_TOKEN" \
     -b cookies.txt
# Response: "Dashboard accessed successfully. Found session_token: xxx"
```

### Logout

```bash
curl -X POST http://localhost:8080/logout \
     -H "X-CSRF-Token: YOUR_CSRF_TOKEN" \
     -b cookies.txt
```

Note, `curl` automatically uses POST method when sending data (-d flag). The -X POST flag is redundant in this case but doesn't affect functionality.

## Response Formats

### Successful Registration/Login
- **Session Cookie**: `session_token` (HttpOnly, Secure in production)
- **Response Body**: Contains CSRF token for API calls
- **OTP Mode**: Also includes OTP code in response

### Error Responses
- **400 Bad Request**: Invalid input (malformed email, short password)
- **401 Unauthorized**: Invalid credentials or expired session
- **409 Conflict**: Email already exists (registration)
- **500 Internal Server Error**: Server-side errors

## Security Considerations

### Session Security
- HttpOnly cookies prevent XSS access
- Secure flag enabled in production
- 24-hour expiration with automatic cleanup
- Device-specific session isolation

### CSRF Protection
- Stateful CSRF tokens stored in database
- Required for all state-changing operations
- Validated against session-bound tokens

### Password Security
- bcrypt hashing with salt
- Minimum length validation
- No plaintext storage

### OTP Security
- Time-based expiration (5 minutes)
- Single-use tokens
- Automatic cleanup after verification

## Development Notes

### Environment Configuration
```bash
# Password mode
OTP_ENABLED=false

# OTP mode
OTP_ENABLED=true
```

### Testing
- Integration tests cover both authentication modes
- CSRF token handling automated in test helpers
- Database cleanup between test runs
- Docker-based test environment with migrations

### Database Schema
- `users` table: email, password_hash, otp_code, otp_expires_at
- `sessions` table: user_id, session_token, csrf_token, user_agent, ip, expires_at
- Automatic UUID generation for user IDs
- Indexed columns for performance
