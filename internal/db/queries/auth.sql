-- name: CreateUserWithPassword :one
INSERT INTO users (id, email, password_hash, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, NOW(), NOW())
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1 LIMIT 1;

-- name: UserExistsByEmail :one
SELECT EXISTS(SELECT 1 FROM users WHERE email = $1);

-- name: CreateSession :one
INSERT INTO sessions (user_id, session_token, csrf_token, user_agent, ip, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetSessionRowBySessionToken :one
SELECT * FROM sessions
WHERE session_token = $1
LIMIT 1;

-- name: GetSessionsByUserID :many
SELECT * FROM sessions
WHERE user_id = $1;

-- name: GetUserIDBySessionToken :one
SELECT user_id FROM sessions
WHERE session_token = $1
LIMIT 1;

-- name: DeleteSessionByID :execrows
DELETE FROM sessions
WHERE id = $1;

-- name: DeleteSessionByUserID :execrows
DELETE FROM sessions
WHERE user_id = $1;

-- name: DeleteSessionsByDevice :execrows
DELETE FROM sessions
WHERE user_id = $1 AND user_agent = $2 AND ip = $3;

-- name: GetCsrfTokenBySessionToken :one
SELECT csrf_token FROM sessions
WHERE session_token = $1
LIMIT 1;

-- name: CreateUserWithOtp :one
INSERT INTO users (id, email, otp, otp_expires_at, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, $3, NOW(), NOW())
RETURNING *;

-- name: SetUserOTP :exec
UPDATE users
SET otp = $1,
    otp_expires_at = $2,
    updated_at = NOW()
WHERE id = $3;

-- name: GetUserOTP :one
SELECT otp, otp_expires_at
FROM users
WHERE id = $1
  AND otp IS NOT NULL
  AND otp_expires_at > NOW();

-- name: ClearUserOTP :exec
UPDATE users
SET otp = NULL,
    otp_expires_at = NULL,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateSessionToken :exec
UPDATE sessions
SET session_token = $2,
    expires_at = $3
WHERE id = $1;

-- Multi-tenant queries

-- name: GetTenantByDomain :one
SELECT id, name, domain, subdomain, api_key, settings, is_active, created_at, updated_at
FROM tenants
WHERE domain = $1 AND is_active = true
LIMIT 1;

-- name: GetTenantByAPIKey :one
SELECT id, name, domain, subdomain, api_key, settings, is_active, created_at, updated_at
FROM tenants
WHERE api_key = $1 AND is_active = true
LIMIT 1;

-- name: CreateTenant :one
INSERT INTO tenants (name, domain, subdomain, api_key, settings)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: UpdateTenantSettings :exec
UPDATE tenants
SET settings = $2, updated_at = NOW()
WHERE id = $1;

-- Tenant-aware user queries

-- name: GetUserByEmailAndTenant :one
SELECT * FROM users
WHERE tenant_id = $1 AND email = $2
LIMIT 1;

-- name: CreateUserWithPasswordInTenant :one
INSERT INTO users (id, tenant_id, email, password_hash, otp, otp_expires_at, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, NOW(), NOW())
RETURNING *;

-- name: CreateUserWithOtpInTenant :one
INSERT INTO users (id, tenant_id, email, otp, otp_expires_at, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW(), NOW())
RETURNING *;

-- name: UserExistsByEmailAndTenant :one
SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id = $1 AND email = $2);

-- name: SetUserOTPInTenant :exec
UPDATE users
SET otp = $3,
    otp_expires_at = $4,
    updated_at = NOW()
WHERE id = $1 AND tenant_id = $2;

-- name: GetUserOTPInTenant :one
SELECT otp, otp_expires_at
FROM users
WHERE tenant_id = $1 AND id = $2
  AND otp IS NOT NULL;

-- name: ClearUserOTPInTenant :exec
UPDATE users
SET otp = NULL,
    otp_expires_at = NULL,
    updated_at = NOW()
WHERE tenant_id = $1 AND id = $2;

-- Tenant-aware session queries

-- name: CreateSessionInTenant :one
INSERT INTO sessions (tenant_id, user_id, session_token, csrf_token, user_agent, ip, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetSessionByTokenAndTenant :one
SELECT id, tenant_id, user_id, session_token, csrf_token, user_agent, ip, expires_at, created_at
FROM sessions
WHERE tenant_id = $1 AND session_token = $2 AND expires_at > NOW()
LIMIT 1;

-- name: GetSessionsByUserIDAndTenant :many
SELECT id, tenant_id, user_id, session_token, csrf_token, user_agent, ip, expires_at, created_at
FROM sessions
WHERE tenant_id = $1 AND user_id = $2;

-- name: DeleteSessionByIDAndTenant :execrows
DELETE FROM sessions
WHERE tenant_id = $1 AND id = $2;

-- name: DeleteSessionByUserIDAndTenant :execrows
DELETE FROM sessions
WHERE tenant_id = $1 AND user_id = $2;

-- name: DeleteSessionsByDeviceAndTenant :execrows
DELETE FROM sessions
WHERE tenant_id = $1 AND user_id = $2 AND user_agent = $3 AND ip = $4;

-- name: GetCsrfTokenBySessionTokenAndTenant :one
SELECT csrf_token FROM sessions
WHERE tenant_id = $1 AND session_token = $2 AND expires_at > NOW()
LIMIT 1;

-- name: UpdateSessionTokenInTenant :exec
UPDATE sessions
SET session_token = $3,
    expires_at = $4
WHERE tenant_id = $1 AND id = $2;

-- name: GetUserByIDAndTenant :one
SELECT * FROM users
WHERE tenant_id = $1 AND id = $2
LIMIT 1;

-- Additional tenant management queries

-- name: ListTenants :many
SELECT id, name, domain, subdomain, api_key, settings, is_active, created_at, updated_at
FROM tenants
ORDER BY created_at DESC;

-- name: GetTenantByID :one
SELECT id, name, domain, subdomain, api_key, settings, is_active, created_at, updated_at
FROM tenants
WHERE id = $1
LIMIT 1;

-- name: UpdateTenantStatus :exec
UPDATE tenants
SET is_active = $2, updated_at = NOW()
WHERE id = $1;

-- name: UpdateTenant :one
UPDATE tenants
SET name = $2,
    domain = $3,
    subdomain = $4,
    is_active = $5,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteTenantByID :exec
DELETE FROM tenants
WHERE id = $1;

-- name: CountUsersByTenant :one
SELECT COUNT(*) as user_count
FROM users
WHERE tenant_id = $1;

-- name: CountSessionsByTenant :one
SELECT COUNT(*) as session_count
FROM sessions
WHERE tenant_id = $1;

-- name: GetUserByVerificationTokenAndTenant :one
SELECT * FROM users
WHERE tenant_id = $1 AND verification_token = $2
LIMIT 1;

-- name: GetUserByOTPAndTenant :one
SELECT * FROM users
WHERE tenant_id = $1 AND otp = $2 AND otp_expires_at > NOW()
LIMIT 1;

-- name: UpdateUserEmailVerified :exec
UPDATE users
SET email_verified = $3
WHERE id = $1 AND tenant_id = $2;

-- name: ClearVerificationToken :exec
UPDATE users
SET verification_token = NULL
WHERE id = $1 AND tenant_id = $2;
