-- name: CreateUserWithPassword :one
INSERT INTO users (id, email, password_hash, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, NOW(), NOW())
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1 LIMIT 1;

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
INSERT INTO users (id, email, otp_code, otp_expires_at, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, $3, NOW(), NOW())
RETURNING *;

-- name: SetUserOTP :exec
UPDATE users
SET otp_code = $1,
    otp_expires_at = $2,
    updated_at = NOW()
WHERE id = $3;

-- name: GetUserOTP :one
SELECT otp_code, otp_expires_at
FROM users
WHERE id = $1
  AND otp_code IS NOT NULL
  AND otp_expires_at > NOW();

-- name: ClearUserOTP :exec
UPDATE users
SET otp_code = NULL,
    otp_expires_at = NULL,
    updated_at = NOW()
WHERE id = $1;