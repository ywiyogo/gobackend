-- This SQL migration script initializes the database schema for a user management system.
-- It creates two tables: users and sessions, along with necessary indexes.
-- This script is intended to be run in a PostgreSQL database.
-- Migration script to create initial schema for user management system
-- migrate -path internal/db/migrations -database "postgres://${DB_USER}:${DB_PASSWORD}@localhost:5432/${DB_NAME}?sslmode=disable" up

CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sessions (
    id BIGSERIAL PRIMARY KEY, -- Using BIGSERIAL for session ID to allow auto-incrementing, not for distributed ID purposes
    user_id UUID NOT NULL REFERENCES users(id),
    session_token TEXT UNIQUE NOT NULL,  -- or BYTEA if raw binary is preferred
    csrf_token TEXT UNIQUE NOT NULL,
    user_agent TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);