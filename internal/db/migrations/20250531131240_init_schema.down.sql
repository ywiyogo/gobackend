DROP TABLE IF EXISTS "users";
DROP TABLE IF EXISTS "sessions";
DROP INDEX IF EXISTS "idx_users_email";
DROP INDEX IF EXISTS "idx_sessions_user_id";
-- Revert to the previous schema state
-- This will remove the users and sessions tables, along with their indexes.