-- Drop the trigger and function for tenant consistency validation
DROP TRIGGER IF EXISTS trigger_validate_session_tenant_consistency ON sessions;
DROP FUNCTION IF EXISTS validate_session_tenant_consistency();

-- Remove constraint ensuring session belongs to same tenant as user
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS fk_session_tenant_user;

-- Remove tenant-scoped unique constraint and restore original email constraint
ALTER TABLE users DROP CONSTRAINT IF EXISTS unique_email_per_tenant;
ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);

-- Make tenant_id columns nullable before dropping them
ALTER TABLE users ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE sessions ALTER COLUMN tenant_id DROP NOT NULL;

-- Drop indexes related to tenant support
DROP INDEX IF EXISTS idx_sessions_tenant_token;
DROP INDEX IF EXISTS idx_sessions_tenant_user;
DROP INDEX IF EXISTS idx_sessions_tenant_id;
DROP INDEX IF EXISTS idx_users_tenant_email;
DROP INDEX IF EXISTS idx_users_tenant_id;

-- Remove tenant_id columns
ALTER TABLE sessions DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE users DROP COLUMN IF EXISTS tenant_id;

-- Drop tenants table
DROP TABLE IF EXISTS tenants;