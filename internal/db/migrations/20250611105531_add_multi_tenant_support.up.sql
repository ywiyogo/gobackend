-- Enable pgcrypto extension for cryptographic functions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create tenants table
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE NOT NULL,
    subdomain VARCHAR(100),
    api_key VARCHAR(255) UNIQUE NOT NULL,
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_subdomain_domain UNIQUE (subdomain, domain)
);

-- Add tenant_id to users table (nullable initially for migration)
ALTER TABLE users ADD COLUMN tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;

-- Add tenant_id to sessions table (nullable initially for migration)
ALTER TABLE sessions ADD COLUMN tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;

-- Create indexes for performance
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_tenant_email ON users(tenant_id, email);
CREATE INDEX idx_sessions_tenant_id ON sessions(tenant_id);
CREATE INDEX idx_sessions_tenant_user ON sessions(tenant_id, user_id);
CREATE INDEX idx_sessions_tenant_token ON sessions(tenant_id, session_token);

-- Note: tenant_id columns remain nullable for now
-- They will be populated by deployment scripts and then made NOT NULL
-- in a subsequent migration after tenant data is properly seeded

-- Drop the old unique constraint on email and create tenant-scoped constraint
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
ALTER TABLE users ADD CONSTRAINT unique_email_per_tenant UNIQUE (tenant_id, email);

-- Create function to validate tenant consistency between sessions and users
CREATE OR REPLACE FUNCTION validate_session_tenant_consistency()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if the session's tenant_id matches the user's tenant_id
    IF NEW.tenant_id != (SELECT tenant_id FROM users WHERE id = NEW.user_id) THEN
        RAISE EXCEPTION 'Session tenant_id (%) does not match user tenant_id', NEW.tenant_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger that fires before INSERT or UPDATE on sessions table
CREATE TRIGGER trigger_validate_session_tenant_consistency
    BEFORE INSERT OR UPDATE ON sessions
    FOR EACH ROW
    EXECUTE FUNCTION validate_session_tenant_consistency();

-- Insert initial tenants with generated API keys and settings
INSERT INTO tenants (id, name, domain, subdomain, api_key, settings, is_active, created_at, updated_at)
VALUES
    (
        gen_random_uuid(),
        'Test Project',
        'localhost:3000',
        NULL,
        encode(gen_random_bytes(32), 'hex'),
        '{"otp_enabled": true, "session_timeout_minutes": 480, "rate_limit_per_minute": 60, "csrf_enabled": true, "secure_cookies": false, "admin_email": "admin@localhost"}',
        true,
        NOW(),
        NOW()
    )
ON CONFLICT (domain) DO NOTHING;

-- Log the API keys for initial setup (these will be visible in migration logs)
-- In production, these should be retrieved via admin API
DO $$
DECLARE
    tenant_record RECORD;
BEGIN
    FOR tenant_record IN SELECT name, domain, api_key FROM tenants WHERE domain IN ('localhost:3000')
    LOOP
        RAISE NOTICE 'Tenant: % (%) - API Key: %', tenant_record.name, tenant_record.domain, tenant_record.api_key;
    END LOOP;
END $$;
