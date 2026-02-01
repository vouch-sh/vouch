-- GitHub credential events table for audit logging
-- DSQL compatible: no REFERENCES constraints
-- (user_id references users.id, org_id references organizations.id)
CREATE TABLE github_credential_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    user_id TEXT NOT NULL,  -- references users(id)
    user_email TEXT NOT NULL,
    org_id TEXT,  -- references organizations(id)
    installation_id BIGINT,
    session_id TEXT,
    authenticator_id TEXT,
    repositories TEXT,
    permissions TEXT,
    token_expires_at TIMESTAMPTZ,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_code TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
