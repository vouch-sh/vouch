-- OAuth clients table
-- DSQL compatible: no REFERENCES constraints
-- (user_id references users.id, org_id references organizations.id)
-- Timestamps generated in application code
CREATE TABLE oauth_clients (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,  -- references users(id)
    client_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    application_type TEXT NOT NULL CHECK (application_type IN ('web', 'native', 'spa', 'service')),
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    access_scope TEXT NOT NULL DEFAULT 'personal'
        CHECK (access_scope IN ('organization', 'personal', 'public')),
    org_id TEXT  -- references organizations(id)
);
