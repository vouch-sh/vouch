-- SCIM tokens for provisioning
-- DSQL compatible: no REFERENCES constraints (org_id references organizations.id)
CREATE TABLE scim_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    org_id TEXT,  -- references organizations(id)
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);
