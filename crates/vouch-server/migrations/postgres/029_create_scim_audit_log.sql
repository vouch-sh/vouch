-- SCIM audit log for tracking provisioning operations
-- DSQL compatible: no REFERENCES constraints (actor_token_id references scim_tokens.id)
CREATE TABLE scim_audit_log (
    id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,  -- create, update, delete
    resource_type TEXT NOT NULL,  -- User
    resource_id TEXT NOT NULL,
    actor_token_id TEXT,  -- references scim_tokens(id)
    details TEXT,  -- JSON with operation details
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
