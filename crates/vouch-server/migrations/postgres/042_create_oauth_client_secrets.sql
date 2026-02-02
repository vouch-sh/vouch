-- OAuth client secrets table
-- DSQL compatible: no REFERENCES constraints (oauth_client_id references oauth_clients.id)
-- Timestamps generated in application code
CREATE TABLE oauth_client_secrets (
    id TEXT PRIMARY KEY,
    oauth_client_id TEXT NOT NULL,  -- references oauth_clients(id)
    secret_hash TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
