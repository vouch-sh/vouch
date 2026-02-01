-- OAuth usage events table for tracking client activity
-- DSQL compatible: no REFERENCES constraints (oauth_client_id references oauth_clients.id)
CREATE TABLE oauth_usage_events (
    id TEXT PRIMARY KEY,
    oauth_client_id TEXT NOT NULL,  -- references oauth_clients(id)
    event_type TEXT NOT NULL CHECK (event_type IN ('token_issued', 'token_refreshed', 'token_revoked', 'auth_success', 'auth_failure')),
    user_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
