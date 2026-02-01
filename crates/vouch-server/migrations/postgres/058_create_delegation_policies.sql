-- Delegation policies table for token exchange authorization
CREATE TABLE delegation_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    grantor_pattern TEXT NOT NULL,
    grantee_pattern TEXT NOT NULL,
    allowed_scopes TEXT,
    max_ttl_seconds INTEGER DEFAULT 28800,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
