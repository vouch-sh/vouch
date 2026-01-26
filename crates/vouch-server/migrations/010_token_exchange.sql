-- RFC 8693 Token Exchange
-- Enables token exchange for delegation and service-to-service auth

-- Token exchange audit log
CREATE TABLE IF NOT EXISTS token_exchanges (
    id TEXT PRIMARY KEY,
    -- Subject token info (the token being exchanged)
    subject_user_id TEXT NOT NULL REFERENCES users(id),
    subject_token_hash TEXT NOT NULL,
    -- Actor token info (for delegation chains, optional)
    actor_user_id TEXT REFERENCES users(id),
    -- Issued token info
    issued_token_hash TEXT UNIQUE NOT NULL,
    -- Exchange parameters
    requested_audience TEXT,
    granted_scope TEXT,
    -- Timestamps
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

-- Index for querying by subject user
CREATE INDEX IF NOT EXISTS idx_token_exchanges_subject ON token_exchanges(subject_user_id);

-- Index for looking up by issued token
CREATE INDEX IF NOT EXISTS idx_token_exchanges_issued ON token_exchanges(issued_token_hash);

-- Delegation policies (defines who can delegate to whom)
CREATE TABLE IF NOT EXISTS delegation_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    -- Pattern matching for grantor (who can delegate)
    -- Can be email, domain pattern (e.g., "*@example.com"), or "*" for any
    grantor_pattern TEXT NOT NULL,
    -- Pattern matching for grantee (who can receive delegation)
    grantee_pattern TEXT NOT NULL,
    -- Allowed scopes (JSON array, null for all)
    allowed_scopes TEXT,
    -- Maximum TTL for exchanged tokens (seconds)
    max_ttl_seconds INTEGER DEFAULT 28800,
    -- Whether this policy is active
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Index for looking up active policies
CREATE INDEX IF NOT EXISTS idx_delegation_policies_enabled ON delegation_policies(enabled);
