-- SCIM tokens for API authentication
CREATE TABLE IF NOT EXISTS scim_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    expires_at TEXT
);

-- SCIM audit log
CREATE TABLE IF NOT EXISTS scim_audit_log (
    id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,  -- create, update, delete
    resource_type TEXT NOT NULL,  -- User
    resource_id TEXT NOT NULL,
    actor_token_id TEXT REFERENCES scim_tokens(id) ON DELETE SET NULL,
    details TEXT,  -- JSON with operation details
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- User status field for SCIM active flag
ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1;

-- External ID for SCIM provisioning
ALTER TABLE users ADD COLUMN external_id TEXT;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scim_tokens_hash ON scim_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_scim_audit_created ON scim_audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(active);
