-- OAuth Application Registration
-- Phase 7: Self-service portal for developers to register OAuth applications

-- OAuth Client Applications
CREATE TABLE IF NOT EXISTS oauth_clients (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    application_type TEXT NOT NULL CHECK (application_type IN ('web', 'native', 'spa', 'service')),
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_oauth_clients_user ON oauth_clients(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_active ON oauth_clients(active);

-- OAuth Client Secrets (supports rotation with multiple active secrets)
CREATE TABLE IF NOT EXISTS oauth_client_secrets (
    id TEXT PRIMARY KEY,
    oauth_client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    secret_hash TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT,
    revoked_at TEXT
);

-- Indexes for secret lookup
CREATE INDEX IF NOT EXISTS idx_oauth_client_secrets_client ON oauth_client_secrets(oauth_client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_client_secrets_hash ON oauth_client_secrets(secret_hash);

-- OAuth Usage Events (for statistics)
CREATE TABLE IF NOT EXISTS oauth_usage_events (
    id TEXT PRIMARY KEY,
    oauth_client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL CHECK (event_type IN ('token_issued', 'token_refreshed', 'token_revoked', 'auth_success', 'auth_failure')),
    user_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for usage queries
CREATE INDEX IF NOT EXISTS idx_oauth_usage_client ON oauth_usage_events(oauth_client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_usage_created ON oauth_usage_events(created_at);
CREATE INDEX IF NOT EXISTS idx_oauth_usage_type ON oauth_usage_events(event_type);
