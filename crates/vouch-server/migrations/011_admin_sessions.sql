-- Admin sessions for browser-based OIDC login
CREATE TABLE IF NOT EXISTS admin_sessions (
    id TEXT PRIMARY KEY,
    admin_email TEXT NOT NULL,
    session_token_hash TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    oidc_provider TEXT,
    oidc_subject TEXT,
    revoked INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    last_used_at TEXT DEFAULT (datetime('now'))
);

-- Index for session lookup by token hash
CREATE INDEX IF NOT EXISTS idx_admin_sessions_token_hash ON admin_sessions(session_token_hash);

-- Index for admin email lookup
CREATE INDEX IF NOT EXISTS idx_admin_sessions_email ON admin_sessions(admin_email);

-- Index for cleanup of expired sessions
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at);
