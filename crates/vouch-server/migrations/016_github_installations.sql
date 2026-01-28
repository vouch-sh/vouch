-- GitHub App installations linked to Vouch organizations
CREATE TABLE IF NOT EXISTS github_installations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    installation_id INTEGER NOT NULL UNIQUE,
    github_account_login TEXT NOT NULL,
    github_account_type TEXT NOT NULL,  -- "Organization" or "User"
    permissions TEXT NOT NULL,           -- JSON
    repository_selection TEXT NOT NULL,  -- "all" or "selected"
    installed_at TEXT NOT NULL DEFAULT (datetime('now')),
    installed_by_user_id TEXT REFERENCES users(id),
    suspended_at TEXT,
    UNIQUE(org_id)
);

-- Comprehensive audit log for GitHub credential events
CREATE TABLE IF NOT EXISTS github_credential_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,  -- 'token_issued', 'installation_connected', etc.
    user_id TEXT NOT NULL REFERENCES users(id),
    user_email TEXT NOT NULL,
    org_id TEXT REFERENCES organizations(id),
    installation_id INTEGER,
    session_id TEXT,
    authenticator_id TEXT,
    repositories TEXT,         -- JSON array
    permissions TEXT,          -- JSON
    token_expires_at TEXT,
    success INTEGER NOT NULL DEFAULT 1,
    error_code TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_github_installations_org ON github_installations(org_id);
CREATE INDEX IF NOT EXISTS idx_github_events_user ON github_credential_events(user_id);
CREATE INDEX IF NOT EXISTS idx_github_events_org ON github_credential_events(org_id);
CREATE INDEX IF NOT EXISTS idx_github_events_created ON github_credential_events(created_at);
