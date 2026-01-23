-- Device Authorization Requests (RFC 8628)
CREATE TABLE IF NOT EXISTS device_auth_requests (
    id TEXT PRIMARY KEY,
    device_code_hash TEXT UNIQUE NOT NULL,
    user_code TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, authorized, denied
    user_id TEXT REFERENCES users(id),
    user_email TEXT,
    authenticator_id TEXT REFERENCES authenticators(id),
    expires_at TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_poll_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- OIDC States for CSRF protection
CREATE TABLE IF NOT EXISTS oidc_states (
    id TEXT PRIMARY KEY,
    state TEXT UNIQUE NOT NULL,
    device_auth_id TEXT NOT NULL REFERENCES device_auth_requests(id) ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_device_auth_user_code ON device_auth_requests(user_code);
CREATE INDEX IF NOT EXISTS idx_device_auth_expires ON device_auth_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_states_state ON oidc_states(state);
CREATE INDEX IF NOT EXISTS idx_oidc_states_expires ON oidc_states(expires_at);
