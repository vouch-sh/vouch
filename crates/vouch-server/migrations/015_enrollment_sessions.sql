-- Enrollment sessions for browser-based key management during enrollment
-- These sessions allow users to manage their security keys after OIDC authentication,
-- surviving page refreshes without requiring re-authentication.
CREATE TABLE IF NOT EXISTS enrollment_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_email TEXT NOT NULL,
    session_token_hash TEXT UNIQUE NOT NULL,
    device_auth_id TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    last_used_at TEXT DEFAULT (datetime('now'))
);

-- Index for session lookup by token hash
CREATE INDEX IF NOT EXISTS idx_enrollment_sessions_token_hash ON enrollment_sessions(session_token_hash);

-- Index for user lookup
CREATE INDEX IF NOT EXISTS idx_enrollment_sessions_user_id ON enrollment_sessions(user_id);

-- Index for cleanup of expired sessions
CREATE INDEX IF NOT EXISTS idx_enrollment_sessions_expires_at ON enrollment_sessions(expires_at);
