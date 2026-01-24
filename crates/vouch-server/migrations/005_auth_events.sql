-- Authentication events table for tracking login/enrollment context.
-- This enables future anomaly detection without implementing detection logic now.

CREATE TABLE IF NOT EXISTS auth_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    -- Event type: login_success, login_failed, enrollment, logout
    event_type TEXT NOT NULL,
    -- Which authenticator was used (if applicable)
    authenticator_id TEXT,
    -- Client context from HTTP headers
    client_ip TEXT,
    user_agent TEXT,
    -- Client context from CLI (sent in request body)
    client_hostname TEXT,
    client_os TEXT,
    client_arch TEXT,
    client_version TEXT,
    -- Success/failure tracking
    success INTEGER NOT NULL DEFAULT 1,
    failure_reason TEXT,
    -- Timestamp
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for querying by user
CREATE INDEX IF NOT EXISTS idx_auth_events_user_id ON auth_events(user_id);

-- Index for time-based queries (retention cleanup, recent events)
CREATE INDEX IF NOT EXISTS idx_auth_events_created_at ON auth_events(created_at);

-- Index for IP-based queries (detect logins from same IP)
CREATE INDEX IF NOT EXISTS idx_auth_events_client_ip ON auth_events(client_ip);

-- Index for event type queries
CREATE INDEX IF NOT EXISTS idx_auth_events_event_type ON auth_events(event_type);
