-- Authentication events for audit logging
-- DSQL compatible: no REFERENCES constraints (user_id references users.id)
CREATE TABLE auth_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,  -- references users(id)
    event_type TEXT NOT NULL,  -- login_success, login_failed, enrollment, logout
    authenticator_id TEXT,
    client_ip TEXT,
    user_agent TEXT,
    client_hostname TEXT,
    client_os TEXT,
    client_arch TEXT,
    client_version TEXT,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
