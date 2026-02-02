-- Device authorization requests table (OAuth 2.0 Device Authorization Grant - RFC 8628)
-- DSQL compatible: no REFERENCES constraints
-- (user_id references users.id, authenticator_id references authenticators.id)
-- Timestamps generated in application code
CREATE TABLE device_auth_requests (
    id TEXT PRIMARY KEY,
    device_code_hash TEXT UNIQUE NOT NULL,
    user_code TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, authorized, denied
    user_id TEXT,  -- references users(id)
    user_email TEXT,
    authenticator_id TEXT,  -- references authenticators(id)
    expires_at TIMESTAMPTZ NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_poll_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
