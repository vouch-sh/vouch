-- Sessions table
-- DSQL compatible: no REFERENCES constraints
-- (user_id references users.id, authenticator_id references authenticators.id)
-- Timestamps generated in application code
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,  -- references users(id)
    token_hash TEXT UNIQUE NOT NULL,
    authenticator_id TEXT,  -- references authenticators(id)
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    session_type TEXT NOT NULL CHECK (session_type IN ('fido2_session', 'oauth_access_token'))
);
