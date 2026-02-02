-- Token exchanges table (RFC 8693 Token Exchange)
-- DSQL compatible: no REFERENCES constraints
-- (subject_user_id and actor_user_id reference users.id)
-- Timestamps generated in application code
CREATE TABLE token_exchanges (
    id TEXT PRIMARY KEY,
    subject_user_id TEXT NOT NULL,  -- references users(id)
    subject_token_hash TEXT NOT NULL,
    actor_user_id TEXT,  -- references users(id)
    issued_token_hash TEXT UNIQUE NOT NULL,
    requested_audience TEXT,
    granted_scope TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
