-- Authenticators (WebAuthn credentials) table
-- DSQL compatible: no REFERENCES constraints (user_id references users.id)
-- Note: BYTEA cannot be used in UNIQUE constraints or indexes in DSQL
-- Uniqueness of credential_id is enforced in application code
CREATE TABLE authenticators (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,  -- references users(id)
    name TEXT NOT NULL,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    aaguid TEXT,
    user_handle BYTEA
);
