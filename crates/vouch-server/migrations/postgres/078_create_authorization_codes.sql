-- Authorization codes table for single-use enforcement (RFC 6749 Section 10.5).
-- Stores hashes of issued authorization codes to prevent replay.
-- DSQL compatible: no REFERENCES constraints (user_id references users.id)
-- Timestamps generated in application code
CREATE TABLE IF NOT EXISTS authorization_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,  -- references users(id)
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
