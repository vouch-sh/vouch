-- SSH revoked certificates table for certificate revocation list
-- DSQL compatible: no REFERENCES constraints (user_id references users.id)
-- Timestamps generated in application code
CREATE TABLE ssh_revoked_certificates (
    id TEXT PRIMARY KEY,
    serial TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL,  -- references users(id)
    reason TEXT,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_by TEXT
);
