-- Authorization codes table for single-use enforcement (RFC 6749 Section 10.5).
-- Stores hashes of issued authorization codes to prevent replay.
CREATE TABLE IF NOT EXISTS authorization_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires ON authorization_codes(expires_at);
