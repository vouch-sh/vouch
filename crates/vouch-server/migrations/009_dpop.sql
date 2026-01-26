-- RFC 9449 DPoP (Demonstrating Proof of Possession)
-- Adds support for sender-constrained tokens

-- Add DPoP binding to sessions
ALTER TABLE sessions ADD COLUMN dpop_jkt TEXT;

-- Index for looking up sessions by DPoP thumbprint
CREATE INDEX IF NOT EXISTS idx_sessions_dpop_jkt ON sessions(dpop_jkt);

-- Nonce cache for DPoP (optional server-provided nonces)
CREATE TABLE IF NOT EXISTS dpop_nonces (
    id TEXT PRIMARY KEY,
    nonce TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

-- Index for cleanup of expired nonces
CREATE INDEX IF NOT EXISTS idx_dpop_nonces_expires ON dpop_nonces(expires_at);

-- JTI cache for replay prevention (stores recently used jti values)
CREATE TABLE IF NOT EXISTS dpop_jti_cache (
    jti TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

-- Index for cleanup of expired JTIs
CREATE INDEX IF NOT EXISTS idx_dpop_jti_expires ON dpop_jti_cache(expires_at);
