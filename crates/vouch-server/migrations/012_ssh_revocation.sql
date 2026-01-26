-- SSH certificate revocation tracking
CREATE TABLE IF NOT EXISTS ssh_revoked_certificates (
    id TEXT PRIMARY KEY,
    serial TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL,
    reason TEXT,
    revoked_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    revoked_by TEXT, -- admin email or 'scim' for automatic revocation
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for serial lookup (used when checking revocation)
CREATE INDEX IF NOT EXISTS idx_ssh_revoked_serial ON ssh_revoked_certificates(serial);

-- Index for user lookup (used when revoking all certs for a user)
CREATE INDEX IF NOT EXISTS idx_ssh_revoked_user_id ON ssh_revoked_certificates(user_id);

-- Index for cleanup of expired revocations
CREATE INDEX IF NOT EXISTS idx_ssh_revoked_expires_at ON ssh_revoked_certificates(expires_at);
