-- Index for expired SSH revoked certificate cleanup
CREATE INDEX ASYNC idx_ssh_revoked_expires_at ON ssh_revoked_certificates(expires_at);
