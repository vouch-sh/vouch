-- Index for SSH certificate serial lookups
CREATE INDEX ASYNC idx_ssh_revoked_serial ON ssh_revoked_certificates(serial);
