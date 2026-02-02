-- Index for SSH revoked certificate lookups by user
CREATE INDEX ASYNC idx_ssh_revoked_user_id ON ssh_revoked_certificates(user_id);
