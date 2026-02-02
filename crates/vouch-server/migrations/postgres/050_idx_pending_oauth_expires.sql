-- Index for expired pending OAuth authorization cleanup
CREATE INDEX ASYNC idx_pending_oauth_expires ON pending_oauth_authorizations(expires_at);
