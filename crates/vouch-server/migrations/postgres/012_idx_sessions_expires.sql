-- Index for expired session cleanup
CREATE INDEX ASYNC idx_sessions_expires ON sessions(expires_at);
