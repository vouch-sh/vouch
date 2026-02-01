-- Index for session token lookups
CREATE INDEX ASYNC idx_sessions_token ON sessions(token_hash);
