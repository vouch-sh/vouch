-- Index for user session lookups
CREATE INDEX ASYNC idx_sessions_user ON sessions(user_id);
