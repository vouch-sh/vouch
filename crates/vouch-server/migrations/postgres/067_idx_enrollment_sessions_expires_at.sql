-- Index for expired enrollment session cleanup
CREATE INDEX ASYNC idx_enrollment_sessions_expires_at ON enrollment_sessions(expires_at);
