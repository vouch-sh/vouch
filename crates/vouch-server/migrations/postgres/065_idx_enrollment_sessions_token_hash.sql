-- Index for enrollment session token lookups
CREATE INDEX ASYNC idx_enrollment_sessions_token_hash ON enrollment_sessions(session_token_hash);
