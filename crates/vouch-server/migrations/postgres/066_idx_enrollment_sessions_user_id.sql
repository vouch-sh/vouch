-- Index for enrollment session lookups by user
CREATE INDEX ASYNC idx_enrollment_sessions_user_id ON enrollment_sessions(user_id);
