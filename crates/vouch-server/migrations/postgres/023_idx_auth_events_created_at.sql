-- Index for auth event time-based queries
CREATE INDEX ASYNC idx_auth_events_created_at ON auth_events(created_at);
