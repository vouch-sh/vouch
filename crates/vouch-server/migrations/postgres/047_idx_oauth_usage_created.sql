-- Index for OAuth usage event time-based queries
CREATE INDEX ASYNC idx_oauth_usage_created ON oauth_usage_events(created_at);
