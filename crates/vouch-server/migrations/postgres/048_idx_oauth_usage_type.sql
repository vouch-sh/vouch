-- Index for OAuth usage event type filtering
CREATE INDEX ASYNC idx_oauth_usage_type ON oauth_usage_events(event_type);
