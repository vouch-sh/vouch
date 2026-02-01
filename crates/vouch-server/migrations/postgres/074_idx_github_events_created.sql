-- Index for GitHub credential event time-based queries
CREATE INDEX ASYNC idx_github_events_created ON github_credential_events(created_at);
