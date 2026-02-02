-- Index for GitHub credential event lookups by user
CREATE INDEX ASYNC idx_github_events_user ON github_credential_events(user_id);
