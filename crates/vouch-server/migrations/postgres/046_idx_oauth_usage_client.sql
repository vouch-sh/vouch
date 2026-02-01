-- Index for OAuth usage event lookups by client
CREATE INDEX ASYNC idx_oauth_usage_client ON oauth_usage_events(oauth_client_id);
