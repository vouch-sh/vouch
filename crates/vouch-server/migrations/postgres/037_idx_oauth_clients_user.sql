-- Index for OAuth client lookups by user
CREATE INDEX ASYNC idx_oauth_clients_user ON oauth_clients(user_id);
