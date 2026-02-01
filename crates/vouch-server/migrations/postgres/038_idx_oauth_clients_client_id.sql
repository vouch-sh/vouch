-- Index for OAuth client_id lookups
CREATE INDEX ASYNC idx_oauth_clients_client_id ON oauth_clients(client_id);
