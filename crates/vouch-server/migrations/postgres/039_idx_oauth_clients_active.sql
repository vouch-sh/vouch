-- Index for filtering active OAuth clients
CREATE INDEX ASYNC idx_oauth_clients_active ON oauth_clients(active);
