-- Index for OAuth client access scope filtering
CREATE INDEX ASYNC idx_oauth_clients_access_scope ON oauth_clients(access_scope);
