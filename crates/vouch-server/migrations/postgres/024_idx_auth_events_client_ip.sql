-- Index for auth event IP lookups
CREATE INDEX ASYNC idx_auth_events_client_ip ON auth_events(client_ip);
