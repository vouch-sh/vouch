-- Index for organization OAuth client lookups
CREATE INDEX ASYNC idx_oauth_clients_org ON oauth_clients(org_id);
