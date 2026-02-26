-- Recreate index after table recreation (ASYNC for DSQL compatibility).
CREATE INDEX ASYNC idx_oauth_clients_active ON oauth_clients(active);
