-- Recreate index after table recreation (ASYNC for DSQL compatibility).
CREATE INDEX ASYNC idx_oauth_clients_access_scope ON oauth_clients(access_scope);
