-- Recreate index after table recreation (ASYNC for DSQL compatibility).
CREATE INDEX ASYNC idx_oauth_clients_client_id ON oauth_clients(client_id);
