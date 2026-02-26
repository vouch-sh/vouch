-- Recreate index after table recreation (ASYNC for DSQL compatibility).
CREATE INDEX ASYNC idx_oauth_clients_user ON oauth_clients(user_id);
