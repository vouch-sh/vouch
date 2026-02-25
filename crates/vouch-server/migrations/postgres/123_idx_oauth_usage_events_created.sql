-- Recreate index after table recreation (ASYNC for DSQL compatibility).
CREATE INDEX ASYNC idx_oauth_usage_created ON oauth_usage_events(created_at);
