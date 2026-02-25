-- Recreate index after table recreation (ASYNC for DSQL compatibility).
CREATE INDEX ASYNC idx_oauth_usage_type ON oauth_usage_events(event_type);
