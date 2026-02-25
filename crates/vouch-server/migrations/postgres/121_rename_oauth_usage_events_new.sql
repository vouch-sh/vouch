-- Rename new table to original name (one DDL per migration for DSQL).
ALTER TABLE oauth_usage_events_new RENAME TO oauth_usage_events;
