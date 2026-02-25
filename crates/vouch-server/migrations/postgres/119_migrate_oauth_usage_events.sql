-- Copy data from old table to new table with updated CHECK constraint.
INSERT INTO oauth_usage_events_new SELECT * FROM oauth_usage_events;
