-- Add 'client_registered' to oauth_usage_events.event_type CHECK constraint.
-- RFC 7591 dynamic client registration records this event type.
-- SQLite doesn't support ALTER CONSTRAINT, so we recreate the table.

CREATE TABLE oauth_usage_events_new (
    id TEXT PRIMARY KEY,
    oauth_client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL CHECK (event_type IN ('token_issued', 'token_refreshed', 'token_revoked', 'auth_success', 'auth_failure', 'client_registered')),
    user_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at TEXT NOT NULL
);

INSERT INTO oauth_usage_events_new SELECT * FROM oauth_usage_events;
DROP TABLE oauth_usage_events;
ALTER TABLE oauth_usage_events_new RENAME TO oauth_usage_events;

-- Recreate indexes lost during table recreation
CREATE INDEX idx_oauth_usage_client ON oauth_usage_events(oauth_client_id);
CREATE INDEX idx_oauth_usage_created ON oauth_usage_events(created_at);
CREATE INDEX idx_oauth_usage_type ON oauth_usage_events(event_type);
