-- Add 'client_registered' to oauth_usage_events.event_type CHECK constraint.
-- RFC 7591 dynamic client registration records this event type.
-- DSQL does not support ALTER TABLE DROP/ADD CONSTRAINT, so we use the
-- table recreation pattern (one DDL per migration for DSQL compatibility).
CREATE TABLE oauth_usage_events_new (
    id TEXT PRIMARY KEY,
    oauth_client_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('token_issued', 'token_refreshed', 'token_revoked', 'auth_success', 'auth_failure', 'client_registered')),
    user_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
