-- Index for auth event type filtering
CREATE INDEX ASYNC idx_auth_events_event_type ON auth_events(event_type);
