-- Index for user auth event lookups
CREATE INDEX ASYNC idx_auth_events_user_id ON auth_events(user_id);
