-- Index for expired OIDC state cleanup
CREATE INDEX ASYNC idx_oidc_states_expires ON oidc_states(expires_at);
