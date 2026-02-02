-- Index for OIDC state lookups
CREATE INDEX ASYNC idx_oidc_states_state ON oidc_states(state);
