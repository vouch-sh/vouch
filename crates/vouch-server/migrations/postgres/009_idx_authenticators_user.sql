-- Index for user authenticator lookups
CREATE INDEX ASYNC idx_authenticators_user ON authenticators(user_id);
