-- Index for SCIM external_id lookups
CREATE INDEX ASYNC idx_users_external_id ON users(external_id);
